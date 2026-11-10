package resync

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// replaceExistingFeature is the server capability that must be advertised
// before any override upload: older servers decode the ingest body with
// DisallowUnknownFields and reject the replaceExisting flag with 400
// invalid_json, so the pass probes GET /v1/capabilities first and fails
// closed (nothing ledgered) when the feature is absent.
const replaceExistingFeature = "replace-existing"

// RunOverride performs one explicitly confirmed override pass: it scans
// the CURRENT codex-jsonl and deepseek-harness sources, and retransmits
// every record whose current-scan content differs from the effective
// baseline (or that no baseline has ever seen) with
// BatchRequest.replaceExisting=true, so the server replaces its same-key
// copy with the current scanned record. Records the current scan no
// longer produces, and every record of other sources, are untouched.
//
// Semantics and guarantees:
//   - The current scan is authoritative: same-key conflicts are resolved
//     in favor of the freshly scanned record, and the acknowledged
//     override content is the baseline a later comparison uses (a scan
//     that reverted to the archived value is a NEW drift, not
//     "already synced"). The server has the final say — a record the
//     server rejects (any code, including record_conflict) is NOT
//     confirmed and its attempt stays pending for the next explicit
//     pass; the client never assumes a replacement happened without a
//     receipt.
//   - Capability gate: the server must advertise the replace-existing
//     feature before anything is ledgered, so an old server can never
//     freeze a source behind pending attempts it cannot resolve.
//   - The authoritative baseline is durable: every uploaded key is first
//     persisted in the override ledger as a pending attempt, and promoted
//     to confirmed only for records the receipt accepted (by exact
//     index). The previous confirmed content is never discarded while a
//     new attempt is in flight.
//   - Frozen attempts: a crash between the server's acknowledgment and
//     the local confirmation leaves the attempt pending with its exact
//     content and its persistent attempt id. The next pass re-uploads
//     that FROZEN payload under its deterministic batch identity FIRST
//     (the server replays it if it was already applied), promotes it on
//     the acknowledgment, and only then starts a new override round for
//     keys whose scan drifted further. A pending attempt is never
//     recomputed from a fresh scan, never auto-discarded when the source
//     changed or deleted the key, and never dropped because a receipt is
//     missing — otherwise the server could hold a replaced record the
//     local state no longer knows.
//   - Attempt identities are per-key, persisted, and folded into the
//     batch id together with the full canonical content: a content
//     sequence A→B→A can never reuse the first A's server receipt, and a
//     retry of the same attempt always replays the same batch.
//   - Pending (unconfirmed) attempts block normal collection of their
//     source fail-closed (see overrides.ApplyToBaseline) and are never
//     applied by plain resync: an unconfirmed override is never treated
//     as authoritative.
//   - Authorization is unchanged: the pass re-checks the live device
//     authorization (preflight with durable attempt accounting), honors
//     pause/revocation, evaluates every record against the live consent
//     scope before it is sent, and requires an enabled local source
//     grant for every scanned input. Out-of-scope records are withheld
//     and reported — they are never uploaded and never ledgered.
//   - Honesty: a pass with invalid current-scan records (structurally
//     not uploadable) or unresolved attempts is NEVER reported as
//     completed; scan line issues and quarantined lines are reported as
//     counted, mirroring normal collection.
//   - Old data is protected: outbox entries, batch files, per-message
//     progress, cursors, and the quarantine store are never modified.
//     The override ledger supersedes stored payloads for baseline
//     comparison only.
//   - The pass is bound to the device and server recorded in the ledger;
//     a collector bound differently fails closed.
func RunOverride(ctx context.Context, opt OverrideOptions) (OverrideResult, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return OverrideResult{}, errors.New("override requires a state directory")
	}
	if err := syncclient.CheckResetJournal(stateDir); err != nil {
		return OverrideResult{}, err
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	if opt.MaxBatches < 0 {
		return OverrideResult{}, fmt.Errorf("max-batches must be 0 (whole delta) or a positive upload budget")
	}

	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		return OverrideResult{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return OverrideResult{}, errors.New("device is not bound; the override pass retransmits to the currently bound device only and never binds one itself; run toktrail bind or connect first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	ledgerStore := overrides.New(stateDir)
	ledger, hasLedger, err := ledgerStore.Load()
	if err != nil {
		return OverrideResult{}, err
	}
	if hasLedger {
		if ledger.DataEpoch != st.DataEpoch {
			return OverrideResult{}, errors.New("override ledger belongs to another data epoch; refusing to replay old contents")
		}
		if ledger.DeviceID != st.DeviceID {
			return OverrideResult{}, fmt.Errorf("the override ledger was created for device %q, but this collector is bound as %q; the override baseline is device-bound — remove %s only if you accept abandoning it", ledger.DeviceID, st.DeviceID, ledgerStore.Path())
		}
		if ledger.ServerURL != serverURL {
			return OverrideResult{}, fmt.Errorf("the override ledger targets server %s, but this pass targets %s; re-run against the recorded server, or remove %s to abandon the override", ledger.ServerURL, serverURL, ledgerStore.Path())
		}
	}

	plan, frozenDelta, err := planOverrideContext(ctx, stateDir, st, serverURL, ledger)
	if err != nil {
		return OverrideResult{}, err
	}

	if opt.DryRun {
		return OverrideResult{Plan: plan, DryRun: true}, nil
	}
	if opt.Confirm == nil {
		return OverrideResult{Plan: plan}, errors.New("override execution requires a confirmation callback; the CLI prompts (or passes --yes), and tests inject one")
	}
	if err := opt.Confirm(plan); err != nil {
		return OverrideResult{Plan: plan}, fmt.Errorf("override aborted before any state change or network access: %w", err)
	}

	result := OverrideResult{Plan: plan}
	client := safeOverrideClient(opt.HTTPClient)

	// Live authorization preflight before anything is ledgered or sent.
	// The attempt accounting write happens first: if it fails, zero HTTP
	// traffic of any kind occurs and the disk is untouched.
	if _, err := outbox.New(stateDir).RecordPreflightAttempt(now().UTC()); err != nil {
		result.Stopped = "preflight accounting failed"
		return result, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; no HTTP request was made and nothing was ledgered: %w", err)
	}
	self, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
	if err != nil {
		result.Stopped = "authorization preflight failed"
		return result, fmt.Errorf("override stopped before any state change; nothing was ledgered: %w", err)
	}
	result.Self = self
	if err := syncclient.CheckSelfDataEpoch(self, st.DataEpoch); err != nil {
		result.Stopped = "device data epoch changed"
		return result, err
	}
	if devicePaused(self) {
		result.Stopped = "device paused"
		return result, fmt.Errorf("%w: server reports collection paused for this device; nothing was ledgered and nothing was sent", syncclient.ErrDevicePaused)
	}
	scope, err := scopeFromSelf(self, st)
	if err != nil {
		result.Stopped = "consent scope unknown"
		return result, fmt.Errorf("override stopped before any state change; nothing was ledgered: %w", err)
	}
	// Capability gate BEFORE any pending attempt is persisted: an old
	// server cannot resolve a replaceExisting upload, so ledgering first
	// would freeze the affected sources behind attempts that can never be
	// acknowledged.
	if err := probeReplaceExisting(ctx, client, serverURL); err != nil {
		result.Stopped = "server capability missing"
		return result, fmt.Errorf("override stopped before any state change; nothing was ledgered: %w", err)
	}

	uploads := 0
	budget := opt.MaxBatches > 0
	budgetReached := func() bool { return budget && uploads >= opt.MaxBatches }

	// Stage 1 — resolve frozen attempts. Every pending entry whose
	// (source, input) grant is still enabled is re-uploaded with its
	// exact frozen payload and its persistent attempt id under its
	// deterministic identity (replay if the server already applied it),
	// and promoted on the acknowledgment. This must happen BEFORE any new
	// override round: the local state cannot know whether a crashed
	// pass's upload was applied, so the frozen payload is the only safe
	// candidate until the server answers for it.
	frozen := frozenAttempts(ledger, stateDir)
	if len(frozen) > 0 {
		for _, chunk := range chunkOverrideDelta(frozen) {
			if budgetReached() {
				result.Stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run) before resolving the frozen override attempts; re-run toktrail resync --all --replace-existing to continue", opt.MaxBatches)
				break
			}
			stop, err := uploadOverrideChunk(ctx, store, stateDir, serverURL, client, &ledger, ledgerStore, scope, st, opt, now, chunk, &result, &uploads)
			if stop {
				return result, err
			}
		}
	}

	// Stage 2 — a new round over the FROZEN plan the user confirmed:
	// the delta captured at planning time, re-classified ONLY against the
	// ledger as stage 1 left it. The sources are never re-scanned here,
	// so records that appeared or changed after the confirmation can
	// never ride this pass; they wait for the next explicit one. Keys
	// that still carry a pending attempt (rejected or budget-stopped in
	// stage 1) are excluded: their frozen attempt must be resolved first,
	// and keys whose stage-1 promotion already delivered exactly the
	// confirmed content need no new attempt.
	if result.Stopped == "" && !budgetReached() {
		delta := reclassifyFrozenDelta(frozenDelta, ledger)
		// Per-record live scope evaluation BEFORE anything is ledgered:
		// an out-of-scope record is a normal exclusion — withheld,
		// reported, and never pending (it must not block normal
		// collection).
		uploadSet := make([]overrideDelta, 0, len(delta))
		for _, d := range delta {
			in, _, err := scope.evaluateRecord(d.Canonical)
			if err != nil {
				result.Stopped = "record unevaluable"
				return result, fmt.Errorf("override stopped before the new round was ledgered: %w", err)
			}
			if !in {
				result.WithheldOutOfScope++
				continue
			}
			uploadSet = append(uploadSet, d)
		}
		if len(uploadSet) > 0 {
			// Mint a persistent attempt id per key, then durably mark
			// every to-upload key as a pending attempt BEFORE the first
			// upload of the round. The previous confirmed content (if
			// any) stays in the entry. From this moment the affected
			// sources' normal collection is blocked fail-closed until
			// the pass completes or the user abandons the ledger — that
			// is the honest cost of a decided but unconfirmed override.
			if ledger.Entries == nil {
				ledger.Entries = map[string]overrides.Entry{}
			}
			ledger.Schema = overrides.Schema
			ledger.DeviceID = st.DeviceID
			ledger.ServerURL = serverURL
			ledger.DataEpoch = st.DataEpoch
			at := now().UTC()
			for idx := range uploadSet {
				id, err := newAttemptID()
				if err != nil {
					result.Stopped = "override ledger write failed"
					return result, fmt.Errorf("cannot mint an override attempt id; nothing was retransmitted this round: %w", err)
				}
				uploadSet[idx].AttemptID = id
				d := uploadSet[idx]
				e := ledger.Entries[d.Key]
				e.RecordKey = d.Key
				e.Source = d.Source
				e.Input = d.Input
				e.PendingRecord = append([]byte(nil), d.Canonical...)
				e.PendingAttemptID = id
				e.Status = overrides.StatusPending
				e.PendingSince = &at
				e.UpdatedAt = at
				ledger.Entries[d.Key] = e
			}
			if err := ledgerStore.Save(ledger); err != nil {
				result.Stopped = "override ledger write failed"
				return result, fmt.Errorf("cannot persist the override ledger before any upload; nothing was retransmitted this round: %w", err)
			}
			for _, chunk := range chunkOverrideDelta(uploadSet) {
				if budgetReached() {
					result.Stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run toktrail resync --all --replace-existing to continue", opt.MaxBatches)
					break
				}
				stop, err := uploadOverrideChunk(ctx, store, stateDir, serverURL, client, &ledger, ledgerStore, scope, st, opt, now, chunk, &result, &uploads)
				if stop {
					return result, err
				}
			}
		}
	}

	// Completion: the pass is complete only when no pending attempt
	// remains AND no current-scan record was refused as invalid — a pass
	// that skipped records must never read as a complete repair.
	// Completion is declared under a fresh authorization check, mirroring
	// the archive pass's completion gate.
	pending := 0
	for _, e := range ledger.Entries {
		if e.Status == overrides.StatusPending {
			pending++
		}
	}
	result.RemainingPending = pending
	invalid := 0
	for _, sp := range plan.Sources {
		invalid += sp.InvalidRecords
	}
	if result.Stopped == "" && pending == 0 && invalid == 0 {
		if _, err := outbox.New(stateDir).RecordPreflightAttempt(now().UTC()); err != nil {
			result.Stopped = "preflight accounting failed"
			return result, fmt.Errorf("cannot persist preflight attempt accounting before the completion check; the pass stays incomplete: %w", err)
		}
		finalSelf, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
		if err != nil {
			result.Stopped = "authorization preflight failed"
			return result, fmt.Errorf("override stopped before the completion claim; the pass stays incomplete: %w", err)
		}
		if drift, why := selfDrift(scope, finalSelf, st); drift {
			result.Stopped = scopeGateStopped
			return result, fmt.Errorf("override stopped before claiming completion: the consent scope changed while the pass was running (%s); every accepted upload stands, but the pass's decisions were planned under the old scope — re-run the same command and it re-plans under the live scope", why)
		}
		result.Completed = true
	} else if result.Stopped == "" {
		switch {
		case invalid > 0 && pending > 0:
			result.Stopped = fmt.Sprintf("%d record(s) remain pending acknowledgment and %d current-scan record(s) are structurally invalid and were skipped; the pass is NOT a complete repair — fix the sources and re-run toktrail resync --all --replace-existing", pending, invalid)
		case invalid > 0:
			result.Stopped = fmt.Sprintf("%d current-scan record(s) are structurally invalid and were skipped; the pass is NOT a complete repair — fix the sources and re-run toktrail resync --all --replace-existing", invalid)
		default:
			result.Stopped = fmt.Sprintf("%d record(s) remain pending acknowledgment (rejected by the server or not retryable this run); re-run toktrail resync --all --replace-existing after resolving them", pending)
		}
	}
	if !result.Completed {
		// An incomplete pass is a non-nil error: rejected, invalid, or
		// budget-stopped outcomes must never read as success up the
		// call chain.
		return result, fmt.Errorf("override pass incomplete: %s", result.Stopped)
	}
	return result, nil
}

// safeOverrideClient applies the same HTTP policy the connect sync path
// enforces — a timeout bounded to 15 seconds and no redirects — to the
// capabilities GET and every data POST alike, so the override pass never
// follows a redirect or hangs longer than a normal sync request.
func safeOverrideClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	}
	if cloned.Timeout <= 0 || cloned.Timeout > 15*time.Second {
		cloned.Timeout = 15 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return &cloned
}

// probeReplaceExisting verifies the server advertises the replace-existing
// capability before any override upload. The capabilities endpoint is
// unauthenticated and carries no device data. An absent feature, an
// unreachable endpoint, or an undecodable response fails closed.
func probeReplaceExisting(ctx context.Context, client *http.Client, serverURL string) error {
	endpoint, err := joinOverrideURL(serverURL, "/v1/capabilities")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot check the server's capabilities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the server's capabilities endpoint returned HTTP %d", resp.StatusCode)
	}
	var caps struct {
		Features []string `json:"features"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return fmt.Errorf("the server's capabilities response is not decodable: %w", err)
	}
	for _, feature := range caps.Features {
		if feature == replaceExistingFeature {
			return nil
		}
	}
	return fmt.Errorf("the server does not advertise the %s capability (older servers reject the flag with 400); upgrade the server before running the override pass", replaceExistingFeature)
}

func joinOverrideURL(base, path string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "", errors.New("missing server URL")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path, nil
}

// uploadOverrideChunk writes one deterministic override batch, uploads it
// with replaceExisting=true, and promotes exactly the acknowledged
// records. It mutates the ledger (a new round's pending attempts were
// already persisted by the caller; a promotion happens here) and the
// result counters. stop is true when the caller must return immediately
// with err.
func uploadOverrideChunk(ctx context.Context, store statedir.Store, stateDir, serverURL string, client *http.Client, ledger *overrides.Ledger, ledgerStore overrides.Store, scope liveScope, st statedir.DeviceState, opt OverrideOptions, now func() time.Time, chunk []overrideDelta, result *OverrideResult, uploads *int) (bool, error) {
	id := overrideBatchID(chunk)
	file, err := writeChildBatch(stateDir, id, chunkRecords(chunk), frozenDataEpoch(st.DataEpoch))
	if err != nil {
		result.Stopped = "override batch write failed"
		return true, fmt.Errorf("override stopped; the pending attempts stay resumable: %w", err)
	}
	if _, err := outbox.New(stateDir).RecordPreflightAttempt(now().UTC()); err != nil {
		result.Stopped = "preflight accounting failed"
		return true, fmt.Errorf("cannot persist preflight attempt accounting before the upload of %s; the pending attempts stay resumable: %w", id, err)
	}
	res, runErr := syncclient.Run(ctx, store, syncclient.Options{
		StateDir:        stateDir,
		ServerURL:       serverURL,
		BatchFile:       file,
		BatchID:         id,
		HTTPClient:      client,
		ReplaceExisting: true,
	})
	if runErr != nil {
		result.Stopped = overrideStopReason(runErr)
		return true, fmt.Errorf("override stopped after the upload of %s failed; the pending attempts stay resumable and nothing further was sent: %w", id, runErr)
	}
	if res.Receipt.BatchID == "" {
		result.Stopped = "upload failed"
		return true, fmt.Errorf("override stopped: upload of %s returned no batch receipt; the pending attempts stay resumable", id)
	}
	// Partial-receipt confirmation by exact index: only records the
	// receipt did not reject are promoted; rejected keys keep their
	// frozen attempt pending for the next explicit pass.
	rejectedIdx := make(map[int]string, len(res.Receipt.RecordErrors))
	for _, re := range res.Receipt.RecordErrors {
		if re.Index >= 0 && re.Index < len(chunk) {
			rejectedIdx[re.Index] = re.Code
		}
	}
	acceptedKeys := make([]string, 0, len(chunk))
	for idx, d := range chunk {
		if code, ok := rejectedIdx[idx]; ok {
			result.RejectedRecords++
			result.RejectedKeys = append(result.RejectedKeys, d.Key+" ("+code+")")
			continue
		}
		acceptedKeys = append(acceptedKeys, d.Key)
		if d.IsNew {
			result.InsertedRecords++
		} else {
			result.ReplacedRecords++
		}
	}
	if len(acceptedKeys) > 0 {
		at := now().UTC()
		for _, key := range acceptedKeys {
			e := ledger.Entries[key]
			e.Record = append([]byte(nil), e.PendingRecord...)
			e.AttemptID = e.PendingAttemptID
			e.PendingRecord = nil
			e.PendingAttemptID = ""
			e.PendingSince = nil
			e.Status = overrides.StatusConfirmed
			e.UpdatedAt = at
			ledger.Entries[key] = e
		}
		if err := ledgerStore.Save(*ledger); err != nil {
			result.Stopped = "override ledger write failed"
			return true, fmt.Errorf("cannot persist the override confirmations for %s; the batch was uploaded but its attempts stay pending and will replay idempotently on the next pass: %w", id, err)
		}
		result.ConfirmedKeys += len(acceptedKeys)
	}
	*uploads++
	result.Uploads++
	result.UploadedRecords += res.Receipt.AcceptedRecords + res.Receipt.RejectedRecords
	if opt.Progress != nil {
		opt.Progress(OverrideProgressEvent{
			BatchID:  id,
			Outcome:  "done",
			Records:  len(chunk),
			Accepted: len(acceptedKeys),
			Rejected: len(rejectedIdx),
			Replay:   res.Receipt.Replay,
		})
	}
	// Mid-pass authorization drift: the receipt was accepted under
	// res.Self; when that snapshot moved past the scope this pass
	// evaluated, stop before any further upload. Accepted uploads stand;
	// the pending attempts stay resumable.
	if drift, why := selfDrift(scope, res.Self, st); drift {
		result.Stopped = scopeGateStopped
		return true, fmt.Errorf("override stopped mid-pass: the consent scope changed while retransmitting (%s); the server accepted the upload of %s under the live authorization, but this pass's remaining decisions were planned under the old scope — re-run the same command and it re-plans under the live scope (already-delivered records replay without double counting)", why, id)
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Override planning
// ---------------------------------------------------------------------------

// OverrideOptions configures one override pass.
type OverrideOptions struct {
	StateDir   string
	ServerURL  string
	HTTPClient *http.Client
	DryRun     bool
	// MaxBatches is an optional per-run upload budget (0 = whole delta).
	MaxBatches int
	// Confirm is invoked exactly once with the actual current-scan plan,
	// before any state change or network traffic. Returning an error
	// aborts the pass with zero writes. Required for non-dry-run runs.
	Confirm  func(OverridePlan) error
	Progress func(OverrideProgressEvent)
	Now      func() time.Time
}

// OverrideSourcePlan summarizes one granted input's current-scan delta.
type OverrideSourcePlan struct {
	Source string
	Input  string
	// Scanned counts every record the current scan produced.
	Scanned int
	// ScanIssues counts source lines the scan could not parse, and
	// ScanQuarantined counts lines the loader itself quarantined; both
	// are reported honestly and mirror normal collection semantics.
	ScanIssues      int
	ScanQuarantined int
	// Drifted counts same-key records whose current content differs from
	// the effective baseline (the acknowledged override content when one
	// exists, otherwise the stored payload).
	Drifted int
	// NewRecords counts current-scan records no baseline has ever seen.
	NewRecords int
	// FrozenAttempts counts this input's pending attempts the pass must
	// resolve first (uploaded frozen before any new round).
	FrozenAttempts int
	// AlreadyCurrent counts keys whose effective baseline already equals
	// the current scan (nothing to do).
	AlreadyCurrent int
	// InvalidRecords counts current-scan records refused at planning
	// (structurally not uploadable); they are never uploaded nor
	// ledgered, and their presence keeps the pass incomplete.
	InvalidRecords int
	// InvalidKeys lists a bounded sample of those keys.
	InvalidKeys []string
}

// OverridePlan is the offline-plannable description of one override pass,
// built from the CURRENT source scans — never from the stored archive.
type OverridePlan struct {
	DeviceID        string
	ServerURL       string
	StateDir        string
	LedgerPath      string
	Sources         []OverrideSourcePlan
	ExcludedSources []string
	// WithheldNoGrant counts ledger-pending keys whose local source grant
	// is currently missing or disabled: their frozen attempts stay
	// pending (blocking their source's normal collection) until the
	// grant returns or the ledger is abandoned.
	WithheldNoGrant int
	TotalReplace    int
	TotalNew        int
	Warning         string
}

// OverrideProgressEvent reports one override batch's outcome.
type OverrideProgressEvent struct {
	BatchID  string
	Outcome  string // done
	Records  int
	Accepted int
	Rejected int
	Replay   bool
}

// OverrideResult reports what one override pass did.
type OverrideResult struct {
	Plan   OverridePlan
	DryRun bool
	Self   syncclient.SelfStatus

	Uploads         int
	UploadedRecords int
	// ReplacedRecords counts accepted records that had a baseline.
	ReplacedRecords int
	// InsertedRecords counts accepted records without a baseline.
	InsertedRecords    int
	RejectedRecords    int
	RejectedKeys       []string
	ConfirmedKeys      int
	WithheldOutOfScope int
	RemainingPending   int
	Completed          bool
	Stopped            string
}

// overrideDelta is one current-scan record selected for override upload.
type overrideDelta struct {
	Key       string
	Canonical []byte
	Source    string
	Input     string
	IsNew     bool
	// AttemptID is the persistent unique id of the override attempt this
	// record belongs to: minted when a new round decides the attempt,
	// reused from the ledger when a frozen attempt is retried. It is
	// folded into the batch identity so an A→B→A content sequence never
	// reuses the first A's server receipt.
	AttemptID string
}

// newAttemptID mints one override attempt id.
func newAttemptID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "oa-" + hex.EncodeToString(b[:]), nil
}

// overrideGrant is one enabled grant of the two override sources.
type overrideGrant struct {
	Source string
	Input  string
}

// planOverride scans the granted codex-jsonl and deepseek-harness inputs
// and classifies every current-scan record against the effective
// baseline (outbox pending/synced/reorganized + quarantine, superseded by
// acknowledged overrides) and the override ledger's frozen attempts. It
// performs no network access and writes nothing. The returned delta is
// the FROZEN plan: execution re-classifies it against the ledger only
// and never re-scans, so nothing the user did not confirm can be sent.
//
// This no-context entry point keeps the historical offline-planning
// behavior for existing callers: the scan runs under
// context.Background() and is uncancellable, exactly as before the
// context threading existed. Cancellable callers (RunOverride) use
// planOverrideContext.
func planOverride(stateDir string, st statedir.DeviceState, serverURL string, ledger overrides.Ledger) (OverridePlan, []overrideDelta, error) {
	return planOverrideContext(context.Background(), stateDir, st, serverURL, ledger)
}

// planOverrideContext is planOverride with the pass's cancellation scope:
// the current scan honors ctx at every grant and record boundary, and a
// cancelled or expired scope fails the whole planning closed (never a
// partial plan, never a per-grant skip) with an error matching
// errors.Is(err, context.Canceled) / errors.Is(err, context.DeadlineExceeded).
// Planning stays read-only: a cancellation here returns before the
// dry-run/confirmation gates, so nothing is uploaded, nothing is
// ledgered, and no plan or WAL fragment is committed.
func planOverrideContext(ctx context.Context, stateDir string, st statedir.DeviceState, serverURL string, ledger overrides.Ledger) (OverridePlan, []overrideDelta, error) {
	plan := OverridePlan{
		DeviceID:   st.DeviceID,
		ServerURL:  serverURL,
		StateDir:   stateDir,
		LedgerPath: overrides.New(stateDir).Path(),
		Warning:    "same-key conflicts are resolved in favor of the current scanned record; records the server rejects keep their attempt pending and are NOT confirmed; pending attempts are uploaded frozen before any new round; records the current scan no longer produces are left untouched",
	}
	granted, err := overrideGrants(stateDir, &plan)
	if err != nil {
		return plan, nil, err
	}
	delta, err := classifyOverrideScanContext(ctx, stateDir, granted, ledger, &plan)
	if err != nil {
		return plan, nil, err
	}
	return plan, delta, nil
}

// reclassifyFrozenDelta filters the confirmed frozen plan against the
// ledger as execution has left it: keys that still carry a pending
// attempt are dropped (their frozen attempt must be resolved first), and
// keys whose acknowledged content already equals the confirmed content
// are done. It performs no scan.
func reclassifyFrozenDelta(delta []overrideDelta, ledger overrides.Ledger) []overrideDelta {
	out := make([]overrideDelta, 0, len(delta))
	for _, d := range delta {
		if _, pending := ledger.Pending(d.Key); pending {
			continue
		}
		if entry, ok := ledger.Confirmed(d.Key); ok && entry.Source == d.Source && entry.Input == d.Input {
			if stored, err := overrides.Canonical(entry.Record); err == nil && bytes.Equal(stored, d.Canonical) {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

// overrideGrants loads the enabled grants of the two override sources and
// records the excluded others on the plan.
func overrideGrants(stateDir string, plan *OverridePlan) ([]overrideGrant, error) {
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		return nil, fmt.Errorf("cannot read the local source grants; the override pass refuses to scan without current local authorization: %w", err)
	}
	granted := make([]overrideGrant, 0)
	for _, grant := range cfg.Grants {
		if !grant.Enabled {
			continue
		}
		if overrides.IsOverrideSource(grant.Source) {
			granted = append(granted, overrideGrant{Source: grant.Source, Input: grant.Input})
		} else {
			plan.ExcludedSources = append(plan.ExcludedSources, grant.Source+" "+grant.Input)
		}
	}
	return granted, nil
}

// classifyOverrideScan performs the per-grant current scan and delta
// classification, filling the plan's per-source summaries. Pending
// attempts are accounted per (source, input): a source with several
// granted inputs never mixes one input's attempts into another's plan.
//
// This no-context entry point keeps the historical uncancellable scan
// for existing offline-planning callers; RunOverride plans through
// classifyOverrideScanContext instead.
func classifyOverrideScan(stateDir string, granted []overrideGrant, ledger overrides.Ledger, plan *OverridePlan) ([]overrideDelta, error) {
	return classifyOverrideScanContext(context.Background(), stateDir, granted, ledger, plan)
}

// classifyOverrideScanContext is classifyOverrideScan carrying the pass's
// cancellation scope. The scope is honored at three boundaries: before
// each grant's scan, inside the source loader (adapter.Options.Context
// reaches registry.LoadRecordsForSource, so the loader's own per-file and
// per-line checks observe the same scope), and at every record of the
// classification loop. A cancelled or expired scope fails the WHOLE
// classification closed — the error wraps ctx.Err() with %w so callers
// match it with errors.Is(err, context.Canceled) or
// errors.Is(err, context.DeadlineExceeded) — and is never swallowed as a
// per-grant skip that would let later grants scan anyway.
func classifyOverrideScanContext(ctx context.Context, stateDir string, granted []overrideGrant, ledger overrides.Ledger, plan *OverridePlan) ([]overrideDelta, error) {
	delta := make([]overrideDelta, 0)
	// scannedIn tracks, per (source \0 input), the keys this pass
	// actually scanned — the per-input pending bookkeeping below uses it
	// so a key produced by one input is never attributed to another.
	scannedIn := map[string]map[string]bool{}
	// seenContent is shared across EVERY granted input of the pass: two
	// granted inputs may overlap the same session files, so the same key
	// with conflicting content across inputs fails closed, and an
	// identical key is planned exactly once, attributed to the first
	// granted input whose scan produced it. A local map keeps repeated
	// planning calls independent and race-free.
	seenContent := map[string][]byte{}
	seenOwner := map[string]string{}
	for _, g := range granted {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("override scan cancelled before scanning %s at %s: %w", g.Source, g.Input, err)
		}
		sp := OverrideSourcePlan{Source: g.Source, Input: g.Input}
		baseline, err := sourceStoredBaseline(stateDir, g.Source)
		if err != nil {
			return nil, err
		}
		loaded, err := registry.LoadRecordsForSource(adapter.Options{
			Source:   g.Source,
			Input:    g.Input,
			StateDir: stateDir,
			Context:  ctx,
		})
		if err != nil {
			return nil, fmt.Errorf("cannot scan the current %s records at %s: %w", g.Source, g.Input, err)
		}
		sp.ScanIssues = len(loaded.Issues)
		sp.ScanQuarantined = loaded.Quarantined
		grantKey := g.Source + "\x00" + g.Input
		scanned := map[string]bool{}
		scannedIn[grantKey] = scanned
		for _, rec := range loaded.Records {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("override scan cancelled while classifying %s records at %s: %w", g.Source, g.Input, err)
			}
			key, _ := rec["recordKey"].(string)
			canonical, err := overrides.CanonicalRecord(rec)
			if err != nil {
				return nil, fmt.Errorf("cannot canonicalize a scanned %s record: %w", g.Source, err)
			}
			if prev, ok := seenContent[key]; ok {
				if !bytes.Equal(prev, canonical) {
					return nil, fmt.Errorf("the current scan produced record %s with conflicting content under two granted inputs (%s and %s); failing closed", key, seenOwner[key], grantKey)
				}
				// Identical key already planned under an earlier granted
				// input: counted once there, never twice here.
				continue
			}
			seenContent[key] = canonical
			seenOwner[key] = grantKey
			scanned[key] = true
			sp.Scanned++
			if err := validateOverrideRecord(canonical); err != nil {
				sp.InvalidRecords++
				if len(sp.InvalidKeys) < 20 {
					sp.InvalidKeys = append(sp.InvalidKeys, key)
				}
				continue
			}
			// The effective baseline for the key: the acknowledged
			// override content when one exists, otherwise the stored
			// payload. A scan that matches the archived value while an
			// override was acknowledged is a NEW drift against the
			// acknowledged baseline, never "already synced".
			effective, hasEffective := baseline[key]
			if entry, ok := ledger.Confirmed(key); ok && entry.Source == g.Source && entry.Input == g.Input {
				stored, cerr := overrides.Canonical(entry.Record)
				if cerr != nil {
					return nil, fmt.Errorf("override ledger record %s is not valid JSON: %w", key, cerr)
				}
				effective, hasEffective = stored, true
			}
			if hasEffective && bytes.Equal(effective, canonical) {
				sp.AlreadyCurrent++
				continue
			}
			if hasEffective {
				sp.Drifted++
			} else {
				sp.NewRecords++
			}
			// Keys whose attempt is still frozen are NOT part of a new
			// round: the frozen payload must be resolved first.
			if _, pending := ledger.Pending(key); pending {
				continue
			}
			delta = append(delta, overrideDelta{
				Key:       key,
				Canonical: canonical,
				Source:    g.Source,
				Input:     g.Input,
				IsNew:     !hasEffective,
			})
		}
		// This input's frozen attempts only: pending entries of the same
		// source under a different input belong to that input's plan.
		for _, e := range ledger.Entries {
			if e.Status == overrides.StatusPending && e.Source == g.Source && e.Input == g.Input {
				sp.FrozenAttempts++
			}
		}
		plan.Sources = append(plan.Sources, sp)
		plan.TotalReplace += sp.Drifted
		plan.TotalNew += sp.NewRecords
	}
	// Frozen attempts whose (source, input) grant is missing stay pending:
	// they cannot be retried and keep blocking their source until the
	// grant returns or the ledger is abandoned. A key scanned under a
	// still-granted input is never counted here.
	grantedSet := map[string]bool{}
	for _, g := range granted {
		grantedSet[g.Source+"\x00"+g.Input] = true
	}
	for key, entry := range ledger.Entries {
		if entry.Status != overrides.StatusPending {
			continue
		}
		if grantedSet[entry.Source+"\x00"+entry.Input] && scannedIn[entry.Source+"\x00"+entry.Input][key] {
			continue
		}
		if grantedSet[entry.Source+"\x00"+entry.Input] && !scannedIn[entry.Source+"\x00"+entry.Input][key] {
			// The grant exists but the key vanished from the scan: the
			// frozen attempt still must be resolved (uploaded and
			// acknowledged) before anything else may happen to the key —
			// it is counted as a frozen attempt of its input, already
			// done above. Not a WithheldNoGrant case.
			continue
		}
		plan.WithheldNoGrant++
		_ = key
	}
	return delta, nil
}

// frozenAttempts returns the pending attempts whose (source, input)
// grant is currently enabled, as delta records carrying their exact
// frozen payload and persistent attempt id. Their batch identity derives
// from that frozen content and attempt id, so a re-upload after a crash
// replays instead of double counting.
func frozenAttempts(ledger overrides.Ledger, stateDir string) []overrideDelta {
	granted := map[string]bool{}
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		return nil
	}
	for _, grant := range cfg.Grants {
		if grant.Enabled {
			granted[grant.Source+"\x00"+grant.Input] = true
		}
	}
	out := make([]overrideDelta, 0)
	for key, e := range ledger.Entries {
		if e.Status != overrides.StatusPending {
			continue
		}
		if !granted[e.Source+"\x00"+e.Input] {
			continue
		}
		frozen := e.PendingRecord
		if len(frozen) == 0 {
			continue
		}
		isNew := len(e.Record) == 0
		out = append(out, overrideDelta{
			Key:       key,
			Canonical: append([]byte(nil), frozen...),
			Source:    e.Source,
			Input:     e.Input,
			IsNew:     isNew,
			AttemptID: e.PendingAttemptID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// sourceStoredBaseline builds the same-key content baseline for one
// source from every outbox status (pending, synced, reorganized) and the
// quarantine store — exactly the baseline the source history filters
// compare against, before override supersession.
func sourceStoredBaseline(stateDir, source string) (map[string][]byte, error) {
	known := make(map[string][]byte)
	remember := func(raw json.RawMessage) error {
		canonical, err := overrides.Canonical(raw)
		if err != nil {
			return err
		}
		var probe struct {
			RecordKey string `json:"recordKey"`
		}
		if err := json.Unmarshal(canonical, &probe); err != nil {
			return err
		}
		if probe.RecordKey == "" {
			return fmt.Errorf("stored %s record has no key", source)
		}
		if prev, ok := known[probe.RecordKey]; ok && !bytes.Equal(prev, canonical) {
			return fmt.Errorf("stored %s record %s has conflicting content", source, probe.RecordKey)
		}
		known[probe.RecordKey] = canonical
		return nil
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range out.Batches {
		if entry.Source != source {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown %s outbox status %q", source, entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read %s history batch %s: %w", source, entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("%s history batch identity mismatch", source)
		}
		for _, rec := range batch.Records {
			if err := remember(rec); err != nil {
				return nil, err
			}
		}
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Source != source {
			continue
		}
		if err := remember(entry.Record); err != nil {
			return nil, err
		}
	}
	return known, nil
}

// validateOverrideRecord mirrors the send-path gates (privacy whitelist,
// per-record size cap, recordKey, occurredAt) so a bad current-scan
// record is refused at planning time per key instead of wedging the pass
// after it is ledgered.
func validateOverrideRecord(canonical []byte) error {
	if !utf8.Valid(canonical) {
		return errors.New("record contains invalid UTF-8")
	}
	var record adapter.Record
	if err := json.Unmarshal(canonical, &record); err != nil || record == nil {
		return errors.New("record is not a record object")
	}
	if !adapter.RecordIsUploadSafe(record) {
		return errors.New("record carries extra fields or an invalid model (outside the upload whitelist)")
	}
	if len(canonical) > syncclient.MaxBatchPayloadBytes {
		return fmt.Errorf("record exceeds the maximum allowed size (%d bytes > %d bytes)", len(canonical), syncclient.MaxBatchPayloadBytes)
	}
	if _, err := recordKeyOf(canonical); err != nil {
		return err
	}
	var probe struct {
		OccurredAt string `json:"occurredAt"`
	}
	if err := json.Unmarshal(canonical, &probe); err != nil {
		return err
	}
	if strings.TrimSpace(probe.OccurredAt) == "" {
		return errors.New("record has no occurredAt")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(probe.OccurredAt)); err != nil {
		return fmt.Errorf("record has an unparseable occurredAt %q", probe.OccurredAt)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Override upload derivation
// ---------------------------------------------------------------------------

// overrideBatchID derives the deterministic override batch identity from
// the persistent attempt ids and the FULL canonical content of the batch
// (source, then every attempt id, key, and record in order). Retrying
// the same attempt replays to the identical id; a new attempt round —
// even with content identical to an old round (A→B→A) — derives a
// different batch instead of replaying the old round's receipt.
func overrideBatchID(chunk []overrideDelta) string {
	h := sha256.New()
	h.Write([]byte(chunk[0].Source))
	for _, d := range chunk {
		h.Write([]byte{0})
		h.Write([]byte(d.AttemptID))
		h.Write([]byte{0})
		h.Write([]byte(d.Key))
		h.Write([]byte{0})
		h.Write(d.Canonical)
	}
	return "ovr-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// overrideEnvelopeOverhead is the fixed JSON envelope overhead of one
// override batch on the wire, INCLUDING the replaceExisting flag the
// send path adds (the on-disk child file never carries it; the POST body
// does).
const overrideEnvelopeOverhead = len(`{"batchId":"ovr-0123456789abcdef","records":[],"replaceExisting":true}`)

// chunkOverrideDelta partitions the delta per source into chunks of <=
// syncclient.MaxBatchRecords records and <= syncclient.MaxBatchPayloadBytes
// compact envelope. Records are ordered by recordKey so the partition is
// deterministic.
func chunkOverrideDelta(delta []overrideDelta) [][]overrideDelta {
	bySource := map[string][]overrideDelta{}
	sources := make([]string, 0)
	for _, d := range delta {
		if _, ok := bySource[d.Source]; !ok {
			sources = append(sources, d.Source)
		}
		bySource[d.Source] = append(bySource[d.Source], d)
	}
	sort.Strings(sources)
	chunks := make([][]overrideDelta, 0)
	for _, source := range sources {
		group := bySource[source]
		sort.Slice(group, func(i, j int) bool { return group[i].Key < group[j].Key })
		var current []overrideDelta
		currentSize := overrideEnvelopeOverhead
		for _, d := range group {
			projected := currentSize + len(d.Canonical)
			if len(current) > 0 {
				projected++
			}
			if len(current) > 0 && (len(current) >= syncclient.MaxBatchRecords || projected > syncclient.MaxBatchPayloadBytes) {
				chunks = append(chunks, current)
				current = nil
				currentSize = overrideEnvelopeOverhead
				projected = overrideEnvelopeOverhead + len(d.Canonical)
			}
			current = append(current, d)
			currentSize = projected
		}
		if len(current) > 0 {
			chunks = append(chunks, current)
		}
	}
	return chunks
}

func chunkRecords(chunk []overrideDelta) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(chunk))
	for _, d := range chunk {
		out = append(out, d.Canonical)
	}
	return out
}

// overrideStopReason maps an upload error to the result's stopped marker.
func overrideStopReason(err error) string {
	switch {
	case errors.Is(err, syncclient.ErrDeviceRevoked), errors.Is(err, syncclient.ErrSubjectDeleted):
		return "device no longer authorized"
	case errors.Is(err, syncclient.ErrDevicePaused):
		return "device paused"
	case errors.Is(err, syncclient.ErrScopeChanged), errors.Is(err, syncclient.ErrOutsideScope):
		return "server scope rejection"
	default:
		return "upload failed"
	}
}
