package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/cursor/protocol"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncretry"
)

// Stable ingest authorization codes mirrored from the server contract. The
// collector keys off these sentinels (not the human-readable message), so
// callers can distinguish terminal stop conditions from retryable failures.
var (
	// ErrDeviceRevoked maps to the server's stable 401 device_revoked code:
	// the device binding is permanently revoked. Sending stops and the
	// collector never re-binds automatically.
	ErrDeviceRevoked = errors.New("device_revoked")
	// ErrSubjectDeleted maps to the server's stable 401 subject_deleted
	// code: the subject identity is tombstoned and can never be reused.
	// Sending stops and the collector never re-binds automatically.
	ErrSubjectDeleted = errors.New("subject_deleted")
	// ErrScopeChanged maps to the server's stable 409 scope_changed code:
	// the consent revision sent with the batch predates a consent-scope
	// change. When the batch came from the outbox (state directory present),
	// the collector automatically and persistently reorganizes it under the
	// live scope: kept records move to a new batch with a new ID, the rest
	// are quarantined recoverably, and the old batch stays immutable and
	// terminal. The error still surfaces so callers see the reorganization.
	ErrScopeChanged = errors.New("scope_changed")
	// ErrOutsideScope maps to the server's stable 403 outside_scope code:
	// record(s) fall outside the current consent scope. Outbox batches get
	// the same automatic persistent reorganization as scope_changed; all
	// out-of-scope records are quarantined recoverably and the outbox head
	// is freed instead of blocking later batches.
	ErrOutsideScope = errors.New("outside_scope")
	// ErrDeviceUnauthorized marks an authentication or identity failure on
	// GET /v1/devices/self: the server rejected the device credentials
	// (HTTP 401/403) or answered with another device's authorization.
	// Callers must stop local reading; this is never treated as a
	// transient network failure.
	ErrDeviceUnauthorized = errors.New("device_unauthorized")
	// ErrSelfProtocol marks a structurally invalid device self response
	// (undecodable body or a missing device object on HTTP 200). Callers
	// must stop local reading rather than fall back to a previous scope.
	ErrSelfProtocol = errors.New("self_protocol")
	// ErrDevicePaused maps to the grant protocol's paused state: the
	// server explicitly paused collection for this device. Callers stop
	// sending (uploads and tool-status reports) and keep pending batches
	// queued; it is a state, not a failure, and never triggers re-binding.
	ErrDevicePaused = errors.New("device_paused")
	// ErrEpochStale maps the server's stable 409 device_epoch_stale code
	// and every local data-epoch fence: the batch's durable dataEpoch or
	// the server-reported device epoch does not match the locally locked
	// epoch, so the data predates (or postdates) a device usage reset.
	// Sending stops and the batch stays pending; the fence is final,
	// never retried, and never reorganized (a scope reorganization
	// cannot relabel old-epoch data into the current epoch). The local
	// epoch only advances through an initial bind or an explicit
	// force-recollect journal transition — never from a self snapshot —
	// so a mismatch means the device needs the force-recollect flow, not
	// a retry.
	ErrEpochStale = errors.New("device_epoch_stale")
	// ErrResetInProgress reports that the state directory carries a
	// force-recollect journal that has not completed: ordinary
	// entrypoints (periodic collection, connect, sync, and every
	// syncclient send) stop before any recover, export or upload work,
	// so a half-finished reset can never mix old and new epoch data.
	// Only the recollect driver may continue, by naming the journal's
	// exact request id in Options.AllowedResetRequestID.
	ErrResetInProgress = errors.New("device_reset_in_progress")
	// ErrResetConflict maps HTTP 409 answers on the device usage-reset
	// endpoints: the expected data epoch or consent revision no longer
	// matches the server's current state, or the same request id arrived
	// with a different payload. It is final; the recollect driver must
	// re-read the plan before retrying.
	ErrResetConflict = errors.New("device_reset_conflict")
	// ErrQuarantineHeld reports the recovery-only outcome that quarantined
	// records exist but none is currently recoverable: the live consent
	// scope still excludes them (or the revision is not strictly newer),
	// or — on a device with a configured grant store — their (source,
	// input) no longer carries an enabled local grant. It is a steady
	// state, not a failure: the records stay quarantined and recoverable
	// until the authorization widens again. The periodic drain treats it
	// as a settled run; manual `toktrail sync` still surfaces the wrapped
	// diagnosis.
	ErrQuarantineHeld = errors.New("quarantine_held")
	// ErrPreflightAccounting reports that the durable authorization-attempt
	// accounting write failed BEFORE a device self GET: the attempt was
	// stopped with zero HTTP traffic of any kind and nothing was sent.
	// The error is always plain (never retry-marked), so the retry policy
	// ends the loop immediately; callers that keep jobs resumable can
	// match it with errors.Is and must not treat the stopped target as a
	// failed send.
	ErrPreflightAccounting = errors.New("preflight_accounting")
)

type Options struct {
	ServerURL    string
	StateDir     string
	BatchFile    string
	BatchID      string
	HTTPClient   *http.Client
	ToolStatuses []ToolStatus
	// Budget is optional. When set, one attempt is reserved immediately
	// before an ingest POST, after local authorization and privacy gates.
	Budget      *syncbudget.Budget
	BudgetQueue string
	// Retry is optional. nil (the default) keeps the original behavior:
	// exactly one send attempt, with every failure returned untouched.
	// When set, a failed ingest send is retried under the policy — and
	// only transport failures of the POST itself, HTTP 429, explicit 5xx
	// responses, and success responses whose body was lost or truncated;
	// authorization (401/403), paused, scope, receipt-validation, and
	// conflict failures are final, and an acknowledged send is never
	// repeated. Every attempt re-runs the durable attempt accounting and
	// the full authorization preflight and privacy gate, keeps the same
	// batch ID with the same immutable request bytes, and reserves the
	// upload budget again before the actual POST. Production wiring that
	// enables retries should construct the policy with an explicit
	// non-zero random Jitter: syncretry.New on its own is deterministic
	// (jitter nil). ReportToolStatuses also uses this policy for transient
	// failures of its preflight GET and metadata POST, with fresh authorization
	// each time; those metadata requests do not consume the ingest Budget.
	Retry *syncretry.Policy
	// PreflightAccounting is the preflight-only safe-accounting hook for
	// runs that deliberately pass NO StateDir — the history
	// retransmission, which selects its batch through BatchFile so the
	// outbox is never re-marked and synced batches stay terminal. It is
	// invoked immediately before EVERY device self GET this run performs
	// (the first attempt's and every retry's), and the write must
	// succeed before the GET is made: a non-nil error fails that attempt
	// closed with zero HTTP traffic of any kind, as a plain error the
	// retry policy treats as final. Callers wire it to the same durable
	// outbox accounting (outbox.Store.RecordPreflightAttempt) they would
	// get from a StateDir. Runs with a StateDir keep the built-in ledger
	// accounting and leave this nil.
	// PreferBatchID names the pending outbox batch to upload when no
	// BatchFile is given. The batch must still be pending; an unknown or
	// already-settled id falls back to the oldest pending batch, so a stale
	// preference can never wedge the queue.
	PreferBatchID       string
	PreflightAccounting func(at time.Time) error
	// Progress is optional. When non-nil, Run delivers one sanitized
	// AttemptEvent per send attempt of the selected batch — exactly one
	// event per attempt, emitted synchronously on Run's own goroutine
	// immediately after the attempt concludes (success or failure), in
	// strictly increasing attempt order, before any later attempt starts.
	// Run sends a single batch per call, so the attempt numbering is per
	// Run; callers looping over batches attach their own correlation.
	// The events carry only closed stage/result enums, monotonic stage
	// durations and a planned payload size behind explicit Observed bits,
	// and the receipt's decision counts and whole-batch replay bit behind
	// ReceiptKnown — never paths, URLs, batch/device/record identifiers,
	// secrets, consent revisions, HTTP statuses, server free text, or
	// error text. See AttemptEvent for the full field contract.
	//
	// nil (the default) changes nothing observable about the run: no
	// extra or fewer HTTP requests, identical durable attempt accounting
	// (MarkAttempt and the preflight ledger or hook), identical
	// WAL/retry ordering, and identical budget reservations — and no
	// instrumentation at all: no tracker is created, the monotonic clock
	// is never read for progress purposes, and the stage marks inside
	// the send path become nil-receiver no-ops that allocate nothing.
	// The callback must return quickly and must not panic; it cannot
	// influence the send in any way.
	Progress func(AttemptEvent)
	// ReplaceExisting must be enabled only for an explicitly authorized repair.
	ReplaceExisting bool
	// AllowedResetRequestID optionally names the in-progress
	// force-recollect journal request this run continues under. It is
	// set ONLY by the recollect driver. The journal guard then passes
	// when force-recollect.json exists, is not completed, and carries
	// exactly this request id; a missing journal or a different request
	// id fails closed. Ordinary callers leave it empty and are blocked
	// by any non-completed journal. The data-epoch fences are NOT
	// affected by this field: they always run, so even the recollect
	// driver must upload batches stamped with the epoch its journal
	// transition installed.
	AllowedResetRequestID string
}

type Result struct {
	State   statedir.DeviceState
	Receipt BatchReceipt
	Status  int
	// Self is the device authorization snapshot learned from the preflight;
	// Receipt.ConsentRevision-echoed header came from Self.ConsentRevision.
	Self SelfStatus
	// Recovered counts records moved out of the quarantine store back into
	// a pending batch during this run (scope widened under a strictly newer
	// consent revision).
	Recovered int
	// Quarantined counts records currently sitting in the quarantine store
	// after this run finished.
	Quarantined int
}

type BatchRequest struct {
	BatchID         string            `json:"batchId"`
	Records         []json.RawMessage `json:"records"`
	ReplaceExisting bool              `json:"replaceExisting,omitempty"`
	// DataEpoch is the durable data epoch the batch was exported under,
	// frozen in the payload exactly like the records. It is written by
	// the export pipeline from the locked device state and carried
	// verbatim through every reorganization (scope split, oversize
	// split, quarantine recovery) — never refreshed from a self
	// snapshot or the current state, so an old batch can never be
	// relabeled with a newer epoch. nil means a legacy pre-epoch batch,
	// tolerated only while the local device epoch is still 0.
	DataEpoch *int64 `json:"dataEpoch,omitempty"`
}

type BatchReceipt struct {
	BatchID         string        `json:"batchId"`
	Status          string        `json:"status"`
	AcceptedRecords int           `json:"acceptedRecords"`
	RejectedRecords int           `json:"rejectedRecords"`
	Replay          bool          `json:"replay"`
	ReceivedAt      time.Time     `json:"receivedAt"`
	RecordErrors    []RecordError `json:"recordErrors,omitempty"`
}

type RecordError struct {
	Index     int    `json:"index"`
	RecordKey string `json:"recordKey,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type ingestResponse struct {
	Batch BatchReceipt `json:"batch"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// SelfStatus is the device authorization snapshot returned by
// GET /v1/devices/self. ConsentRevision versions the upload authorization
// and must be echoed back as the X-Consent-Revision header on every ingest
// POST; HistoryFrom/UploadUntil/AllowedTools describe the live consent
// scope (nil/empty means unrestricted).
//
// Grant protocol: when GrantProtocolVersion is present, the server speaks
// the device grant protocol and the top-level Paused/AllowedTools/
// HistoryFrom/ConsentRevision fields are this device's effective grant
// scope (Paused is always sent as bool; a paused device reports
// AllowedTools containing the "__toktrail_paused__" sentinel). Absent
// GrantProtocolVersion means an older server: callers keep the legacy
// behavior and must not apply grant-scope changes.
type SelfStatus struct {
	DeviceID             string     `json:"deviceId"`
	ConsentRevision      int64      `json:"consentRevision"`
	HistoryFrom          *time.Time `json:"historyFrom,omitempty"`
	UploadUntil          *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools         []string   `json:"allowedTools,omitempty"`
	ProductionBound      bool       `json:"productionBound,omitempty"`
	UploadAuthorized     bool       `json:"uploadAuthorized"`
	Revoked              bool       `json:"revoked"`
	Paused               bool       `json:"paused,omitempty"`
	GrantProtocolVersion *int       `json:"grantProtocolVersion,omitempty"`
	// DeviceGrantManaged is the server's persistent explicit-authorization
	// flag for this device. Only a present-and-true flag permits the
	// collector to add built-in default-directory grants for confirmed
	// tools; false or absent means filter-only — the device never creates
	// local paths on the server's behalf.
	DeviceGrantManaged *bool `json:"deviceGrantManaged,omitempty"`
	// AccountSources lists the account-level sources this device is the
	// designated executor of (the server only returns the executing
	// device's sources). Absent/empty on servers without account sources.
	AccountSources []protocol.Source `json:"accountSources,omitempty"`
	// DataEpoch is the device's current data epoch as the server
	// reports it. nil means an older server that predates the
	// device-usage-reset feature (treated as epoch 0). The value is
	// parsed for callers to compare — the collector NEVER advances the
	// local state epoch from it: a mismatch is the blocked state that
	// only the force-recollect flow resolves.
	DataEpoch *int64 `json:"dataEpoch,omitempty"`
	// UsageReset is the server's summary of this device's latest usage
	// reset task, when one exists. Absent on servers without the
	// feature or devices that were never reset.
	UsageReset *DeviceUsageReset `json:"usageReset,omitempty"`
}

// DeviceUsageReset is the per-device usage-reset task summary the server
// reports on device self (and device summaries). Status is the closed
// vocabulary "recollecting" or "completed"; anything else is untrusted
// free text callers must not branch on beyond displaying a held state.
type DeviceUsageReset struct {
	RequestID      string     `json:"requestId"`
	DataEpoch      int64      `json:"dataEpoch"`
	Status         string     `json:"status"`
	ResetAt        time.Time  `json:"resetAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	ChangeSequence int64      `json:"changeSequence"`
}

type selfResponse struct {
	Device *SelfStatus `json:"device,omitempty"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	// Force-recollect journal guard, before ANY recovery or send work:
	// while a reset is in flight, replaying a half-applied scope
	// reorganization or sync ACK would mutate the very stores the
	// recollect driver is archiving and swapping. Ordinary runs stop
	// here; the recollect driver passes its journal's exact request id.
	// The guard keys on opt.StateDir, falling back to the store's own
	// directory so StateDir-less history retransmissions over a real
	// state directory stay guarded too.
	guardDir := strings.TrimSpace(opt.StateDir)
	if guardDir == "" {
		guardDir = store.Dir()
	}
	if err := GuardResetJournal(guardDir, opt.AllowedResetRequestID); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(opt.StateDir) != "" {
		// Replay any half-applied scope reorganization or quarantine
		// recovery before anything else, so state is consistent before this
		// run selects a batch.
		if err := recoverPendingReorg(strings.TrimSpace(opt.StateDir)); err != nil {
			return Result{}, err
		}
		if err := recoverPendingSyncACK(store, strings.TrimSpace(opt.StateDir)); err != nil {
			return Result{}, err
		}
	}
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	client := noRedirectClient(opt.HTTPClient)
	batchFile := strings.TrimSpace(opt.BatchFile)
	ledger := outbox.New(strings.TrimSpace(opt.StateDir))
	fromOutbox := false
	var outboxEntry outbox.BatchEntry
	if batchFile == "" && strings.TrimSpace(opt.StateDir) != "" {
		// A caller that already selected a pending batch (the periodic
		// drain, which prefers recent data) passes its id here; without it
		// the historical oldest-first selection applies.
		entry, ok, err := ledger.PendingByID(opt.PreferBatchID)
		if err != nil {
			return Result{}, err
		}
		if !ok {
			entry, ok, err = ledger.NextPending()
			if err != nil {
				return Result{}, err
			}
		}
		if !ok {
			// Empty outbox: if quarantined records exist, try to recover
			// them under the live scope. This path performs exactly one
			// self GET (preceded by durable attempt accounting) and no
			// ingest POST. A revoked or unknown scope stops with an error.
			entries, err := quarantine.New(strings.TrimSpace(opt.StateDir)).Load()
			if err != nil {
				return Result{}, err
			}
			if len(entries) == 0 {
				return Result{}, errors.New("missing batch file and no pending outbox batch")
			}
			self, recovered, err := recoverQuarantinedWithFreshSelf(ctx, client, serverURL, st, strings.TrimSpace(opt.StateDir))
			if err != nil {
				return Result{}, err
			}
			if recovered == 0 {
				return Result{}, fmt.Errorf("%w; missing batch file and no pending outbox batch; %d quarantined record(s) remain outside the consent scope and need a strictly newer consent revision before they can be recovered (or their local source grant is no longer enabled)", ErrQuarantineHeld, len(entries))
			}
			return Result{Self: self, Recovered: recovered, Quarantined: quarantineCount(strings.TrimSpace(opt.StateDir))}, nil
		}
		outboxEntry = entry
		batchFile = entry.File
		if strings.TrimSpace(opt.BatchID) == "" {
			opt.BatchID = entry.BatchID
		}
		fromOutbox = true
	}
	if opt.ReplaceExisting && fromOutbox {
		return Result{}, errors.New("replacement requires an explicitly selected batch file")
	}
	batch, err := loadBatch(batchFile, opt.BatchID)
	if err != nil {
		return Result{}, err
	}
	batch.ReplaceExisting = opt.ReplaceExisting
	// Data-epoch fence, before the privacy gate, the oversize split and
	// every attempt write: a batch whose durable payload epoch does not
	// match the locally locked device epoch is pre-reset (or
	// post-transition) data that must never leave the device, and it
	// must not even be split — the split children inherit the same
	// stale stamp and would just queue more refusals. The batch stays
	// pending untouched.
	if err := checkBatchDataEpoch(batch, st.DataEpoch); err != nil {
		return Result{}, err
	}
	// Privacy gate before any state change or HTTP traffic: a batch with
	// extra fields or malformed model identifiers must never leave the device, so
	// the upload cannot rely on the server rejecting it. The check sits
	// before MarkAttempt and the preflight journal so a rejection leaves
	// the outbox entry, attempt accounting, and batch file untouched.
	if err := requireUploadPrivacy(batch); err != nil {
		return Result{}, err
	}
	// Fail closed if any individual record exceeds MaxBatchPayloadBytes.
	for idx, raw := range batch.Records {
		compact, err := compactRawRecord(raw)
		if err != nil {
			return Result{}, fmt.Errorf("record %d invalid json: %w", idx, err)
		}
		if len(compact) > MaxBatchPayloadBytes {
			return Result{}, fmt.Errorf("record %d exceeds maximum allowed size (%d bytes > %d bytes); failing closed", idx, len(compact), MaxBatchPayloadBytes)
		}
	}

	// Oversized pending recovery: partition into <= 500 records and compact envelope <= 768 KiB.
	// Same Run uploads the first child batch.
	if isOversizedBatch(batch) {
		if !fromOutbox || strings.TrimSpace(opt.StateDir) == "" {
			return Result{}, fmt.Errorf("batch %s exceeds size limits (%d records); cannot upload oversized batch without state directory outbox", batch.BatchID, len(batch.Records))
		}
		journal, err := reorganizeOversizedBatch(strings.TrimSpace(opt.StateDir), outboxEntry, batch)
		if err != nil {
			return Result{}, fmt.Errorf("reorganize oversized batch %s: %w", batch.BatchID, err)
		}
		if len(journal.NewBatches) == 0 {
			return Result{}, fmt.Errorf("oversize split of batch %s produced no child batches", batch.BatchID)
		}
		firstChild := journal.NewBatches[0]
		opt.BatchID = firstChild.BatchID
		batchFile = batchFilePath(strings.TrimSpace(opt.StateDir), firstChild.BatchID)
		batch, err = loadBatch(batchFile, opt.BatchID)
		if err != nil {
			return Result{}, fmt.Errorf("load split child batch %s: %w", firstChild.BatchID, err)
		}
		outboxEntry = outbox.BatchEntry{
			BatchID:               firstChild.BatchID,
			File:                  batchFile,
			Source:                firstChild.Source,
			Input:                 firstChild.Input,
			Status:                outbox.StatusPending,
			RecordCount:           len(firstChild.Records),
			OriginConsentRevision: journal.ConsentRevision,
		}
	}
	// ---- The send loop -------------------------------------------------
	//
	// Everything above fixed WHAT is sent: the outbox selection and the
	// oversize split happen before any POST, and the first attempt below
	// runs the scope gate before its POST, so the batch ID is stable for
	// the rest of the run. runSendAttempt is one fully authorized send of
	// that fixed batch. With no retry policy (nil Options.Retry, the
	// historical behavior) exactly one attempt runs and every failure is
	// returned untouched. With a policy, only transport failures of the
	// POST itself, HTTP 429, the explicitly retryable 5xx statuses, and
	// success responses whose body was lost or truncated are retried;
	// authorization (401/403), paused, scope, receipt-validation, and
	// conflict failures stay final, and an acknowledged send is never
	// repeated.
	stateDir := strings.TrimSpace(opt.StateDir)
	var payload []byte
	var recovered int
	runSendAttempt := func(ctx context.Context, attemptNo int, tr *attemptProgress) (Result, error) {
		if attemptNo > 1 {
			// Retry invariant, part one: the privacy gate is re-run over
			// the same immutable batch bytes before anything else may
			// happen. The payload below is frozen after the first
			// attempt's scope gate, so this can only fail closed.
			if err := requireUploadPrivacy(batch); err != nil {
				return Result{}, err
			}
		}
		if fromOutbox {
			// MarkAttempt stays batch-bound: only a known pending outbox entry
			// can be marked, never an arbitrary --file batch. It runs before
			// every attempt — retries included — so durable attempt accounting
			// always precedes an ingest POST.
			if err := ledger.MarkAttempt(batch.BatchID, time.Now().UTC()); err != nil {
				return Result{}, err
			}
		}
		if stateDir != "" {
			// Durable authorization-attempt accounting for the self GET too:
			// every GET — including the explicit --file path with a state
			// directory — is preceded by a persisted attempt record, mirroring
			// the guarantee MarkAttempt gives the ingest POST. If this write
			// fails, zero HTTP traffic of any kind happens. Only the fully
			// stateless mode (no state directory) is exempt: there is nothing
			// to journal into.
			if _, err := ledger.RecordPreflightAttempt(time.Now().UTC()); err != nil {
				if fromOutbox {
					return Result{}, fmt.Errorf("%w; cannot persist preflight attempt accounting before the authorization check; the batch stays pending and no HTTP request was made: %w", ErrPreflightAccounting, err)
				}
				return Result{}, fmt.Errorf("%w; cannot persist preflight attempt accounting before the authorization check; the batch file was not uploaded and no HTTP request was made: %w", ErrPreflightAccounting, err)
			}
		} else if opt.PreflightAccounting != nil {
			// Preflight-only accounting for the StateDir-less runs (the
			// history retransmission): the caller-supplied hook carries the
			// same durable-record-before-every-self-GET guarantee without a
			// StateDir ever being set — the outbox stays untouched and synced
			// batches stay terminal. A hook failure is a plain error (final,
			// never retried) and performs zero HTTP traffic of any kind.
			if err := opt.PreflightAccounting(time.Now().UTC()); err != nil {
				if fromOutbox {
					return Result{}, fmt.Errorf("%w; cannot persist preflight attempt accounting before the authorization check; the batch stays pending and no HTTP request was made: %w", ErrPreflightAccounting, err)
				}
				return Result{}, fmt.Errorf("%w; cannot persist preflight attempt accounting before the authorization check; the batch file was not uploaded and no HTTP request was made: %w", ErrPreflightAccounting, err)
			}
		}
		// Preflight: refresh the live device authorization snapshot before
		// any upload — once per attempt, so a retry can never lean on a
		// stale authorization. The MarkAttempt journal above is already
		// durable at this point, so the existing guarantee holds: a failure
		// before or during this check still performs zero ingest POSTs while
		// attempt accounting survives. A revoked or deleted device stops
		// here, before the POST; a 401/403 on a retry's preflight stops the
		// retry loop the same way.
		tr.markSelfStart()
		selfStatus, err := preflightSelf(ctx, client, serverURL, st)
		tr.markSelfDone()
		if err != nil {
			return Result{}, err
		}
		// A server that speaks the grant protocol and reports the device
		// paused stops all sending here: the batch stays pending (never
		// quarantined — pause is temporary) and no ingest POST happens. The
		// server's record-level scope enforcement remains the final defense
		// for everything uploaded before the pause.
		if err := checkNotPaused(selfStatus); err != nil {
			return Result{Self: selfStatus}, err
		}
		// Data-epoch fence on the fresh preflight, every attempt: the
		// server's epoch for this device must still match the locally
		// locked epoch (a nil snapshot epoch counts as 0, the legacy
		// steady state). This is the "stale local" stop: after a
		// server-side usage reset the local epoch deliberately never
		// auto-advances, so every ordinary upload stops until the
		// force-recollect flow completes. It is final — never retried,
		// never reorganized — and unaffected by AllowedResetRequestID:
		// even the recollect driver must upload under the epoch its
		// journal transition installed.
		if err := CheckSelfDataEpoch(selfStatus, st.DataEpoch); err != nil {
			return Result{Self: selfStatus}, err
		}
		if attemptNo == 1 {
			// Local scope gate BEFORE any POST: narrowed-away data must never
			// leave the device for the server to reject. Every record is checked
			// against the fresh preflight scope (allowed tools and time range).
			// Out-of-scope records in an outbox batch are split off through the
			// durable WAL/quarantine path — quarantined locally, never submitted —
			// while the in-scope remainder uploads normally; a --file batch with
			// out-of-scope records is refused outright with zero network traffic.
			//
			// Race boundary (deliberately not over-promised): a consent change the
			// user makes between this preflight GET and the ingest POST cannot be
			// recalled from the wire — bytes already sent are sent. What the gate
			// guarantees is that the server never PERSISTS such data: the POST
			// still carries X-Consent-Revision and the server validates it, so a
			// racing narrowing rejects the batch server-side exactly as before.
			// No absolute instantaneous revocation of in-flight requests is
			// claimed.
			if err := gateBatchAgainstScope(&batch, &outboxEntry, &opt, ledger, fromOutbox, selfStatus, stateDir); err != nil {
				return Result{Self: selfStatus}, err
			}
			// With the live scope in hand, recover any quarantined records that are
			// back inside it (requires a strictly newer consent revision). A
			// recovery failure fails closed: the batch stays pending and no POST
			// happens, because proceeding with an unrecoverable quarantine state
			// could silently strand records. Recovery runs on the first attempt
			// only: a retry resends the fixed batch and never re-batches.
			recovered, err = recoverQuarantinedWithScope(stateDir, selfStatus)
			if err != nil {
				return Result{}, err
			}
			batch.ReplaceExisting = opt.ReplaceExisting
			// The wire bytes are frozen once, after the first attempt's scope
			// gate: every retry resends exactly these bytes under the same
			// batch ID, which is what makes a resend after a lost response
			// idempotent server-side.
			payload, err = json.Marshal(batch)
			if err != nil {
				return Result{}, err
			}
			tr.noteFrozenPayload(len(payload))
		} else {
			// Retry invariant, part two: the fresh authorization snapshot
			// is re-checked against the SAME batch, with the identical
			// liveScopeFromSelf/evaluateRecord semantics the full gate
			// above uses. A retry must keep the same batch ID and the same
			// immutable bytes, so this check is deliberately pure — it
			// never splits, quarantines, or re-batches. When the live
			// consent scope no longer covers every record the retry stops
			// for good and the batch stays pending, leaving the standard
			// scope reorganization to the next run.
			if err := recheckBatchScopeForRetry(batch, selfStatus); err != nil {
				return Result{Self: selfStatus}, err
			}
		}
		endpoint, err := joinURL(serverURL, "/v1/ingest/batches")
		if err != nil {
			return Result{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
		// The production control plane requires the consent revision the
		// snapshot was taken under; the batch body wire format is unchanged.
		// Each attempt echoes the revision of its own fresh preflight.
		req.Header.Set("X-Consent-Revision", strconv.FormatInt(selfStatus.ConsentRevision, 10))
		if opt.Budget != nil {
			if strings.TrimSpace(opt.BudgetQueue) == "" {
				return Result{}, errors.New("sync budget queue is required")
			}
			// One reservation per actual POST, retries included: a decline
			// is a plain error, which the retry policy treats as final, so
			// the reservation decision stays with the run's accounting.
			if err := opt.Budget.Reserve(ctx, opt.BudgetQueue); err != nil {
				return Result{Self: selfStatus}, err
			}
		}
		// The attempt enters the upload stage only here, at the handoff to
		// the HTTP client — after every local gate, accounting write, and
		// budget reservation has already succeeded.
		tr.markPostIssued()
		resp, err := client.Do(req)
		if err != nil {
			tr.markPostDone()
			// A run context that is canceled or past its own deadline is
			// final: no retry can start, so the policy never sees a
			// retryable marker. The run context's own state — not the
			// error chain — is the discriminator, because an
			// http.Client request timeout also matches
			// errors.Is(err, context.DeadlineExceeded) while the run
			// context is still live, and such a timeout IS retryable.
			// Classification runs on the raw error exactly as before;
			// only the surfaced text is sanitized (the raw transport
			// error can name endpoints or carry runtime detail).
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, errDeviceRedirect) {
				return Result{}, wrapTransportError("sync upload", err)
			}
			if opt.Retry == nil {
				return Result{}, wrapTransportError("sync upload", err)
			}
			// Still-live run context: the POST failed on the wire —
			// connection reset, DNS, or a client request timeout — which
			// is transient from the run's point of view.
			return Result{}, syncretry.Retryable(wrapTransportError("sync upload", err))
		}
		defer resp.Body.Close()
		var body ingestResponse
		decodeErr := json.NewDecoder(capResponseBody(resp.Body)).Decode(&body)
		tr.markPostDone()
		successStatus := resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		if decodeErr != nil {
			if errors.Is(decodeErr, errResponseBodyTooLarge) {
				// An over-cap body is an explicit, identified outcome (the
				// capped reader probed one byte past the limit and recorded
				// no content). It keeps the exact lost-body semantics: on a
				// success status the receipt never arrived intact, so an
				// idempotent resend is safe; on a retryable failure status
				// the server's Retry-After floor still rides along.
				sizeErr := fmt.Errorf("ingest response body exceeded the %d MiB safety limit (HTTP %d); the receipt was not read", maxResponseBodyBytes>>20, resp.StatusCode)
				if opt.Retry == nil {
					return Result{}, sizeErr
				}
				if successStatus {
					return Result{}, syncretry.Retryable(sizeErr)
				}
				if retryableIngestStatus(resp.StatusCode) {
					return Result{}, syncretry.RetryAfterHeader(sizeErr, resp.Header.Get("Retry-After"))
				}
				return Result{}, sizeErr
			}
			if opt.Retry == nil {
				// Original behavior: an undecodable body is the failure,
				// whatever the status said. Only an identity-derived,
				// content-free description of the decode failure surfaces.
				return Result{}, safeDecodeErrorOf(decodeErr)
			}
			if successStatus {
				// The server reported success but the receipt never arrived
				// intact. Resending the same batch ID with the same bytes is
				// idempotent server-side, and no local ACK can have happened
				// (no receipt was ever seen to validate), so this is
				// retryable with no risk of a double ACK.
				return Result{}, syncretry.Retryable(fmt.Errorf("ingest response body lost or truncated (HTTP %d): %w", resp.StatusCode, safeDecodeErrorOf(decodeErr)))
			}
			if retryableIngestStatus(resp.StatusCode) {
				return Result{}, syncretry.RetryAfterHeader(fmt.Errorf("sync failed: status %d; ingest response body was not decodable: %w", resp.StatusCode, safeDecodeErrorOf(decodeErr)), resp.Header.Get("Retry-After"))
			}
			return Result{}, safeDecodeErrorOf(decodeErr)
		}
		if !successStatus {
			code := ""
			if body.Error != nil {
				code = body.Error.Code
			}
			err := classifyIngestError(resp.StatusCode, code)
			// Scope rejections of an outbox batch trigger a persistent, crash-safe
			// reorganization under the live scope: kept records get a new batch
			// with a new deterministic ID, out-of-scope records are quarantined
			// recoverably, and the old batch becomes terminal — the outbox head
			// can never stay blocked on a stale scope. Batches passed via --file
			// (no outbox) keep the diagnosis-only behavior. Scope rejections are
			// never retried: the reorganization is the response, and it hands
			// the new batch ID to the NEXT run.
			if fromOutbox && stateDir != "" &&
				(errors.Is(err, ErrScopeChanged) || errors.Is(err, ErrOutsideScope)) {
				journal, reorgErr := reorganizeBatchAfterScopeError(ctx, client, serverURL, st, stateDir, outboxEntry, batch)
				if reorgErr != nil {
					return Result{}, fmt.Errorf("%w; automatic scope reorganization failed, the batch stays pending and no records were moved: %v", err, reorgErr)
				}
				return Result{}, fmt.Errorf("%w; %s", err, reorgSummary(journal))
			}
			if opt.Retry != nil && retryableIngestStatus(resp.StatusCode) && retryableIngestCode(code) &&
				!errors.Is(err, ErrDeviceRevoked) && !errors.Is(err, ErrSubjectDeleted) &&
				!errors.Is(err, ErrScopeChanged) && !errors.Is(err, ErrOutsideScope) {
				// 429 and the explicitly retryable 5xx statuses are
				// transient; the raw Retry-After header rides along so the
				// policy honors the server's floor and never resends
				// earlier than the server allows. Terminal authorization
				// codes win over a retryable-looking status.
				return Result{}, syncretry.RetryAfterHeader(err, resp.Header.Get("Retry-After"))
			}
			return Result{}, err
		}
		if body.Batch.BatchID == "" {
			return Result{}, errors.New("sync response missing batch receipt")
		}
		if body.Batch.BatchID != batch.BatchID {
			// The server's receipt batch ID is untrusted free text and is
			// never echoed; only the locally submitted ID is named.
			return Result{}, fmt.Errorf("sync response batch receipt does not match submitted batch %q; keeping batch pending", batch.BatchID)
		}
		// Reconcile the receipt against the submitted batch BEFORE any state
		// change: an inconsistent receipt (wrong counts or indexes that do not
		// match the submitted records) must leave the outbox pending, the
		// per-message progress untouched, and no ACK journal behind, rather than
		// guess which records succeeded. Receipt problems are validation
		// failures and are never retried.
		rejectedKeys, err := reconcileReceipt(body.Batch, batch)
		if err != nil {
			return Result{}, err
		}
		// Receiving-point hygiene: everything the validated receipt
		// carries onward — into device state, the outbox, per-message
		// progress, the returned Result, and ultimately human output —
		// is reduced to closed sets here. reconcileReceipt above has
		// already validated the counts and folded the rejection codes;
		// the status is DERIVED from the validated counts (the wire
		// string is untrusted and ignored downstream — see
		// deriveReceiptStatus), and the record errors carried in the
		// Result keep only the closed codes with the server's free-text
		// message dropped entirely. Legitimate receipts keep exactly the
		// status their counts imply, so the ACK flow and the receipt
		// persistence they rely on are unaffected.
		body.Batch.Status = deriveReceiptStatus(body.Batch.AcceptedRecords, body.Batch.RejectedRecords)
		body.Batch.RecordErrors = sanitizeReceiptRecordErrors(body.Batch.RecordErrors)
		// The receipt is only "known" to progress consumers once it fully
		// validated against the submitted batch.
		tr.setReceipt(body.Batch)
		st.ServerURL = strings.TrimRight(serverURL, "/")
		st.LastSyncBatchID = body.Batch.BatchID
		st.LastSyncStatus = body.Batch.Status
		st.LastSyncAcceptedRecords = body.Batch.AcceptedRecords
		st.LastSyncRejectedRecords = body.Batch.RejectedRecords
		st.LastSyncedAt = body.Batch.ReceivedAt
		if st.LastSyncedAt.IsZero() {
			st.LastSyncedAt = time.Now().UTC()
		}
		receipt := outbox.Receipt{
			BatchID:         body.Batch.BatchID,
			Status:          body.Batch.Status,
			AcceptedRecords: body.Batch.AcceptedRecords,
			RejectedRecords: body.Batch.RejectedRecords,
			ReceivedAt:      st.LastSyncedAt,
		}
		var cursorConfirm *progress.ConfirmOptions
		var messageConfirm *progress.MessageBatchConfirm
		if fromOutbox && strings.TrimSpace(outboxEntry.Source) != "" && strings.TrimSpace(outboxEntry.Input) != "" {
			cursorConfirm = &progress.ConfirmOptions{
				Source:      outboxEntry.Source,
				Input:       outboxEntry.Input,
				BatchID:     body.Batch.BatchID,
				RecordCount: outboxEntry.RecordCount,
				Status:      body.Batch.Status,
				ConfirmedAt: st.LastSyncedAt,
			}
			// Per-message partial ACK: accepted messages advance to their pending
			// to-state, rejected ones unfreeze but keep their baseline and never
			// auto-resend the same interval key. Rejected messages never block
			// accepted ones.
			messageConfirm = &progress.MessageBatchConfirm{
				BatchID:      body.Batch.BatchID,
				RejectedKeys: rejectedKeys,
			}
		}
		// The ACK runs at most once per Run: only the attempt whose receipt
		// fully validated reaches it, its failure is final (never retried),
		// and an attempt whose response was lost can not have ACKed — no
		// receipt was ever seen to validate.
		tr.markAckStart()
		ackErr := commitSyncACK(store, stateDir, syncACKJournal{
			State:          st,
			FromOutbox:     fromOutbox,
			Receipt:        receipt,
			CursorConfirm:  cursorConfirm,
			MessageConfirm: messageConfirm,
		})
		tr.markAckDone()
		if ackErr != nil {
			return Result{}, ackErr
		}
		return Result{State: st, Receipt: body.Batch, Status: resp.StatusCode, Self: selfStatus, Recovered: recovered, Quarantined: quarantineCount(stateDir)}, nil
	}

	// runAttempt wraps runSendAttempt with the optional per-attempt
	// progress event. With no Progress callback there is no
	// instrumentation at all: no tracker is created, attemptNow is never
	// read, and every mark inside runSendAttempt is a nil-receiver
	// no-op. With a callback, the tracker is created before the attempt,
	// the event fires exactly once — after the attempt closure returns
	// and before any later attempt can start — and prevAttemptEnd
	// (maintained only on this path) is captured AFTER the callback
	// returns, so a slow consumer cannot inflate the next attempt's
	// InterAttemptDelay: that measurement stays wrapper-return to
	// wrapper-invocation, covering the retry policy's wait and overhead
	// only.
	var prevAttemptEnd time.Time
	runAttempt := func(ctx context.Context, attemptNo int) (Result, error) {
		var tr *attemptProgress
		if opt.Progress != nil {
			tr = startAttemptProgress(attemptNo, prevAttemptEnd)
			// A retry always resends the payload a previous attempt froze
			// (every pre-marshal failure is final), so its size is already
			// known before the attempt does anything.
			if attemptNo > 1 && len(payload) > 0 {
				tr.noteFrozenPayload(len(payload))
			}
		}
		res, err := runSendAttempt(ctx, attemptNo, tr)
		if opt.Progress != nil {
			opt.Progress(tr.finish(err))
			prevAttemptEnd = attemptNow()
		}
		return res, err
	}

	if opt.Retry == nil {
		// No retry policy: the original single-attempt behavior — one
		// authorized send, every failure returned untouched.
		res, err := runAttempt(ctx, 1)
		if err != nil {
			return res, err
		}
		return res, nil
	}
	// Opt-in bounded retry. The policy owns waiting, Retry-After floors,
	// the run deadline, and the retry budget; the attempt above owns
	// authorization, immutability of the batch ID and bytes, attempt
	// accounting, budget reservation, and the single ACK.
	var outcome Result
	if err := opt.Retry.Do(ctx, func(ctx context.Context, attemptNo int) error {
		res, err := runAttempt(ctx, attemptNo)
		outcome = res
		return err
	}); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// FetchDeviceSelf fetches the device's live authorization snapshot via
// GET /v1/devices/self using the device's own credentials, WITHOUT the
// upload-preflight history adjustment: the returned HistoryFrom and
// AllowedTools are the raw server-effective grant scope, so grant-sync
// callers can honor server-side widenings. Revoked or unauthorized devices
// fail like the upload preflight. This never binds or re-binds.
func FetchDeviceSelf(ctx context.Context, store statedir.Store, opt Options) (SelfStatus, error) {
	st, err := store.Load()
	if err != nil {
		return SelfStatus{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return SelfStatus{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return fetchSelf(ctx, client, serverURL, st)
}

// fetchSelf performs the authenticated GET and applies the shared
// terminal-condition checks. The returned snapshot is raw (no local
// history adjustment).
//
// Redirect protection: the GET carries the device credential, so the
// request must never follow a redirect — a server (or an intermediary)
// answering 3xx could otherwise aim a second, credential-bearing request
// at an arbitrary URL. The client used here is a shallow CLONE of the
// caller's with redirects refused; the caller's Timeout and Transport are
// preserved as-is and the caller's client object is never modified. A
// redirect answer fails closed as an error, having performed exactly one
// request.
func fetchSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState) (SelfStatus, error) {
	return fetchSelfAttempt(ctx, client, serverURL, st, false)
}

// fetchSelfAttempt optionally classifies transient failures for metadata retries.
// Existing fetchSelf callers retain their single-attempt error contract.
func fetchSelfAttempt(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState, retryTransient bool) (SelfStatus, error) {
	endpoint, err := joinURL(serverURL, "/v1/devices/self")
	if err != nil {
		return SelfStatus{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SelfStatus{}, err
	}
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	resp, err := noRedirectClient(client).Do(req)
	if err != nil {
		// The raw transport text (endpoint, runtime detail) never reaches
		// a human message; the cause stays matchable through Unwrap.
		return SelfStatus{}, retryToolStatusTransport(ctx, retryTransient, "device self check failed", err)
	}
	defer resp.Body.Close()
	var body selfResponse
	if err := json.NewDecoder(capResponseBody(resp.Body)).Decode(&body); err != nil {
		if retryTransient && ctx.Err() == nil && retryableIngestStatus(resp.StatusCode) && !errors.Is(err, errResponseBodyTooLarge) {
			return SelfStatus{}, syncretry.RetryAfterHeader(fmt.Errorf("device self check response HTTP %d: %w", resp.StatusCode, safeDecodeErrorOf(err)), resp.Header.Get("Retry-After"))
		}
		if errors.Is(err, errResponseBodyTooLarge) {
			return SelfStatus{}, fmt.Errorf("%w: device self check response exceeded the %d MiB body limit (status %d)", ErrSelfProtocol, maxResponseBodyBytes>>20, resp.StatusCode)
		}
		return SelfStatus{}, fmt.Errorf("%w: device self check returned an undecodable body (status %d): %w", ErrSelfProtocol, resp.StatusCode, safeDecodeErrorOf(err))
	}
	if resp.StatusCode == http.StatusOK {
		if body.Device == nil {
			return SelfStatus{}, fmt.Errorf("%w: device self check response missing device status", ErrSelfProtocol)
		}
		// Credential-reflection guard, before any part of the snapshot is
		// applied or validated: a hostile server that echoes the device
		// secret it just received back into any downstream-propagating
		// string field (device ID, allowed tools, account source fields)
		// fails closed here, with a fixed message that never names the
		// reflected value and without touching any local state. This is a
		// pure local check after the single GET — no extra HTTP of any
		// kind, and the durable accounting that preceded the GET stands
		// unchanged.
		if selfSnapshotReflectsSecret(body.Device, st.DeviceSecret) {
			return SelfStatus{}, fmt.Errorf("%w: device self check response carried reflected credential material; failing closed without applying any part of the snapshot", ErrSelfProtocol)
		}
		if body.Device.Revoked || !body.Device.UploadAuthorized {
			return SelfStatus{}, fmt.Errorf("%w: server reports this device is no longer authorized to upload; sending stopped and the collector never re-binds automatically", ErrDeviceRevoked)
		}
		// The snapshot must describe THIS device: applying another device's
		// authorization (or a server that cannot name the authenticated
		// device) fails closed. The server's device identifier is
		// untrusted free text and is never echoed.
		if body.Device.DeviceID != st.DeviceID {
			return SelfStatus{}, fmt.Errorf("%w: device self check returned authorization for a different device; refusing to apply another device's authorization", ErrDeviceUnauthorized)
		}
		return *body.Device, nil
	}
	code := ""
	if body.Error != nil {
		code = body.Error.Code
	}
	switch code {
	case "device_revoked":
		return SelfStatus{}, fmt.Errorf("%w: the server revoked this device (HTTP %d); sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, resp.StatusCode)
	case "subject_deleted":
		return SelfStatus{}, fmt.Errorf("%w: the server deleted the subject (HTTP %d); sending stopped and the collector never re-binds automatically", ErrSubjectDeleted, resp.StatusCode)
	}
	// Authentication failures are terminal for reading, never a transient
	// network condition.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return SelfStatus{}, fmt.Errorf("%w: device self check rejected the device credentials (HTTP %d)", ErrDeviceUnauthorized, resp.StatusCode)
	}
	if retryTransient && ctx.Err() == nil && retryableIngestStatus(resp.StatusCode) && retryableIngestCode(code) {
		return SelfStatus{}, syncretry.RetryAfterHeader(fmt.Errorf("device self check failed: status %d", resp.StatusCode), resp.Header.Get("Retry-After"))
	}
	if code != "" {
		// Unknown server codes are never echoed — not even the code
		// string itself, which is untrusted free text.
		return SelfStatus{}, fmt.Errorf("device self check failed: status %d (server error code: other)", resp.StatusCode)
	}
	return SelfStatus{}, fmt.Errorf("device self check failed: status %d", resp.StatusCode)
}

// noRedirectClient returns a shallow copy of client that never follows
// redirects. The caller's client is not modified; its Timeout and
// Transport are preserved exactly, and a nil client becomes the default
// redirect-refusing client (matching the 15-second send-path default). A
// 3xx answer surfaces as an error from Do with the redirect response
// body closed, so no credential-bearing second request is ever made.
var errDeviceRedirect = errors.New("syncclient: redirects are not allowed on device endpoints")

func noRedirectClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	} else {
		cloned.Timeout = 15 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errDeviceRedirect
	}
	return &cloned
}

// preflightSelf refreshes the device's live authorization snapshot via
// GET /v1/devices/self before any upload. It returns the snapshot whose
// ConsentRevision must be echoed on the ingest POST. Terminal conditions
// (device revoked, subject deleted) return wrapped ErrDeviceRevoked /
// ErrSubjectDeleted so callers stop sending; the collector never re-binds
// automatically. Any other failure is a plain error: the batch stays
// pending and the next sync run retries after a fresh preflight.
// gateBatchAgainstScope enforces the fresh consent scope locally before
// any ingest POST. It mutates batch/outboxEntry to the in-scope child when
// a split happened, so the caller uploads exactly the scoped-down batch.
func gateBatchAgainstScope(batch *BatchRequest, entry *outbox.BatchEntry, opt *Options, ledger outbox.Store, fromOutbox bool, self SelfStatus, stateDir string) error {
	scope, err := liveScopeFromSelf(self)
	if err != nil {
		return err
	}
	outOfScope := 0
	for _, raw := range batch.Records {
		inScope, _, err := scope.evaluateRecord(raw)
		if err != nil {
			return fmt.Errorf("batch %s stays pending and was not uploaded: %w", batch.BatchID, err)
		}
		if !inScope {
			outOfScope++
		}
	}
	if outOfScope == 0 {
		return nil
	}
	if !fromOutbox || stateDir == "" {
		return fmt.Errorf("batch %s contains %d of %d record(s) outside the current consent scope; refusing to upload a --file batch without sending anything (drain the outbox instead, which quarantines out-of-scope records locally)",
			batch.BatchID, outOfScope, len(batch.Records))
	}
	journal, err := splitBatchUnderScope(stateDir, *entry, *batch, scope, "pre-post-scope")
	if err != nil {
		return err
	}
	if len(journal.NewBatches) == 0 {
		// Everything was out of scope: the old batch is terminal and its
		// records are quarantined locally; nothing is uploaded.
		return fmt.Errorf("%w; batch %s fully quarantined locally under revision %d without any upload", ErrOutsideScope, batch.BatchID, scope.revision)
	}
	child := journal.NewBatches[0]
	childFile := batchFilePath(stateDir, child.BatchID)
	childBatch, err := loadBatch(childFile, child.BatchID)
	if err != nil {
		return fmt.Errorf("load scoped child batch %s: %w", child.BatchID, err)
	}
	childEntry := outbox.BatchEntry{
		BatchID:               child.BatchID,
		File:                  childFile,
		Source:                child.Source,
		Input:                 child.Input,
		Status:                outbox.StatusPending,
		RecordCount:           len(child.Records),
		OriginConsentRevision: journal.ConsentRevision,
	}
	if err := ledger.MarkAttempt(child.BatchID, time.Now().UTC()); err != nil {
		return err
	}
	*batch = childBatch
	*entry = childEntry
	if strings.TrimSpace(opt.BatchID) != "" {
		opt.BatchID = child.BatchID
	}
	return nil
}

// recheckBatchScopeForRetry re-verifies a still-pending batch against a
// fresh preflight snapshot before a retry may resend it. It applies the
// identical liveScopeFromSelf/evaluateRecord semantics the full
// gateBatchAgainstScope uses, but is deliberately PURE: a retry must keep
// the same batch ID and the same immutable bytes, so this check never
// splits, quarantines, or re-batches. When the live consent scope no
// longer covers every record — or the snapshot cannot establish a scope
// at all — the returned error is plain (never retry-marked): the retry
// stops for good, nothing is resent, and the batch stays pending so the
// next run performs the standard scope reorganization under whatever the
// server then reports.
func recheckBatchScopeForRetry(batch BatchRequest, self SelfStatus) error {
	scope, err := liveScopeFromSelf(self)
	if err != nil {
		return fmt.Errorf("batch %s stays pending and was not resent: %w", batch.BatchID, err)
	}
	outOfScope := 0
	for idx, raw := range batch.Records {
		inScope, _, evalErr := scope.evaluateRecord(raw)
		if evalErr != nil {
			return fmt.Errorf("batch %s stays pending and was not resent: record %d: %w", batch.BatchID, idx, evalErr)
		}
		if !inScope {
			outOfScope++
		}
	}
	if outOfScope > 0 {
		return fmt.Errorf("batch %s stays pending and was not resent: %d of %d record(s) now fall outside the consent scope reported at revision %d; the retry stopped without resending so the next sync run can reorganize the batch under the live scope",
			batch.BatchID, outOfScope, len(batch.Records), scope.revision)
	}
	return nil
}

// checkNotPaused reports ErrDevicePaused when the fetched snapshot speaks
// the grant protocol and the device is paused (explicit flag or the
// allowedTools sentinel). Old-protocol snapshots never pause.
func checkNotPaused(self SelfStatus) error {
	if self.GrantProtocolVersion == nil {
		return nil
	}
	paused := self.Paused
	for _, tool := range self.AllowedTools {
		if strings.TrimSpace(tool) == pausedToolSentinel {
			paused = true
		}
	}
	if paused {
		return fmt.Errorf("%w: server reports collection paused for this device; pending batches stay queued and nothing is sent", ErrDevicePaused)
	}
	return nil
}

// pausedToolSentinel is the marker the server places in allowedTools when
// the device is paused.
const pausedToolSentinel = "__toktrail_paused__"

func preflightSelf(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState) (SelfStatus, error) {
	return preflightSelfAttempt(ctx, client, serverURL, st, false)
}

func preflightSelfAttempt(ctx context.Context, client *http.Client, serverURL string, st statedir.DeviceState, retryTransient bool) (SelfStatus, error) {
	dev, err := fetchSelfAttempt(ctx, client, serverURL, st, retryTransient)
	if err != nil {
		return SelfStatus{}, err
	}
	// Under the grant protocol the server-confirmed effective cutoff is
	// authoritative and may legitimately widen beyond the bind-time cutoff,
	// so it is used as-is. Only old-protocol servers keep the legacy
	// never-widen behavior (max with the bind-time cutoff).
	if dev.GrantProtocolVersion == nil {
		if st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
			if dev.HistoryFrom == nil || dev.HistoryFrom.Before(*st.HistoryFrom) {
				hf := *st.HistoryFrom
				dev.HistoryFrom = &hf
			}
		}
	}
	return dev, nil
}

// classifyIngestError maps a non-2xx ingest response onto a typed error.
// Terminal codes (device_revoked, subject_deleted) stop sending entirely;
// scope codes (scope_changed, outside_scope) are handled by the caller with
// a persistent reorganization when the batch came from the outbox, so the
// messages here describe that follow-up rather than demanding manual
// re-export.
//
// Human-message hygiene: only the closed set of known codes above maps to
// a sentinel with a FIXED description; every other non-empty code — and
// any server free-text message, known code or not — is reduced to the
// fixed "(server error code: other)" wording. The raw code still drives
// classification (retryability, reorganization triggers) inside the
// caller; it is just never echoed to humans. The message parameter is
// deliberately gone: nothing an untrusted endpoint writes in it can be
// safely printed.
func classifyIngestError(status int, code string) error {
	switch code {
	case "device_revoked":
		return fmt.Errorf("%w: the server revoked this device (HTTP %d); sending stopped and the collector never re-binds automatically", ErrDeviceRevoked, status)
	case "subject_deleted":
		return fmt.Errorf("%w: the server deleted the subject (HTTP %d); sending stopped and the collector never re-binds automatically", ErrSubjectDeleted, status)
	case "scope_changed":
		return fmt.Errorf("%w: the server reported the consent scope changed (HTTP %d); the batch is reorganized under the live consent scope when it came from the outbox", ErrScopeChanged, status)
	case "outside_scope":
		return fmt.Errorf("%w: the server reported records outside the consent scope (HTTP %d); out-of-scope records are quarantined recoverably when the batch came from the outbox", ErrOutsideScope, status)
	case "device_epoch_stale":
		// A server-side epoch fence: the batch's durable dataEpoch does
		// not match the server's current epoch for this device. Like the
		// local fence, it is final and never reorganized — relabeling
		// old-epoch data is exactly what the fence exists to prevent.
		return fmt.Errorf("%w: the server rejected the batch because its data epoch does not match the device's current epoch (HTTP %d); the batch stays pending and the device needs a force-recollect if a usage reset happened", ErrEpochStale, status)
	}
	if code != "" {
		return fmt.Errorf("sync failed: status %d (server error code: other)", status)
	}
	return fmt.Errorf("sync failed: status %d", status)
}

// retryableIngestStatus reports whether a failed ingest response's HTTP
// status makes the send eligible for a policy retry. The list is an
// explicit allowlist, deliberately narrow: 429 (throttling, with the
// Retry-After header honored as a floor) and 500/502/503/504 (internal
// error and the gateway/proxy trio, all conventionally transient).
// Everything else is final: 401/403 authorization failures, 409
// conflicts, other 4xx validation rejections, and even 5xx statuses that
// are not conventionally transient (501 Not Implemented, 505 version
// mismatches, …) — retrying those cannot help and only spends budget.
func retryableIngestStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableIngestCode fails closed on unknown business errors even when an
// intermediary reports a retryable HTTP status.
func retryableIngestCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "", "internal_error", "service_unavailable", "rate_limited", "too_many_requests":
		return true
	default:
		return false
	}
}

// batchRecordKey extracts the recordKey of one raw submitted record.
func batchRecordKey(raw json.RawMessage) (string, error) {
	var probe struct {
		RecordKey string `json:"recordKey"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", fmt.Errorf("submitted record is not valid JSON: %w", err)
	}
	return probe.RecordKey, nil
}

// reconcileReceipt checks the server receipt against the submitted batch:
//   - accepted + rejected must equal the submitted record count;
//   - both counts must be non-negative (a hostile "-1 accepted + 2
//     rejected" must not pass the sum check and poison the counts);
//   - len(recordErrors) must equal the rejected count;
//   - every error index must address a submitted record, and a non-empty
//     recordKey must match the record at that index;
//   - every rejection index must be unique (duplicate indexes would merge
//     in the per-message map and leave a rejected record confirmed as
//     accepted).
//
// On success it returns the rejected record keys with their error codes
// for per-message confirmation. On inconsistency it returns an error and
// the caller must not change any state.
//
// Human-message hygiene: the receipt's batch ID and record keys are
// untrusted server text and never appear in the returned errors —
// messages name only the locally submitted batch — and the server's
// recordKey value is compared but not echoed. The trust boundary folds
// the rejection codes onto the closed known list here, so nothing
// downstream (per-message progress, cursor hints, human output) can
// carry an unknown code; the server's free-text message is never
// returned or persisted at all.
func reconcileReceipt(receipt BatchReceipt, batch BatchRequest) (map[string]string, error) {
	if receipt.AcceptedRecords < 0 || receipt.RejectedRecords < 0 {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: negative decision counts (%d accepted, %d rejected); keeping batch pending",
			batch.BatchID, receipt.AcceptedRecords, receipt.RejectedRecords)
	}
	if receipt.AcceptedRecords+receipt.RejectedRecords != len(batch.Records) {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: %d accepted + %d rejected != %d submitted records; keeping batch pending",
			batch.BatchID, receipt.AcceptedRecords, receipt.RejectedRecords, len(batch.Records))
	}
	// A KNOWN status word that contradicts the counts is an inconsistent
	// receipt and fails closed here; empty and unknown words stay
	// compatible and the persisted status is derived from the validated
	// counts instead (see receiptStatusContradictsCounts for the
	// evidence and the safety argument). The wire word itself is never
	// echoed into the error.
	if receiptStatusContradictsCounts(receipt.Status, receipt.AcceptedRecords, receipt.RejectedRecords) {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: the reported status contradicts the decision counts (%d accepted, %d rejected); keeping batch pending",
			batch.BatchID, receipt.AcceptedRecords, receipt.RejectedRecords)
	}
	if len(receipt.RecordErrors) != receipt.RejectedRecords {
		return nil, fmt.Errorf("receipt inconsistent with batch %s: %d record errors != %d rejected records; keeping batch pending",
			batch.BatchID, len(receipt.RecordErrors), receipt.RejectedRecords)
	}
	keys := make([]string, len(batch.Records))
	for idx, raw := range batch.Records {
		key, err := batchRecordKey(raw)
		if err != nil {
			return nil, fmt.Errorf("batch %s record %d: %w", batch.BatchID, idx, err)
		}
		if key == "" {
			return nil, fmt.Errorf("batch %s record %d has no recordKey", batch.BatchID, idx)
		}
		keys[idx] = key
	}
	seenIndexes := make(map[int]bool, len(receipt.RecordErrors))
	rejectedKeys := make(map[string]string, len(receipt.RecordErrors))
	for _, recordErr := range receipt.RecordErrors {
		if recordErr.Index < 0 || recordErr.Index >= len(keys) {
			return nil, fmt.Errorf("receipt inconsistent with batch %s: record error index %d out of range for %d submitted records; keeping batch pending",
				batch.BatchID, recordErr.Index, len(keys))
		}
		if seenIndexes[recordErr.Index] {
			return nil, fmt.Errorf("receipt inconsistent with batch %s: record error index %d appears more than once; keeping batch pending",
				batch.BatchID, recordErr.Index)
		}
		seenIndexes[recordErr.Index] = true
		key := recordErr.RecordKey
		if key == "" {
			key = keys[recordErr.Index]
		} else if key != keys[recordErr.Index] {
			return nil, fmt.Errorf("receipt inconsistent with batch %s: record error index %d references a recordKey that does not match the record submitted at that index; keeping batch pending",
				batch.BatchID, recordErr.Index)
		}
		rejectedKeys[key] = sanitizeRecordErrorCode(recordErr.Code)
	}
	return rejectedKeys, nil
}

const syncACKJournalFileName = "sync-ack-transaction.json"

type syncACKJournal struct {
	State          statedir.DeviceState          `json:"state"`
	FromOutbox     bool                          `json:"fromOutbox"`
	Receipt        outbox.Receipt                `json:"receipt"`
	CursorConfirm  *progress.ConfirmOptions      `json:"cursorConfirm,omitempty"`
	MessageConfirm *progress.MessageBatchConfirm `json:"messageConfirm,omitempty"`
}

func syncACKJournalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), syncACKJournalFileName)
}

func recoverPendingSyncACK(store statedir.Store, stateDir string) error {
	path := syncACKJournalPath(stateDir)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal syncACKJournal
	if err := json.Unmarshal(b, &journal); err != nil {
		return err
	}
	if err := applySyncACK(store, strings.TrimSpace(stateDir), journal); err != nil {
		return err
	}
	return os.Remove(path)
}

func commitSyncACK(store statedir.Store, stateDir string, journal syncACKJournal) error {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return applySyncACK(store, stateDir, journal)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	path := syncACKJournalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := applySyncACK(store, stateDir, journal); err != nil {
		return err
	}
	return os.Remove(path)
}

func applySyncACK(store statedir.Store, stateDir string, journal syncACKJournal) error {
	if err := store.Save(journal.State); err != nil {
		return err
	}
	if journal.FromOutbox {
		if err := outbox.New(stateDir).MarkSynced(journal.Receipt); err != nil {
			return err
		}
	}
	if journal.CursorConfirm != nil {
		if _, err := progress.New(stateDir).Confirm(*journal.CursorConfirm); err != nil {
			return err
		}
	}
	// Per-message progress only exists under a state directory.
	if journal.MessageConfirm != nil && strings.TrimSpace(stateDir) != "" {
		if _, err := progress.New(stateDir).ConfirmMessageBatch(*journal.MessageConfirm); err != nil {
			return err
		}
	}
	return nil
}

func loadBatch(path string, overrideBatchID string) (BatchRequest, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return BatchRequest{}, errors.New("missing batch file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return BatchRequest{}, err
	}
	var batch BatchRequest
	if err := json.Unmarshal(b, &batch); err != nil {
		return BatchRequest{}, err
	}
	if strings.TrimSpace(overrideBatchID) != "" {
		batch.BatchID = strings.TrimSpace(overrideBatchID)
	}
	batch.BatchID = strings.TrimSpace(batch.BatchID)
	if batch.BatchID == "" {
		return BatchRequest{}, errors.New("batch file missing batchId; pass --batch or include batchId")
	}
	if len(batch.Records) == 0 {
		return BatchRequest{}, errors.New("batch file must contain at least one record")
	}
	return batch, nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid server URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
