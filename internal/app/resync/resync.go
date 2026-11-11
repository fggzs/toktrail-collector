// Package resync implements `toktrail resync --all`: the explicit,
// deliberate retransmission of already-synced device-outbox history to the
// currently bound server, typically after the server lost its database
// while the local outbox still records the batches as synced.
//
// Guarantees:
//   - The original outbox entries stay terminal and immutable: synced
//     batches are never re-marked pending, never re-attempted through the
//     outbox, and their files are never modified. Per-message progress,
//     cursors, the quarantine store, and the export WAL are untouched, and
//     no progress is deleted or rescanned. No Claude baselines are
//     recomputed and no record keys are rewritten.
//   - No new device is bound and no authorization is bypassed: there is no
//     force flag. Every run re-checks the live device authorization via the
//     existing syncclient preflight, and every upload goes through the
//     existing syncclient privacy gate, scope gate, and receipt
//     reconciliation.
//   - Coverage is the device ledger only (internal/local/outbox). Other
//     stores — independent account-source ledgers such as the cursor
//     account history, or recoverable quarantine records — are not part of
//     resync, and output says so explicitly instead of claiming a full
//     restore.
//   - An optional caller snapshot can restrict a NEW job to the synced
//     batches that existed when the snapshot was captured (connect does
//     this, under its setup state lock, so its automatic retransmission
//     never immediately replays the batches the same run's collection
//     uploads). The restriction is durable: the job's journal freezes the
//     ORIGINAL snapshot id universe — including entries the local grants
//     excluded at plan time, so a widened authorization can recover them
//     — and both resume and every consent-scope re-plan preserve that
//     boundary, never widening it to batches synced after the capture. A
//     nil snapshot (the explicit resync pass, and legacy journals without
//     the field) keeps the original full-archive semantics, and a
//     non-nil snapshot with zero batch ids records a first install
//     (nothing was synced yet), which is distinct from nil.
//   - Local authorization is strict: only batches whose (source, input)
//     currently matches an enabled local source grant are retransmitted. A
//     missing grant config denies by default, so residual archives cannot
//     bypass a withdrawn local permission.
//   - Consent-scope changes never turn stale progress into completion: an
//     incomplete job records the live consent scope its done/skip
//     decisions were made under, and every run re-verifies that baseline
//     against a fresh live snapshot after the preflight. When the
//     authorization revision or scope content changed — narrowed or
//     widened — the old decisions are not treated as completing the
//     current scope: the job is re-planned under the fresh scope, within
//     its frozen snapshot universe when it has one and over the complete
//     synced history otherwise, and saved as the new journal; the run
//     stops before any upload, and the next explicit pass executes the
//     re-planned plan
//     (already-delivered records replay without double counting). A
//     finalize-only run (crash after the last upload, before the
//     completion write) may only complete after the same verification.
//     The same rule holds while a pass is running: every upload's
//     receipt is checked against the authorization snapshot it was
//     actually accepted under, and the completion write is preceded by
//     one final fresh scope comparison — a mid-run change (even a
//     widening that lets every upload succeed) stops the pass incomplete
//     instead of completing on stale decisions. Records withheld as
//     outside the live scope are a normal exclusion, never a failure or
//     a gap of the pass.
//   - Idempotent and resumable: an interrupted job resumes from the
//     resync-owned journal (payload hashes detect tampering), deterministic
//     child batch identities keep partial-scope retransmissions stable, and
//     the server's replay receipts keep repeated uploads from double
//     counting. A completed job is replaced by the next explicit full pass.
//   - An optional shared POST budget (Options.Budget) can cap the concrete
//     ingest POST attempts one pass makes: every history retransmission
//     target reserves exactly one attempt, under the "history" queue,
//     immediately before its POST and only after the authorization,
//     privacy, and scope gates. A decline stops the pass BEFORE that POST
//     — the declined target is not marked failed, the journal keeps the
//     job resumable, and the next run continues — while an externally
//     canceled context keeps its original upload-failure semantics. A nil
//     budget (the default, and the explicit resync CLI) leaves the pass
//     unbudgeted, exactly as before.
//   - Note: the outbox does not record which device originally synced a
//     batch, so idempotency is guaranteed for the CURRENT device identity
//     only; cross-device de-duplication on the server is not promised.
package resync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/overrides"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// SyncedBatchSnapshot freezes which synced outbox batches one automatic
// retransmission pass may cover. connect captures it under its setup
// state lock, BEFORE this run's collection syncs anything, so its
// automatic pass covers exactly the history that existed when the
// authorization gesture started and never immediately replays the
// batches the same run uploads.
//
// The nil/empty distinction is load-bearing:
//   - a nil Options.Snapshot keeps the original full-pass semantics (the
//     explicit `toktrail resync --all`, and every pre-snapshot caller);
//   - a non-nil snapshot with zero BatchIDs records a first install —
//     nothing was synced yet — so the restricted pass plans nothing and
//     completes as an empty pass.
//
// Batch ids the outbox no longer lists (or no longer marks synced) are
// simply absent from the plan: the snapshot is a filter, not a checklist.
type SyncedBatchSnapshot struct {
	// BatchIDs lists the outbox batch ids that were already synced when
	// the snapshot was captured. Order and duplicates are irrelevant.
	BatchIDs []string `json:"batchIds"`
}

// NewSyncedBatchSnapshot captures the given synced batch ids as a
// restriction snapshot. It ALWAYS returns a non-nil snapshot — including
// for an empty or nil id list, which means "nothing was synced yet" — so
// a caller can never accidentally collapse the empty set into the
// no-restriction nil. The ids are copied defensively and the slice is
// never nil, so the journal round-trip keeps the empty set distinct from
// an absent (unrestricted) field.
func NewSyncedBatchSnapshot(batchIDs []string) *SyncedBatchSnapshot {
	return &SyncedBatchSnapshot{BatchIDs: append(make([]string, 0, len(batchIDs)), batchIDs...)}
}

// cloneSnapshot returns a defensive copy of the universe with a non-nil
// BatchIDs slice; nil stays nil (unrestricted).
func cloneSnapshot(s *SyncedBatchSnapshot) *SyncedBatchSnapshot {
	if s == nil {
		return nil
	}
	return &SyncedBatchSnapshot{BatchIDs: append(make([]string, 0, len(s.BatchIDs)), s.BatchIDs...)}
}

// Options configures one resync run.
type Options struct {
	StateDir string
	// ServerURL defaults to the bound server (device.json), then to the
	// same local default the sync command uses.
	ServerURL string
	// MaxBatches is an optional per-run upload budget. Zero (the default)
	// walks the entire frozen job plan — a bounded list, never a scan. A
	// positive value stops after that many uploads and reports the
	// remainder for the next run. Negative values are rejected.
	MaxBatches int
	// Budget optionally caps the concrete ingest POST attempts this pass
	// may make through a budget shared with its caller: every history
	// retransmission target — verbatim parents, derived children, and the
	// override-ledger retransmission — reserves exactly one attempt,
	// under the "history" queue, immediately before its POST and only
	// after the authorization, privacy, and scope gates. When the shared
	// budget declines an attempt the pass stops BEFORE that POST: the
	// declined target is not marked failed, the journal keeps the job
	// resumable, and re-running the same command continues the pass. An
	// externally canceled context is not a decline and keeps the original
	// upload-failure semantics. nil (the default, and the explicit resync
	// CLI) leaves the pass unbudgeted and identical to before.
	Budget *syncbudget.Budget
	// Retry, when set, opts this pass's retransmission sends into the
	// bounded retry policy (internal/syncretry) — the AUTOMATIC history
	// pass (connect) wires it; the explicit `resync --all` CLI and the
	// override pass deliberately do not, keeping the historical
	// single-shot semantics. The policy wraps each target's send INSIDE
	// syncclient.Run (one retry loop per POST, never a loop around the
	// target list): every attempt resends the same batch ID with the same
	// immutable bytes, re-runs the fresh self preflight, and reserves the
	// shared Budget again before its real POST. The target keeps its
	// BatchFile selection and never gains a StateDir — synced outbox
	// entries stay terminal and untouched — while the per-attempt
	// authorization accounting rides syncclient's preflight-only hook
	// against this run's own ledger, so every self GET of every attempt
	// (retries included) stays durably accounted exactly once and a
	// failed accounting write stops the send with zero HTTP traffic.
	// Nil keeps the single-attempt behavior exactly as before.
	Retry      *syncretry.Policy
	HTTPClient *http.Client
	// DryRun plans offline: no network access, no state changes, no journal
	// write. The remote consent scope is NOT verified in a dry run.
	DryRun bool
	// Snapshot optionally restricts a NEW job to the outbox batches that
	// were already synced when the caller captured it (connect captures
	// one under its setup state lock, before any collection runs).
	//
	// nil keeps the original full-archive semantics — the explicit
	// `toktrail resync --all` pass and every pre-snapshot caller. A
	// non-nil snapshot restricts NEW jobs to exactly its listed batch
	// ids, and an empty BatchIDs list is meaningful (nothing was synced
	// yet: a first install plans an empty pass), which is why the
	// distinction from nil is load-bearing.
	//
	// The restriction is durable. The job's journal freezes the snapshot
	// id universe as captured — BEFORE grant filtering, so entries the
	// grants exclude at plan time stay in it — and a resume keeps the
	// frozen plan while a consent-scope change re-plans WITHIN that
	// universe: batches synced after the capture (most commonly the same
	// run's collection uploads) never join the job lineage, while
	// grant-excluded entries rejoin once a widened authorization allows
	// them. Jobs without a universe (nil, or legacy journals without the
	// field) plan and re-plan over the complete synced history, exactly
	// as before.
	Snapshot *SyncedBatchSnapshot
	// Confirm is invoked exactly once before any state change or network
	// traffic (execution only, after planning). Returning an error aborts
	// the run with zero uploads. Required for non-dry-run runs.
	Confirm func(Plan) error
	// Progress reports each batch outcome during execution (may be nil).
	Progress func(ProgressEvent)
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// PlannedBatch is one already-synced outbox batch selected for
// retransmission.
type PlannedBatch struct {
	BatchID       string
	File          string
	Source        string
	Input         string
	Records       int
	PayloadSHA256 string
	CreatedAt     time.Time
}

// Plan is the offline-plannable description of one run.
type Plan struct {
	DeviceID    string
	ServerURL   string
	StateDir    string
	JournalPath string
	JobID       string
	Resumed     bool
	// Batches are the still-to-retransmit parent batches, in order.
	Batches []PlannedBatch
	// PlannedRecords sums len(Batches[i].Records).
	PlannedRecords int
	// TotalInJob is the job's full plan size; DoneInJob counts batches the
	// resumed job already retransmitted successfully.
	TotalInJob int
	DoneInJob  int

	ExcludedReorganized int
	ExcludedPending     int
	// ExcludedAfterSnapshot counts synced batches the plan deliberately
	// did not include because they were synced after the restricting
	// snapshot was captured — most commonly the batches this very run's
	// collection uploaded, which an immediate replay would only
	// duplicate. Always zero for unrestricted passes.
	ExcludedAfterSnapshot int
	// SnapshotRestricted is true when this plan was restricted to a
	// caller-captured synced-batch snapshot (connect's automatic pass).
	// False is the explicit full pass. A resumed job reports what its
	// journal recorded, and a consent-scope re-plan preserves the job's
	// frozen universe, so the flag survives re-plans.
	SnapshotRestricted bool
	// ExcludedLocalGrant lists batch IDs withheld because their
	// (source, input) has no currently enabled local source grant.
	ExcludedLocalGrant []string
	// QuarantinedRecords counts the recoverable quarantine store
	// (informational; quarantine is not part of resync).
	QuarantinedRecords int
	// PendingFinalize is true when the only remaining work is persisting
	// the job (nothing to upload): the previous run crashed after its last
	// upload but before the completion write, or there are no synced
	// batches at all. A dry run reports it without writing anything.
	// Execution re-verifies the live consent scope before it may claim
	// completion (an empty pass finalizes offline; a crash-recovery
	// finalize goes through the preflight and the scope gate, and
	// re-plans instead of completing when the authorization changed).
	PendingFinalize bool
	CoverageNote    string
}

// ProgressEvent reports one parent batch's outcome during execution.
type ProgressEvent struct {
	BatchID       string
	UploadBatchID string
	Outcome       string // done | blocked | failed
	Records       int    // parent batch records
	Uploaded      int    // records retransmitted for this event
	Accepted      int    // records the server accepted
	Rejected      int    // records the server rejected (not restored)
	Replay        bool
	Skipped       int    // records held back outside the live scope
	Err           string // non-empty on failed
}

// Result reports what one run did.
type Result struct {
	Plan   Plan
	DryRun bool
	// Self is the live authorization snapshot the run planned against;
	// zero for a dry run, which never contacts the server.
	Self syncclient.SelfStatus

	Uploads         int // concrete uploads (verbatim batches + derived children)
	UploadedBatches int // parent batches fully retransmitted this run
	UploadedRecords int // records retransmitted this run (submitted)
	// AcceptedRecords / RejectedRecords split this run's submitted records
	// by the server verdict. A pass with rejections is terminal (the
	// server's rejection is deterministic; retrying it would loop), but it
	// must never be reported as a full restore.
	AcceptedRecords int
	RejectedRecords int
	ReplayReceipts  int
	// SkippedOutOfScopeRecords counts records withheld under the live
	// consent scope (record keys are listed in the journal). A pass with
	// this counter above zero did NOT restore those records.
	SkippedOutOfScopeRecords int
	Blocked                  int
	Failed                   int
	Remaining                int
	Completed                bool
	// Stopped is non-empty when the run ended before finishing the plan
	// (a budget stop — the per-run MaxBatches cap or a shared sync-budget
	// decline — upload failure, an authorization stop, or a consent-scope
	// change that re-planned the job).
	Stopped     string
	JournalPath string
}

// coverageNote is the fixed scope statement every plan and report carries.
const coverageNote = "resync covers the device outbox (this collector's already-synced batches) only; independent account-source ledgers (such as cursor account history) and recoverable quarantine records are not included, and completion is not a claim of restoring anything beyond that ledger"

// restrictedCoverageSuffix extends the coverage note for a pass whose
// plan a caller snapshot restricted, so its report never claims the
// complete synced archive.
const restrictedCoverageSuffix = "this pass was restricted to the batches already synced when the caller captured its snapshot, so batches synced afterwards (for example by the same run's collection) were excluded and are NOT retransmitted here — an explicit full pass covers the complete synced archive"

// coverageNoteFor renders the coverage note for one pass, restricted or
// not.
func coverageNoteFor(restricted bool) string {
	if restricted {
		return coverageNote + "; " + restrictedCoverageSuffix
	}
	return coverageNote
}

// budgetQueueHistory is the syncbudget queue name every retransmission
// POST of a resync pass reserves under, so a caller sharing one Budget
// across collection and history retransmission can cap them
// independently (collection reserves under "device").
const budgetQueueHistory = "history"

// budgetStopped is the Result.Stopped marker for a pass the shared POST
// budget declined: the declined target never POSTed, nothing was marked
// failed, and the journal keeps the job resumable for the next run.
const budgetStopped = "sync budget exhausted"

// budgetDecline reports whether err is a shared-budget decline that
// syncclient returned before an ingest POST — the run-wide total, this
// queue's own cap, or the budget's own deadline ran out, so nothing was
// submitted for the target. A canceled caller context is deliberately
// NOT a decline: it keeps the original upload-failure semantics instead
// of being reported as a budget stop.
func budgetDecline(err error) bool {
	return errors.Is(err, syncbudget.ErrTotalExhausted) ||
		errors.Is(err, syncbudget.ErrQueueExhausted) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded)
}

// Run performs one resync pass. The caller must hold the state directory
// process lock (the CLI does); Run itself never locks.
func Run(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("resync requires a state directory")
	}
	if err := syncclient.CheckResetJournal(stateDir); err != nil {
		return Result{}, err
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	if opt.MaxBatches < 0 {
		return Result{}, fmt.Errorf("max-batches must be 0 (whole frozen plan) or a positive upload budget")
	}

	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; resync retransmits to the currently bound device only and never binds one itself; run toktrail bind or connect first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	ledger := outbox.New(stateDir)
	out, err := ledger.Load()
	if err != nil {
		return Result{}, err
	}

	// Override-ledger gate: plain resync retransmits archived payloads,
	// so it must never run underneath an unfinished override (the
	// superseded values would collide with the very records the override
	// is repairing) nor apply another binding's acknowledgments. Pending
	// attempts block fail-closed; confirmed entries are folded into the
	// retransmission below (content substitution and the ledger-only
	// records).
	ovStore := overrides.New(stateDir)
	ovLedger, hasOverrides, err := ovStore.Load()
	if err != nil {
		return Result{}, err
	}
	confirmedOverrides := map[string]overrides.Entry{}
	if hasOverrides {
		if err := ovLedger.BindingError(stateDir); err != nil {
			return Result{}, err
		}
		if ovLedger.HasPending() {
			pending := 0
			for _, e := range ovLedger.Entries {
				if e.Status == overrides.StatusPending {
					pending++
				}
			}
			return Result{}, fmt.Errorf("an override pass is incomplete (%d record(s) pending acknowledgment); plain resync is blocked so it cannot retransmit superseded payloads underneath an unfinished override — re-run toktrail resync --all --replace-existing to finish it, or remove %s only if you accept abandoning the override", pending, ovStore.Path())
		}
		for key, entry := range ovLedger.Entries {
			if entry.Status == overrides.StatusConfirmed {
				confirmedOverrides[key] = entry
			}
		}
	}

	// An incomplete job is resumed; a completed job is replaced by this
	// fresh explicit pass (server replay keeps the full re-pass from double
	// counting). A corrupt journal fails closed.
	existing, hasJob, err := loadJob(stateDir)
	if err != nil {
		return Result{}, err
	}
	resumed := false
	if hasJob && existing.completed() {
		hasJob = false
	}
	if hasJob {
		if existing.DeviceID != st.DeviceID {
			return Result{}, fmt.Errorf("the incomplete resync job %s was planned for device %q, but this collector is bound as %q; resync targets the currently bound device only — remove %s only if you accept abandoning that job", existing.JobID, existing.DeviceID, st.DeviceID, journalPath(stateDir))
		}
		if existing.ServerURL != serverURL {
			return Result{}, fmt.Errorf("the incomplete resync job %s targets server %s, but this run targets %s; re-run against the recorded server, or remove %s to abandon the job", existing.JobID, existing.ServerURL, serverURL, journalPath(stateDir))
		}
		resumed = true
	}

	plan := Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    serverURL,
		StateDir:     stateDir,
		JournalPath:  journalPath(stateDir),
		Resumed:      resumed,
		CoverageNote: coverageNote,
	}
	plan.QuarantinedRecords = quarantineCount(stateDir)

	var jb job
	// finalizeOnly marks a run whose only remaining write is persisting the
	// job (an empty new pass, or a job whose last upload landed but whose
	// completion write crashed). A dry run — and a confirmation abort —
	// must leave the disk byte-identical, so the write happens only after
	// the execution path is confirmed. An empty pass finalizes fully
	// offline; a crash-recovery finalize performs no uploads but MUST
	// re-verify the live consent scope before it may claim completion, so
	// it flows through the preflight and the scope gate like any resume
	// (its all-done batch loop then converges with zero uploads).
	var finalizeOnly bool
	if resumed {
		jb = existing
		// A resumed job keeps the plan its journal froze — including the
		// snapshot universe recorded when it was planned. This run's own
		// Snapshot option is deliberately NOT applied to a resume: the
		// journal is the plan, and re-deriving it from a fresh snapshot
		// could silently drop batches the job still owes (or admit
		// batches synced after the job's boundary was captured).
		plan.SnapshotRestricted = jb.Snapshot != nil
		plan.CoverageNote = coverageNoteFor(jb.Snapshot != nil)
		remaining, done, err := resumePlan(stateDir, jb, out)
		if err != nil {
			return Result{}, err
		}
		if len(remaining) == 0 {
			// Crash after the last upload but before the completion write:
			// converge lazily, never inside a dry run.
			finalizeOnly = true
			plan.Batches = nil
			plan.TotalInJob = len(jb.Batches)
			plan.DoneInJob = len(jb.Batches)
			plan.JobID = jb.JobID
			fillExclusions(&plan, jb.Exclusions)
		} else {
			plan.Batches = remaining
			plan.TotalInJob = len(jb.Batches)
			plan.DoneInJob = done
			plan.JobID = jb.JobID
			fillExclusions(&plan, jb.Exclusions)
		}
	} else {
		jb, plan, err = buildNewJob(stateDir, st, serverURL, out, now, plan, opt.Snapshot)
		if err != nil {
			return Result{}, err
		}
		if len(jb.Batches) == 0 {
			// Nothing synced: the empty completed job is persisted only by
			// a confirmed execution run.
			at := now().UTC()
			jb.CompletedAt = &at
			finalizeOnly = true
		}
	}
	plan.PendingFinalize = finalizeOnly

	if opt.DryRun {
		return Result{Plan: plan, DryRun: true, JournalPath: plan.JournalPath}, nil
	}

	if opt.Confirm == nil {
		return Result{Plan: plan}, errors.New("resync execution requires a confirmation callback; the CLI prompts (or passes --yes), and tests inject one")
	}
	if err := opt.Confirm(plan); err != nil {
		return Result{Plan: plan}, fmt.Errorf("resync aborted before any state change or network access: %w", err)
	}

	result := Result{Plan: plan, JournalPath: plan.JournalPath}
	// emptyFinalize is the offline completion of a pass with nothing to
	// retransmit at all (no synced batches, or an empty resumed journal):
	// there is no scope-dependent decision to re-verify, so it needs no
	// network access. Every other finalize-only case is a crash recovery
	// whose done decisions still have to clear the scope gate below.
	emptyFinalize := finalizeOnly && len(jb.Batches) == 0
	if !resumed || emptyFinalize {
		// Durable plan before any upload (a crash from here on resumes
		// instead of restarting), or the empty-pass completion write.
		// Both happen strictly after confirmation.
		if emptyFinalize && jb.CompletedAt == nil {
			if err := completeJob(stateDir, &jb, now); err != nil {
				return result, err
			}
		} else if err := saveJob(stateDir, jb); err != nil {
			return result, fmt.Errorf("cannot persist the resync job journal before any upload; nothing was retransmitted: %w", err)
		}
	}
	if emptyFinalize {
		return Result{Plan: plan, Completed: true, JournalPath: plan.JournalPath}, nil
	}

	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	// Retry wiring (the automatic pass only; the explicit CLI leaves
	// opt.Retry nil). The hook hands syncclient's per-attempt self GETs
	// the same durable preflight accounting this pass performs for its
	// own authorization reads — one persisted record per GET, retries
	// included — while the target keeps its BatchFile selection and never
	// gains a StateDir: the outbox is never re-marked and synced batches
	// stay terminal. With the hook wired, syncclient accounts the FIRST
	// attempt's GET itself, so the per-target records below are skipped
	// to keep the accounting exactly one record per GET.
	var retryPreflight func(time.Time) error
	if opt.Retry != nil {
		retryPreflight = func(at time.Time) error {
			_, err := ledger.RecordPreflightAttempt(at)
			return err
		}
	}

	// Live authorization preflight before anything is retransmitted. The
	// attempt accounting write happens first: if it fails, zero HTTP
	// traffic of any kind occurs.
	if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
		return result, fmt.Errorf("cannot persist preflight attempt accounting before the authorization check; no HTTP request was made and the job stays resumable: %w", err)
	}
	self, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
	if err != nil {
		result.Stopped = "authorization preflight failed"
		return result, fmt.Errorf("resync stopped before any upload; the job stays resumable: %w", err)
	}
	result.Self = self
	if err := syncclient.CheckSelfDataEpoch(self, st.DataEpoch); err != nil {
		result.Stopped = "device data epoch changed"
		return result, err
	}
	if devicePaused(self) {
		result.Stopped = "device paused"
		return result, fmt.Errorf("%w: server reports collection paused for this device; the resync job stays resumable and nothing was sent", syncclient.ErrDevicePaused)
	}
	scope, err := scopeFromSelf(self, st)
	if err != nil {
		result.Stopped = "consent scope unknown"
		return result, fmt.Errorf("resync stopped before any upload; the job stays resumable: %w", err)
	}

	// Scope gate: the job's recorded done/skip decisions are valid only
	// under the live consent scope they were made under. Verify the job's
	// baseline against this fresh snapshot; on any change (revision or
	// content, narrowed or widened) re-plan under the fresh scope and stop
	// before any upload — stale decisions are never treated as completing
	// the current authorization. The re-plan preserves the job's frozen
	// snapshot universe when it has one (batch boundary intact) and
	// covers the complete synced history otherwise. This also guards the
	// crash-recovery finalize above: a job whose every batch is done may
	// only be marked complete under an unchanged scope.
	gate, err := reconcileJobScope(stateDir, st, serverURL, out, &jb, scope, now)
	if err != nil {
		result.Stopped = scopeGateStopped
		return result, err
	}
	if gate.replanned {
		result.Stopped = scopeGateStopped
		result.Remaining = countNotDone(gate.job)
		return result, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s); the job's earlier done/skip decisions were made under the old authorization and were NOT treated as completing the current scope. The job was re-planned as %s (%d batch(es)) under the fresh scope — within its original snapshot boundary when it had one, so batches synced after that snapshot was captured stay excluded — and saved to %s; re-run the same toktrail resync --all command to execute the re-planned pass — already-delivered records replay without double counting, and records outside the live scope stay withheld as a normal exclusion rather than a gap. Nothing was retransmitted in this run", jb.JobID, gate.change, gate.job.JobID, len(gate.job.Batches), journalPath(stateDir))
	}

	uploads := 0
	budget := opt.MaxBatches > 0
	for idx := range jb.Batches {
		b := &jb.Batches[idx]
		if b.Outcome == outcomeDone {
			if b.ScopeRevision == scope.revision {
				continue
			}
			// Per-batch dynamic scope check (defense in depth behind the
			// job-level gate): this done decision was recorded under a
			// consent revision other than the live one. Old done — and
			// its withheld-record list — must not count as completing the
			// current authorization, so the batch is re-opened and
			// re-evaluated from scratch below under the fresh scope. Its
			// prior receipts are dropped with it: re-derived targets
			// replay idempotently server-side, and the journal's receipt
			// accounting then reflects exactly the current evaluation.
			b.Outcome = outcomePlanned
			b.BlockedReason = ""
			b.Error = ""
			b.Skipped = nil
			b.Uploads = nil
		}
		// Tamper guard: the parent file must still hash to the payload the
		// job was planned against.
		raw, err := os.ReadFile(b.File)
		if errors.Is(err, os.ErrNotExist) {
			result.Stopped = "history file missing"
			return result, fmt.Errorf("resync stopped: batch %s history file disappeared (%s); the job stays resumable — restore the file or remove the journal to abandon it", b.BatchID, b.File)
		}
		if err != nil {
			result.Stopped = "history file unreadable"
			return result, fmt.Errorf("resync stopped: batch %s history file cannot be read: %w", b.BatchID, err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != b.PayloadSHA256 {
			result.Stopped = "history file tampered"
			return result, fmt.Errorf("resync stopped: batch %s file content changed since the job was planned (payload hash mismatch); failing closed — nothing more was retransmitted", b.BatchID)
		}
		var parent syncclient.BatchRequest
		if err := json.Unmarshal(raw, &parent); err != nil {
			result.Stopped = "history file unreadable"
			return result, fmt.Errorf("resync stopped: batch %s history file is no longer a valid batch: %w", b.BatchID, err)
		}
		// Divergence guard: the outbox must still know the batch as synced.
		entry, ok := outboxEntry(out, b.BatchID)
		if !ok || entry.Status != outbox.StatusSynced {
			result.Stopped = "outbox diverged"
			return result, fmt.Errorf("resync stopped: batch %s is no longer a synced outbox entry; local state diverged from the job plan, failing closed", b.BatchID)
		}
		// Local permission guard (also covers resume drift): the batch's
		// source must still carry an enabled local grant.
		cfg, cfgErr := grants.New(stateDir).Load()
		if cfgErr != nil {
			result.Stopped = "local grant config unreadable"
			return result, fmt.Errorf("resync stopped: batch %s cannot be checked against the local source grants: %w", b.BatchID, cfgErr)
		}
		if !grantAllowed(cfg, b.Source, b.Input) {
			markAttempt(b, now)
			b.Outcome = outcomeBlocked
			b.ScopeRevision = scope.revision
			b.BlockedReason = "local source grant is disabled or missing; re-enable it with toktrail sources enable and re-run"
			b.Uploads = nil
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.Blocked++
			emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Err: b.BlockedReason})
			continue
		}

		// Live scope evaluation: in-scope records retransmit, out-of-scope
		// records are withheld (never quarantined, never deleted — they
		// stay in the immutable original and are re-evaluated by the next
		// explicit pass).
		inScope := make([]json.RawMessage, 0, len(parent.Records))
		skipped := make([]skippedRecord, 0)
		for _, rec := range parent.Records {
			in, reason, err := scope.evaluateRecord(rec)
			if err != nil {
				result.Stopped = "record unevaluable"
				return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, err)
			}
			if !in {
				key, keyErr := recordKeyOf(rec)
				if keyErr != nil {
					result.Stopped = "record unevaluable"
					return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, keyErr)
				}
				skipped = append(skipped, skippedRecord{RecordKey: key, Reason: reason})
				continue
			}
			inScope = append(inScope, rec)
		}
		markAttempt(b, now)
		b.ScopeRevision = scope.revision
		b.Skipped = skipped

		if len(inScope) == 0 {
			b.Outcome = outcomeBlocked
			b.BlockedReason = fmt.Sprintf("all %d record(s) fall outside the live consent scope (revision %d)", len(parent.Records), scope.revision)
			b.Uploads = nil
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.Blocked++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Skipped: len(skipped), Err: b.BlockedReason})
			continue
		}

		targets, err := deriveUploads(stateDir, *b, parent, inScope, scope, confirmedOverrides)
		if err != nil {
			result.Stopped = "upload derivation failed"
			return result, fmt.Errorf("resync stopped; batch %s stays un-retransmitted: %w", b.BatchID, err)
		}
		pendingTargets := make([]jobUpload, 0, len(targets))
		doneUploads := make(map[string]bool, len(b.Uploads))
		for _, u := range b.Uploads {
			if u.ReceiptStatus != "" {
				doneUploads[u.BatchID] = true
			}
		}
		for _, t := range targets {
			if !doneUploads[t.BatchID] {
				pendingTargets = append(pendingTargets, t)
			}
		}
		if len(pendingTargets) == 0 {
			b.Outcome = outcomeDone
			b.Error = ""
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.UploadedBatches++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, progressDoneEvent(*b))
			continue
		}

		stopped := ""
		for _, t := range pendingTargets {
			if budget && uploads >= opt.MaxBatches {
				stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run toktrail resync --all to continue", opt.MaxBatches)
				break
			}
			// Account Run's internal self GET before it happens, mirroring
			// the syncclient guarantee that every authorization GET is
			// preceded by a durable attempt record. Under the retry policy
			// the syncclient performs this accounting itself — before
			// EVERY attempt's GET, retries included — so the record is
			// made here only for the single-shot pass.
			if retryPreflight == nil {
				if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
					result.Stopped = "preflight accounting failed"
					return result, fmt.Errorf("cannot persist preflight attempt accounting before the upload of %s; the job stays resumable: %w", t.BatchID, err)
				}
			}
			res, runErr := syncclient.Run(ctx, store, syncclient.Options{
				ServerURL:           serverURL,
				BatchFile:           t.File,
				BatchID:             t.BatchID,
				HTTPClient:          client,
				ReplaceExisting:     t.Replace,
				Budget:              opt.Budget,
				BudgetQueue:         budgetQueueHistory,
				Retry:               opt.Retry,
				PreflightAccounting: retryPreflight,
			})
			if runErr != nil {
				switch {
				case errors.Is(runErr, syncclient.ErrPreflightAccounting):
					// The durable preflight accounting write failed before
					// any self GET: zero HTTP traffic happened and nothing
					// was submitted, so the target is NOT marked failed —
					// the job stays resumable exactly like the pass-level
					// accounting failure above.
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = "preflight accounting failed"
					return result, fmt.Errorf("cannot persist preflight attempt accounting before the upload of %s; the job stays resumable: %w", t.BatchID, runErr)
				case errors.Is(runErr, syncclient.ErrDeviceRevoked), errors.Is(runErr, syncclient.ErrSubjectDeleted):
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = "device no longer authorized"
					return result, fmt.Errorf("resync stopped; the job stays resumable and nothing further was sent: %w", runErr)
				case errors.Is(runErr, syncclient.ErrDevicePaused):
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = "device paused"
					return result, fmt.Errorf("resync stopped; the job stays resumable and nothing further was sent: %w", runErr)
				case errors.Is(runErr, syncclient.ErrScopeChanged), errors.Is(runErr, syncclient.ErrOutsideScope):
					b.Outcome = outcomeBlocked
					b.BlockedReason = "server rejected the upload under the live consent scope: " + runErr.Error()
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Blocked++
					result.Stopped = "server scope rejection"
					emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, Outcome: outcomeBlocked, Records: b.Records, Skipped: len(skipped), Err: b.BlockedReason})
					return result, fmt.Errorf("resync stopped after a server-side scope rejection of batch %s; the local scope snapshot may be stale, the job stays resumable: %w", b.BatchID, runErr)
				case budgetDecline(runErr):
					// The shared POST budget declined this attempt after
					// the authorization and scope gates but BEFORE the
					// ingest POST, so nothing was submitted. That is not
					// a batch failure and the journal is not lost: the
					// batch keeps its previous outcome (a later run
					// re-evaluates planned, failed, and blocked batches
					// alike), and the pass stops here, resumable by
					// re-running the same command under a fresh budget.
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Stopped = budgetStopped
					result.Remaining = countNotDone(jb)
					return result, fmt.Errorf("resync stopped before the upload of %s: the shared sync POST budget declined the attempt, so no ingest POST was made for it and the batch was NOT marked failed; the job stays resumable — re-run the same toktrail resync --all command to continue: %w", t.BatchID, runErr)
				default:
					b.Outcome = outcomeFailed
					b.Error = runErr.Error()
					if err := saveJob(stateDir, jb); err != nil {
						return result, err
					}
					result.Failed++
					result.Stopped = "upload failed"
					emit(opt.Progress, ProgressEvent{BatchID: b.BatchID, UploadBatchID: t.BatchID, Outcome: outcomeFailed, Records: b.Records, Err: runErr.Error()})
					return result, fmt.Errorf("resync stopped after the upload of %s failed; the job stays resumable and the failed batch is retried by the next run: %w", t.BatchID, runErr)
				}
			}
			if res.Receipt.BatchID == "" {
				b.Outcome = outcomeFailed
				b.Error = "sync returned no batch receipt"
				if err := saveJob(stateDir, jb); err != nil {
					return result, err
				}
				result.Failed++
				result.Stopped = "upload failed"
				return result, fmt.Errorf("resync stopped: upload of %s returned no batch receipt; the job stays resumable", t.BatchID)
			}
			uploaded := res.Receipt.AcceptedRecords + res.Receipt.RejectedRecords
			b.Uploads = append(b.Uploads, jobUpload{
				BatchID:         t.BatchID,
				File:            t.File,
				Records:         t.Records,
				ReceiptStatus:   res.Receipt.Status,
				AcceptedRecords: res.Receipt.AcceptedRecords,
				RejectedRecords: res.Receipt.RejectedRecords,
				Replay:          res.Receipt.Replay,
				SyncedAt:        res.Receipt.ReceivedAt,
			})
			uploads++
			result.Uploads++
			result.UploadedRecords += uploaded
			result.AcceptedRecords += res.Receipt.AcceptedRecords
			result.RejectedRecords += res.Receipt.RejectedRecords
			if res.Receipt.Replay {
				result.ReplayReceipts++
			}
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			// Mid-run authorization drift: syncclient preflights every
			// upload with its own fresh self GET and echoes that snapshot's
			// consent revision on the POST, so this receipt was accepted
			// under exactly res.Self — which may be newer than the scope
			// this run derived its keep/skip decisions from (a widening
			// does not fail the upload, it succeeds). When the two diverge,
			// the remaining decisions are stale: stop before any further
			// upload and before the batch could be marked done. The
			// accepted upload stands; the job stays resumable under its
			// recorded baseline, so the next run re-plans under the live
			// scope instead of completing on the stale one.
			if drift, why := selfDrift(scope, res.Self, st); drift {
				result.Stopped = scopeGateStopped
				result.Remaining = countNotDone(jb)
				return result, fmt.Errorf("resync stopped mid-pass: the consent scope changed while retransmitting (%s); the server accepted the upload of %s under the live authorization, but this run's remaining done/skip decisions were planned under the old scope and were NOT treated as completing the current scope — re-run the same toktrail resync --all command and it re-plans under the live scope, within the job's original snapshot boundary when it had one (already-delivered records replay without double counting)", why, t.BatchID)
			}
		}
		if stopped != "" {
			result.Stopped = stopped
			break
		}
		allDone := len(b.Uploads) >= len(targets)
		if allDone {
			b.Outcome = outcomeDone
			b.Error = ""
			if err := saveJob(stateDir, jb); err != nil {
				return result, err
			}
			result.UploadedBatches++
			result.SkippedOutOfScopeRecords += len(skipped)
			emit(opt.Progress, progressDoneEvent(*b))
		}
	}

	// Override-ledger retransmission: acknowledged current-scan records
	// that no archived batch carries (keys the override pass added or
	// repaired beyond the archive) are part of the full restore — without
	// them, a server that lost its history again could never recover
	// them. They are re-derived from the CURRENT ledger each run (their
	// identities hash the attempt id and full content, so a changed
	// generation re-uploads instead of replaying an old receipt),
	// grant-gated, scope-evaluated per record, and sent with
	// replaceExisting=true (the acknowledged override content is the
	// authority for its key).
	if result.Stopped == "" && len(confirmedOverrides) > 0 {
		archived, err := plannedBatchKeys(jb)
		if err != nil {
			result.Stopped = "override ledger read failed"
			return result, fmt.Errorf("resync stopped before the override-ledger retransmission; the job stays resumable: %w", err)
		}
		cfg, cfgErr := grants.New(stateDir).Load()
		if cfgErr != nil {
			result.Stopped = "local grant config unreadable"
			return result, fmt.Errorf("resync stopped before the override-ledger retransmission; the job stays resumable: %w", cfgErr)
		}
		delta := make([]overrideDelta, 0)
		for key, entry := range confirmedOverrides {
			if archived[entry.Source][key] {
				// The archived batches already retransmit this key (with
				// the substituted override content); never send it twice.
				continue
			}
			if !grantAllowed(cfg, entry.Source, entry.Input) {
				continue
			}
			canonical, cerr := overrides.Canonical(entry.Record)
			if cerr != nil {
				result.Stopped = "override ledger read failed"
				return result, fmt.Errorf("resync stopped: override ledger record %s is not valid JSON: %w", key, cerr)
			}
			in, _, evalErr := scope.evaluateRecord(canonical)
			if evalErr != nil {
				result.Stopped = "record unevaluable"
				return result, fmt.Errorf("resync stopped before the override-ledger retransmission; the job stays resumable: %w", evalErr)
			}
			if !in {
				result.SkippedOutOfScopeRecords++
				continue
			}
			delta = append(delta, overrideDelta{Key: key, Canonical: canonical, Source: entry.Source, Input: entry.Input, IsNew: true, AttemptID: entry.AttemptID})
		}
		doneOverride := make(map[string]bool, len(jb.OverrideUpload))
		for _, u := range jb.OverrideUpload {
			if u.ReceiptStatus != "" {
				doneOverride[u.BatchID] = true
			}
		}
		for _, chunk := range chunkOverrideDelta(delta) {
			id := overrideBatchID(chunk)
			if doneOverride[id] {
				continue
			}
			if budget && uploads >= opt.MaxBatches {
				result.Stopped = fmt.Sprintf("upload budget reached (%d upload(s) this run); re-run toktrail resync --all to continue", opt.MaxBatches)
				break
			}
			file, werr := writeChildBatch(stateDir, id, chunkRecords(chunk), frozenDataEpoch(st.DataEpoch))
			if werr != nil {
				result.Stopped = "override batch write failed"
				return result, fmt.Errorf("resync stopped before the override-ledger retransmission; the job stays resumable: %w", werr)
			}
			// Same accounting contract as the history targets above: the
			// single-shot pass records Run's internal self GET itself;
			// under the retry policy the syncclient's hook accounts every
			// attempt (retries included) exactly once.
			if retryPreflight == nil {
				if _, perr := ledger.RecordPreflightAttempt(now().UTC()); perr != nil {
					result.Stopped = "preflight accounting failed"
					return result, fmt.Errorf("cannot persist preflight attempt accounting before the upload of %s; the job stays resumable: %w", id, perr)
				}
			}
			res, runErr := syncclient.Run(ctx, store, syncclient.Options{
				ServerURL:           serverURL,
				BatchFile:           file,
				BatchID:             id,
				HTTPClient:          client,
				ReplaceExisting:     true,
				Budget:              opt.Budget,
				BudgetQueue:         budgetQueueHistory,
				Retry:               opt.Retry,
				PreflightAccounting: retryPreflight,
			})
			if runErr != nil {
				if errors.Is(runErr, syncclient.ErrPreflightAccounting) {
					// Zero HTTP traffic, nothing submitted: the job stays
					// resumable and the target is not marked failed.
					if serr := saveJob(stateDir, jb); serr != nil {
						return result, serr
					}
					result.Stopped = "preflight accounting failed"
					return result, fmt.Errorf("cannot persist preflight attempt accounting before the override-ledger upload of %s; the job stays resumable: %w", id, runErr)
				}
				if budgetDecline(runErr) {
					// Same contract as the history batches above: the
					// budget declined before the ingest POST, so nothing
					// was submitted, nothing failed, and the journal
					// keeps the pass resumable.
					if serr := saveJob(stateDir, jb); serr != nil {
						return result, serr
					}
					result.Stopped = budgetStopped
					result.Remaining = countNotDone(jb)
					return result, fmt.Errorf("resync stopped before the override-ledger upload of %s: the shared sync POST budget declined the attempt, so no ingest POST was made for it; the job stays resumable — re-run the same toktrail resync --all command to continue: %w", id, runErr)
				}
				if serr := saveJob(stateDir, jb); serr != nil {
					return result, serr
				}
				result.Stopped = "override-ledger upload failed"
				return result, fmt.Errorf("resync stopped after the override-ledger upload of %s failed; the job stays resumable: %w", id, runErr)
			}
			if res.Receipt.BatchID == "" {
				result.Stopped = "override-ledger upload failed"
				return result, fmt.Errorf("resync stopped: the override-ledger upload of %s returned no batch receipt; the job stays resumable", id)
			}
			jb.OverrideUpload = append(jb.OverrideUpload, jobUpload{
				BatchID:         id,
				File:            file,
				Records:         len(chunk),
				ReceiptStatus:   res.Receipt.Status,
				AcceptedRecords: res.Receipt.AcceptedRecords,
				RejectedRecords: res.Receipt.RejectedRecords,
				Replay:          res.Receipt.Replay,
				Replace:         true,
				SyncedAt:        res.Receipt.ReceivedAt,
			})
			uploads++
			result.Uploads++
			result.UploadedRecords += res.Receipt.AcceptedRecords + res.Receipt.RejectedRecords
			result.AcceptedRecords += res.Receipt.AcceptedRecords
			result.RejectedRecords += res.Receipt.RejectedRecords
			if res.Receipt.Replay {
				result.ReplayReceipts++
			}
			if serr := saveJob(stateDir, jb); serr != nil {
				return result, serr
			}
			if drift, why := selfDrift(scope, res.Self, st); drift {
				result.Stopped = scopeGateStopped
				result.Remaining = countNotDone(jb)
				return result, fmt.Errorf("resync stopped mid-pass: the consent scope changed while retransmitting the override ledger (%s); re-run the same command and it re-plans under the live scope", why)
			}
		}
	}

	if result.Stopped == "" {
		// Completion gate: the job may only be marked complete under the
		// authorization it was planned against, verified FRESH at
		// completion time. The scope can move after the last upload's
		// preflight (or between the run's own preflight and a
		// finalize-only convergence), and neither the loop above nor the
		// server would necessarily notice: a widening lets every upload
		// succeed while the withheld-record decisions were made under the
		// old scope. One final self GET — preceded by the same durable
		// attempt accounting as every authorization read — closes that
		// window; on drift the job stays incomplete and the next run
		// re-plans under the live scope.
		if _, err := ledger.RecordPreflightAttempt(now().UTC()); err != nil {
			result.Stopped = "preflight accounting failed"
			return result, fmt.Errorf("cannot persist preflight attempt accounting before the completion check; the job stays resumable and is not marked complete: %w", err)
		}
		finalSelf, err := syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
		if err != nil {
			result.Stopped = "authorization preflight failed"
			return result, fmt.Errorf("resync stopped before the completion write; the job stays resumable and is not marked complete: %w", err)
		}
		if drift, why := selfDrift(scope, finalSelf, st); drift {
			result.Stopped = scopeGateStopped
			result.Remaining = countNotDone(jb)
			return result, fmt.Errorf("resync stopped before marking the job complete: the consent scope changed while the pass was running (%s); every accepted upload stands, but the job's done/skip decisions were planned under the old scope and were NOT treated as completing the current authorization — re-run the same toktrail resync --all command and it re-plans under the live scope, within the job's original snapshot boundary when it had one (already-delivered records replay without double counting)", why)
		}
		if err := completeJob(stateDir, &jb, now); err != nil {
			return result, err
		}
		result.Completed = true
	} else {
		// Incomplete job: the same command resumes everything not done
		// (planned, failed, and blocked batches are all re-evaluated by
		// the resume run).
		result.Remaining = countNotDone(jb)
	}
	if result.Completed {
		// A completed pass with server-rejected records is terminal (the
		// rejection is deterministic, retrying it in place would loop), but
		// it must never be reported as a full restore.
		if rejected := countJobRejected(jb); rejected > 0 {
			return result, fmt.Errorf("the resync pass completed, but the server rejected %d record(s) (e.g. record_conflict); those records were NOT restored — the journal lists the per-batch receipts, and the record keys remain in the original batch files", rejected)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Planning helpers
// ---------------------------------------------------------------------------

func emit(fn func(ProgressEvent), ev ProgressEvent) {
	if fn != nil {
		fn(ev)
	}
}

func progressDoneEvent(b jobBatch) ProgressEvent {
	uploaded, accepted, rejected := 0, 0, 0
	replay := false
	last := ""
	for _, u := range b.Uploads {
		uploaded += u.AcceptedRecords + u.RejectedRecords
		accepted += u.AcceptedRecords
		rejected += u.RejectedRecords
		if u.Replay {
			replay = true
		}
		last = u.BatchID
	}
	return ProgressEvent{BatchID: b.BatchID, UploadBatchID: last, Outcome: outcomeDone, Records: b.Records, Uploaded: uploaded, Accepted: accepted, Rejected: rejected, Replay: replay, Skipped: len(b.Skipped)}
}
func markAttempt(b *jobBatch, now func() time.Time) {
	b.Attempts++
	at := now().UTC()
	b.LastAttemptAt = &at
}

// countNotDone counts the batches a resume run would re-evaluate.
func countNotDone(jb job) int {
	n := 0
	for _, b := range jb.Batches {
		if b.Outcome != outcomeDone {
			n++
		}
	}
	return n
}

// countJobRejected sums the server-rejected records across the job's
// recorded receipts (accepted + rejected always equals the submitted
// count per receipt).
func countJobRejected(jb job) int {
	n := 0
	for _, b := range jb.Batches {
		for _, u := range b.Uploads {
			n += u.RejectedRecords
		}
	}
	return n
}

func completeJob(stateDir string, jb *job, now func() time.Time) error {
	at := now().UTC()
	jb.CompletedAt = &at
	return saveJob(stateDir, *jb)
}

// scopeGateStopped is the Result.Stopped marker for the consent-scope
// re-plan path: the run ended before any upload because the authorization
// changed, and the journal now carries the re-planned pass.
const scopeGateStopped = "consent scope changed"

// scopeGateOutcome reports what the scope gate decided for one run.
type scopeGateOutcome struct {
	// replanned is true when the recorded decisions were stale and the
	// job was re-planned under the fresh scope.
	replanned bool
	// job is the re-planned replacement job (replanned only): a fresh
	// plan over the current synced outbox WITHIN the old job's frozen
	// snapshot universe when it had one (complete history otherwise),
	// baseline pinned to the fresh scope, every batch planned, no
	// carried-over outcome or receipt — and the same universe frozen
	// for the next re-plan.
	job job
	// change describes the detected divergence for stop messages.
	change string
}

// reconcileJobScope verifies that the job's recorded done/skip decisions
// were made under the live consent scope, or re-plans the job under the
// fresh scope — within its frozen snapshot universe when it has one, over
// the complete synced history otherwise — when they were not. It never
// uploads and
// never touches anything outside the resync-owned journal:
//
//   - A recorded baseline (current schema) must match the fresh scope by
//     revision and content fingerprint.
//   - A journal without a baseline (legacy schema 1, or a job that never
//     reached its preflight) derives one from the per-batch revision
//     stamps: with no live-scope decision at all the fresh scope is simply
//     adopted; with every decision attributable to the same revision as
//     the fresh snapshot the baseline is adopted (the revision is the
//     server's authoritative consent version, so an equal revision means
//     an equal scope); anything else — mixed revisions, unstamped
//     decisions, or a different revision — re-plans.
//
// Adoption only mutates the in-memory job; it persists with the first
// journal write the run performs. On re-plan the previous journal is
// replaced atomically by a fresh plan over the CURRENT synced outbox,
// restricted to the old job's frozen snapshot universe when it had one
// (new job id, all batches planned, fresh scope baseline, same universe);
// the outbox, batch files, per-message progress, cursors, and quarantine
// store are untouched, and already-delivered records stay de-duplicated
// by the server's replay receipts when the re-planned pass re-sends them.
func reconcileJobScope(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, jb *job, scope liveScope, now func() time.Time) (scopeGateOutcome, error) {
	if jb.Scope != nil {
		if jb.Scope.matches(scope) {
			return scopeGateOutcome{}, nil
		}
		return replanJob(stateDir, st, serverURL, out, *jb, jb.Scope, 0, scope, now)
	}
	revision, decided, attributable := jobDecisionRevision(*jb)
	if !decided {
		// No live-scope decision exists yet (fresh plan, or an interrupted
		// run that never reached its preflight): adopt the fresh scope as
		// the baseline the upcoming decisions will be recorded under.
		jb.Scope = snapshotScope(scope)
		return scopeGateOutcome{}, nil
	}
	if attributable && revision == scope.revision {
		// Legacy migration: every recorded decision stamps this same
		// revision, so it was made under the same consent scope. Adopt
		// the full snapshot so later comparisons check content too.
		jb.Scope = snapshotScope(scope)
		return scopeGateOutcome{}, nil
	}
	if !attributable {
		revision = 0
	}
	return replanJob(stateDir, st, serverURL, out, *jb, nil, revision, scope, now)
}

// replanJob rebuilds the resync job under the fresh live scope — within
// the old job's frozen snapshot universe when it had one, over the
// complete synced history otherwise — and durably replaces the stale
// journal with it. oldScope is the recorded baseline (nil for a legacy
// journal whose decisions attribute to legacyRevision, or 0 when they do
// not attribute at all). A failure to build or persist leaves the
// previous journal untouched and resumable.
func replanJob(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, old job, oldScope *jobScope, legacyRevision int64, scope liveScope, now func() time.Time) (scopeGateOutcome, error) {
	change := describeScopeChange(oldScope, legacyRevision, scope)
	// The re-plan preserves the job's history boundary: the frozen
	// snapshot universe recorded when the job was planned, BEFORE grant
	// filtering. Batches synced after that capture — most commonly the
	// current run's own collection uploads — stay excluded, while
	// entries the grants excluded at plan time remain in the universe
	// and rejoin once the widened authorization allows them. An
	// unrestricted job (nil universe: the explicit pass, or a legacy
	// journal without the field) re-plans over the complete synced
	// history, exactly as before. buildNewJob freezes the same universe
	// into the replacement job, so the boundary survives every
	// subsequent re-plan too.
	fresh, _, err := buildNewJob(stateDir, st, serverURL, out, now, Plan{
		DeviceID:     st.DeviceID,
		ServerURL:    serverURL,
		StateDir:     stateDir,
		JournalPath:  journalPath(stateDir),
		CoverageNote: coverageNote,
	}, old.Snapshot)
	if err != nil {
		return scopeGateOutcome{}, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s), and the re-planned pass cannot be built: %w; the previous journal is unchanged and the job stays resumable — resolve the reported problem, or remove %s to abandon the job, then re-run", old.JobID, change, err, journalPath(stateDir))
	}
	fresh.Scope = snapshotScope(scope)
	if err := saveJob(stateDir, fresh); err != nil {
		return scopeGateOutcome{}, fmt.Errorf("resync stopped before any upload: the consent scope changed since the incomplete job %s recorded its progress (%s), and the re-planned job cannot be persisted: %w; the previous journal is unchanged and the job stays resumable", old.JobID, change, err)
	}
	return scopeGateOutcome{replanned: true, job: fresh, change: change}, nil
}

func fillExclusions(plan *Plan, ex jobExclusions) {
	plan.ExcludedReorganized = ex.Reorganized
	plan.ExcludedPending = ex.Pending
	plan.ExcludedAfterSnapshot = ex.AfterSnapshot
	plan.ExcludedLocalGrant = append([]string(nil), ex.LocalGrant...)
}

func outboxEntry(out outbox.Outbox, batchID string) (outbox.BatchEntry, bool) {
	for _, entry := range out.Batches {
		if entry.BatchID == batchID {
			return entry, true
		}
	}
	return outbox.BatchEntry{}, false
}

// grantAllowed reports whether (source, input) currently matches an enabled
// local source grant. An empty source or input can never match, so batches
// without source identity are withheld under the same strict rule.
func grantAllowed(cfg grants.Config, source, input string) bool {
	for _, grant := range cfg.Grants {
		if grant.Source == source && grant.Input == input && grant.Enabled {
			return true
		}
	}
	return false
}

// grantsConfigExists reports whether any grant config file exists. A
// missing config denies retransmission by default (the error message tells
// the user to enable sources) so residual archives cannot bypass a
// withdrawn local permission such as a cancelled connect.
func grantsConfigExists(stateDir string) (bool, error) {
	store := grants.New(stateDir)
	for _, path := range []string{store.Path(), store.LegacyPath()} {
		if _, err := os.Stat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func quarantineCount(stateDir string) int {
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0
	}
	return len(entries)
}

// buildNewJob classifies the outbox into the job plan: synced entries are
// candidate leaves (reorganized parents are terminal — their records live
// in child batches or quarantine, which appear as their own entries, so
// skipping the parents never double counts), pending entries stay with the
// normal sync drain, and only grant-allowed, structurally valid batches
// join the plan. Every validation problem is collected and reported before
// anything is written or uploaded: a missing or tampered history file fails
// the whole run closed, because silently recovering a partial history
// would misrepresent coverage.
//
// restrict optionally limits the plan to the synced batches a caller
// captured earlier (connect's automatic pass): synced batches missing from
// the snapshot are excluded and counted in ExcludedAfterSnapshot instead
// of being silently dropped from the report. The restriction is frozen
// into the job AS CAPTURED — before grant filtering — so a later re-plan
// (replanJob passes the job's universe back in here) keeps the boundary
// and can recover entries the grants excluded at plan time once the
// authorization widens. nil plans the complete synced history (the
// explicit pass, and every re-plan of an unrestricted job).
func buildNewJob(stateDir string, st statedir.DeviceState, serverURL string, out outbox.Outbox, now func() time.Time, plan Plan, restrict *SyncedBatchSnapshot) (job, Plan, error) {
	// universe is the restriction as captured, cloned defensively: the
	// job owns it from here on, verbatim across resume and re-plan.
	universe := cloneSnapshot(restrict)
	var only map[string]bool
	if universe != nil {
		only = make(map[string]bool, len(universe.BatchIDs))
		for _, id := range universe.BatchIDs {
			only[id] = true
		}
	}
	candidates := make([]outbox.BatchEntry, 0)
	ex := jobExclusions{}
	for _, entry := range out.Batches {
		switch entry.Status {
		case outbox.StatusSynced:
			if only != nil && !only[entry.BatchID] {
				// Synced after the snapshot was captured — most commonly
				// by this very run's collection. The automatic pass
				// excludes it (an immediate replay would only duplicate
				// what the drain just uploaded) and reports the
				// exclusion instead of hiding it.
				ex.AfterSnapshot++
				continue
			}
			candidates = append(candidates, entry)
		case outbox.StatusReorganized:
			ex.Reorganized++
		case outbox.StatusPending:
			ex.Pending++
		}
	}
	plan.SnapshotRestricted = universe != nil
	plan.CoverageNote = coverageNoteFor(universe != nil)
	if len(candidates) == 0 {
		// Nothing synced the plan may cover — an empty outbox, or an
		// empty-restricted pass (a first install whose batches this
		// run's collection will sync): return a completed empty job so
		// the next explicit pass is again a fresh full pass. Planning is
		// pure: the empty job is persisted only by a confirmed
		// execution run (finalizeOnly), so a dry run writes nothing.
		id, err := newJobID()
		if err != nil {
			return job{}, plan, err
		}
		at := now().UTC()
		jb := job{Schema: journalSchema, JobID: id, DeviceID: st.DeviceID, ServerURL: serverURL, CreatedAt: at, CompletedAt: &at, Exclusions: ex, Snapshot: universe}
		plan.JobID = id
		plan.TotalInJob = 0
		plan.DoneInJob = 0
		fillExclusions(&plan, ex)
		return jb, plan, nil
	}

	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		return job{}, plan, fmt.Errorf("cannot read the local source grants; resync refuses to retransmit without current local authorization: %w", err)
	}
	configExists, err := grantsConfigExists(stateDir)
	if err != nil {
		return job{}, plan, err
	}

	problems := make([]string, 0)
	planned := make([]PlannedBatch, 0)
	for _, entry := range candidates {
		if !grantAllowed(cfg, entry.Source, entry.Input) {
			ex.LocalGrant = append(ex.LocalGrant, entry.BatchID)
			continue
		}
		pb, err := validatePlannedBatch(entry)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		planned = append(planned, pb)
	}
	// Report integrity problems before the grant-emptiness diagnosis: a
	// run whose history files are all missing must say so, not blame the
	// grants.
	if len(problems) > 0 {
		return job{}, plan, fmt.Errorf("resync cannot plan: %d synced batch file(s) are missing or invalid; nothing was retransmitted and no job was started:\n  - %s", len(problems), strings.Join(problems, "\n  - "))
	}
	if len(planned) == 0 {
		if !configExists {
			return job{}, plan, fmt.Errorf("no local source grants are configured (grants.json is absent): resync denies retransmission by default so residual archives cannot bypass local permission; enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync")
		}
		return job{}, plan, fmt.Errorf("none of the %d synced batch(es) match a currently enabled local source grant (excluded: %s); enable the sources you want to recover with `toktrail sources enable --source <source> --input <absolute-path>` and re-run resync", len(candidates), strings.Join(ex.LocalGrant, ", "))
	}

	sort.Slice(planned, func(i, j int) bool {
		if !planned[i].CreatedAt.Equal(planned[j].CreatedAt) {
			return planned[i].CreatedAt.Before(planned[j].CreatedAt)
		}
		return planned[i].BatchID < planned[j].BatchID
	})

	id, err := newJobID()
	if err != nil {
		return job{}, plan, err
	}
	jb := job{Schema: journalSchema, JobID: id, DeviceID: st.DeviceID, ServerURL: serverURL, CreatedAt: now().UTC(), Exclusions: ex, Snapshot: universe}
	for _, pb := range planned {
		jb.Batches = append(jb.Batches, jobBatch{
			BatchID:       pb.BatchID,
			File:          pb.File,
			Source:        pb.Source,
			Input:         pb.Input,
			Records:       pb.Records,
			PayloadSHA256: pb.PayloadSHA256,
			CreatedAt:     pb.CreatedAt,
			Outcome:       outcomePlanned,
		})
	}
	plan.Batches = planned
	plan.TotalInJob = len(planned)
	plan.DoneInJob = 0
	plan.JobID = id
	for _, pb := range planned {
		plan.PlannedRecords += pb.Records
	}
	fillExclusions(&plan, ex)
	return jb, plan, nil
}

// resumePlan revalidates the non-done batches of an incomplete job: each
// must still be a synced outbox entry and its file must still hash to the
// payload the job froze. Divergence fails closed with the batch named.
func resumePlan(stateDir string, jb job, out outbox.Outbox) ([]PlannedBatch, int, error) {
	remaining := make([]PlannedBatch, 0)
	done := 0
	problems := make([]string, 0)
	for _, b := range jb.Batches {
		if b.Outcome == outcomeDone {
			done++
			continue
		}
		entry, ok := outboxEntry(out, b.BatchID)
		if !ok || entry.Status != outbox.StatusSynced {
			problems = append(problems, fmt.Sprintf("batch %s is no longer a synced outbox entry; local state diverged from the job plan", b.BatchID))
			continue
		}
		raw, err := os.ReadFile(b.File)
		if errors.Is(err, os.ErrNotExist) {
			problems = append(problems, fmt.Sprintf("batch %s: history file is missing: %s (the outbox entry is preserved; restore the file or abandon the job)", b.BatchID, b.File))
			continue
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("batch %s: history file cannot be read: %v", b.BatchID, err))
			continue
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != b.PayloadSHA256 {
			problems = append(problems, fmt.Sprintf("batch %s: file content changed since the job was planned (payload hash mismatch); the file was tampered with or replaced", b.BatchID))
			continue
		}
		remaining = append(remaining, PlannedBatch{
			BatchID:       b.BatchID,
			File:          b.File,
			Source:        b.Source,
			Input:         b.Input,
			Records:       b.Records,
			PayloadSHA256: b.PayloadSHA256,
			CreatedAt:     b.CreatedAt,
		})
	}
	if len(problems) > 0 {
		return nil, 0, fmt.Errorf("the incomplete resync job %s can no longer be resumed safely; nothing was retransmitted:\n  - %s", jb.JobID, strings.Join(problems, "\n  - "))
	}
	return remaining, done, nil
}

// validatePlannedBatch performs the offline validation of one candidate:
// existence, parseability, identity and record-count consistency with the
// outbox entry, the upload privacy whitelist (the same adapter policy
// syncclient enforces), per-record size limits, and the scope-evaluation
// preconditions (record key, occurredAt). It also freezes the payload hash.
func validatePlannedBatch(entry outbox.BatchEntry) (PlannedBatch, error) {
	raw, err := os.ReadFile(entry.File)
	if errors.Is(err, os.ErrNotExist) {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file is missing: %s (the outbox entry is preserved; restore the file, or accept the gap and re-export from the source)", entry.BatchID, entry.File)
	}
	if err != nil {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file cannot be read: %v", entry.BatchID, err)
	}
	var batch syncclient.BatchRequest
	if err := json.Unmarshal(raw, &batch); err != nil {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file is not a valid batch: %v", entry.BatchID, err)
	}
	if strings.TrimSpace(batch.BatchID) != entry.BatchID {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file carries batch id %q; the file does not match the outbox entry", entry.BatchID, batch.BatchID)
	}
	if len(batch.Records) == 0 {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file contains no records", entry.BatchID)
	}
	if entry.RecordCount > 0 && entry.RecordCount != len(batch.Records) {
		return PlannedBatch{}, fmt.Errorf("batch %s: history file carries %d record(s) but the outbox entry recorded %d; the file was modified after it was synced", entry.BatchID, len(batch.Records), entry.RecordCount)
	}
	for idx, rec := range batch.Records {
		if err := validatePlannedRecord(entry.BatchID, idx, rec); err != nil {
			return PlannedBatch{}, err
		}
	}
	sum := sha256.Sum256(raw)
	return PlannedBatch{
		BatchID:       entry.BatchID,
		File:          entry.File,
		Source:        strings.TrimSpace(entry.Source),
		Input:         strings.TrimSpace(entry.Input),
		Records:       len(batch.Records),
		PayloadSHA256: hex.EncodeToString(sum[:]),
		CreatedAt:     entry.CreatedAt,
	}, nil
}

// validatePlannedRecord mirrors the send-path gates that would otherwise
// only fire at upload time (syncclient requireUploadPrivacy plus the
// per-record size cap and scope preconditions), so a bad or tampered batch
// is reported clearly at planning time with zero network traffic.
func validatePlannedRecord(batchID string, idx int, rec json.RawMessage) error {
	if !utf8.Valid(rec) {
		return fmt.Errorf("batch %s: record %d contains invalid UTF-8; refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	var record adapter.Record
	if err := json.Unmarshal(rec, &record); err != nil || record == nil {
		return fmt.Errorf("batch %s: record %d is not a record object; refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	if !adapter.RecordIsUploadSafe(record) {
		return fmt.Errorf("batch %s: record %d carries extra fields or an invalid model (outside the upload whitelist); refusing to retransmit a file that was modified after it was synced", batchID, idx)
	}
	compact, err := compactRecord(rec)
	if err != nil {
		return fmt.Errorf("batch %s: record %d is not valid JSON: %v", batchID, idx, err)
	}
	if len(compact) > syncclient.MaxBatchPayloadBytes {
		return fmt.Errorf("batch %s: record %d exceeds the maximum allowed size (%d bytes > %d bytes); it can never be uploaded as-is", batchID, idx, len(compact), syncclient.MaxBatchPayloadBytes)
	}
	if _, err := recordKeyOf(rec); err != nil {
		return fmt.Errorf("batch %s: record %d: %v", batchID, idx, err)
	}
	var probe struct {
		OccurredAt string `json:"occurredAt"`
	}
	if err := json.Unmarshal(rec, &probe); err != nil {
		return fmt.Errorf("batch %s: record %d is not valid JSON: %v", batchID, idx, err)
	}
	if strings.TrimSpace(probe.OccurredAt) == "" {
		return fmt.Errorf("batch %s: record %d has no occurredAt; it cannot be evaluated against the consent scope", batchID, idx)
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(probe.OccurredAt)); err != nil {
		return fmt.Errorf("batch %s: record %d has an unparseable occurredAt %q", batchID, idx, probe.OccurredAt)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Upload derivation: verbatim original vs deterministic children
// ---------------------------------------------------------------------------

// deriveUploads decides how one parent batch retransmits under the live
// scope. Fully in scope and within the server limits, the ORIGINAL file is
// retransmitted verbatim under its original batch id — the strongest
// idempotency (the server replays the identical batch). Otherwise the
// in-scope records are filtered into deterministic child batches (chunked
// to the server limits) under the resync-owned directory; child ids hash
// the parent id, live revision, scope content, and sorted kept record
// keys, so the same decision always replays to the same identity and the
// server de-duplicates it. Withheld records stay in the immutable original
// file — nothing is quarantined, modified, or deleted.
//
// Confirmed overrides: when a kept record's key carries an acknowledged
// override (of the batch's own source), the override content replaces the
// archived payload — a same-key conflict must send the current scanned
// record, not the superseded archive value. Any substitution forces child
// derivation (never the verbatim parent), folds the FULL canonical content
// and the override attempt ids into the child identity (so an A→B→A
// content sequence can never replay an earlier receipt), and marks the
// upload replace=true so the server replaces instead of rejecting.
func deriveUploads(stateDir string, parent jobBatch, batch syncclient.BatchRequest, inScope []json.RawMessage, scope liveScope, confirmed map[string]overrides.Entry) ([]jobUpload, error) {
	substituted := false
	effective := make([]json.RawMessage, 0, len(inScope))
	for _, rec := range inScope {
		key, err := recordKeyOf(rec)
		if err != nil {
			return nil, err
		}
		if entry, ok := confirmed[key]; ok && entry.Source == parent.Source {
			canonical, cerr := overrides.Canonical(entry.Record)
			if cerr != nil {
				return nil, cerr
			}
			effective = append(effective, canonical)
			substituted = true
			continue
		}
		c, err := compactRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("record is not valid JSON: %w", err)
		}
		effective = append(effective, c)
	}
	if !substituted {
		if len(inScope) == len(batch.Records) &&
			len(batch.Records) <= syncclient.MaxBatchRecords &&
			envelopeSize(batch) <= syncclient.MaxBatchPayloadBytes {
			return []jobUpload{{BatchID: parent.BatchID, File: parent.File, Records: len(batch.Records)}}, nil
		}
	}
	compact := effective
	keys := make([]string, 0, len(compact))
	for _, rec := range compact {
		key, err := recordKeyOf(rec)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	// Partition into chunks of <= MaxBatchRecords records and <=
	// MaxBatchPayloadBytes compact envelope, mirroring the syncclient
	// oversize split.
	dummyOverhead := envelopeSize(syncclient.BatchRequest{BatchID: "resync-0123456789abcdef", Records: []json.RawMessage{}, DataEpoch: batch.DataEpoch})
	var chunks [][]json.RawMessage
	var chunkKeys [][]string
	var current []json.RawMessage
	var currentKeys []string
	currentSize := dummyOverhead
	for idx, rec := range compact {
		recSize := len(rec)
		if dummyOverhead+recSize > syncclient.MaxBatchPayloadBytes {
			return nil, fmt.Errorf("record %d exceeds the per-record size cap; it can never be uploaded as-is", idx)
		}
		projected := currentSize + recSize
		if len(current) > 0 {
			projected++
		}
		if len(current) > 0 && (len(current) >= syncclient.MaxBatchRecords || projected > syncclient.MaxBatchPayloadBytes) {
			chunks = append(chunks, current)
			chunkKeys = append(chunkKeys, currentKeys)
			current = nil
			currentKeys = nil
			currentSize = dummyOverhead
			projected = dummyOverhead + recSize
		}
		current = append(current, rec)
		currentKeys = append(currentKeys, keys[idx])
		currentSize = projected
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
		chunkKeys = append(chunkKeys, currentKeys)
	}
	targets := make([]jobUpload, 0, len(chunks))
	for idx, chunk := range chunks {
		var id string
		if substituted {
			// Override-substituted children hash the full canonical
			// content and the override attempt ids: a later generation
			// (or a revert to an earlier payload) derives a different
			// batch instead of replaying an old receipt.
			id = resyncOverrideChildBatchID(parent.BatchID, scope.revision, scope, chunk)
		} else {
			id = resyncChildBatchID(parent.BatchID, scope.revision, scope, chunkKeys[idx])
		}
		file, err := writeChildBatch(stateDir, id, chunk, batch.DataEpoch)
		if err != nil {
			return nil, err
		}
		targets = append(targets, jobUpload{BatchID: id, File: file, Records: len(chunk), Replace: substituted})
	}
	return targets, nil
}

// resyncOverrideChildBatchID derives the child identity for an
// override-substituted batch: hash(parent batch + live revision + scope
// content + every record's full canonical content). The content — not
// just the keys — is hashed so any payload change yields a new batch.
func resyncOverrideChildBatchID(parentBatchID string, revision int64, scope liveScope, records []json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(parentBatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(revision, 10)))
	h.Write([]byte{0})
	h.Write([]byte(scope.fingerprint()))
	for _, rec := range records {
		h.Write([]byte{0})
		h.Write(rec)
	}
	return "resync-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func envelopeSize(batch syncclient.BatchRequest) int {
	b, err := json.Marshal(batch)
	if err != nil {
		return 0
	}
	return len(b)
}

// plannedBatchKeys reads the job's planned batch files and returns, per
// source, the record keys the archived retransmission already covers —
// the override-ledger retransmission skips those keys so no record is
// sent twice.
func plannedBatchKeys(jb job) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	for _, b := range jb.Batches {
		if out[b.Source] == nil {
			out[b.Source] = map[string]bool{}
		}
		raw, err := os.ReadFile(b.File)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("batch %s history file disappeared (%s)", b.BatchID, b.File)
		}
		if err != nil {
			return nil, fmt.Errorf("batch %s history file cannot be read: %w", b.BatchID, err)
		}
		var batch syncclient.BatchRequest
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("batch %s history file is no longer a valid batch: %w", b.BatchID, err)
		}
		for _, rec := range batch.Records {
			key, err := recordKeyOf(rec)
			if err != nil {
				return nil, err
			}
			out[b.Source][key] = true
		}
	}
	return out, nil
}

// resyncChildBatchID derives the deterministic child identity:
// hash(parent batch + live revision + scope content + sorted kept record
// keys). Identical decisions replay to the identical id; a different scope
// or record set yields a different batch instead of colliding.
func resyncChildBatchID(parentBatchID string, revision int64, scope liveScope, recordKeys []string) string {
	h := sha256.New()
	h.Write([]byte(parentBatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(revision, 10)))
	h.Write([]byte{0})
	h.Write([]byte(scope.fingerprint()))
	sorted := append([]string(nil), recordKeys...)
	sort.Strings(sorted)
	for _, key := range sorted {
		h.Write([]byte{0})
		h.Write([]byte(key))
	}
	return "resync-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// writeChildBatch atomically writes one derived child batch under the
// resync-owned directory. Records are copied verbatim; an existing
// identical file is a replay no-op, a conflicting file is fatal.
func writeChildBatch(stateDir, id string, records []json.RawMessage, epochs ...*int64) (string, error) {
	var epoch *int64
	if len(epochs) > 0 {
		epoch = epochs[0]
	}
	payload, err := json.Marshal(syncclient.BatchRequest{BatchID: id, Records: records, DataEpoch: epoch})
	if err != nil {
		return "", err
	}
	path := childBatchPath(stateDir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if prior, err := os.ReadFile(path); err == nil {
		var priorBatch syncclient.BatchRequest
		if err := json.Unmarshal(prior, &priorBatch); err != nil || priorBatch.BatchID != id || len(priorBatch.Records) != len(records) {
			return "", fmt.Errorf("resync batch file %s already exists with different content; failing closed", path)
		}
		priorPayload, mErr := json.Marshal(priorBatch)
		if mErr != nil || !bytes.Equal(priorPayload, payload) {
			return "", fmt.Errorf("resync batch file %s already exists with different content; failing closed", path)
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func childBatchPath(stateDir, batchID string) string {
	return filepath.Join(strings.TrimSpace(stateDir), "resync", "batches", batchID+".json")
}

func compactRecord(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
