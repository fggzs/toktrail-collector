// Package collection implements the periodic collection entry
// (`toktrail periodic`): export new local observations through the existing
// exportcommit WAL, then drain a bounded number of pending outbox batches
// through the existing syncclient. When the pending queue runs empty while
// the quarantine store still holds records, the drain performs one
// recovery round through the same syncclient — under its fresh-consent
// preflight and local-grant gate, never a local scope decision — so
// records the current authorization allows again are re-pended and drained
// even on a device with no new data. Quarantined records the current
// authorization still excludes stay put without failing the run.
//
// Guarantees:
//   - One process lock (internal/local/runlock) covers the entire run; a second
//     concurrent run fails fast with runlock.ErrBusy and performs no work.
//   - The server-driven grant sync runs before any local scanning, inside the
//     same lock: a bound device fetches its authoritative grant view with its
//     own credentials (so the server can pause, narrow, widen or re-enable
//     tools), applies managed default-directory grants for newly confirmed
//     tools, and fails closed when a previously active grant protocol cannot
//     be refreshed. An unbound device performs no network at all.
//   - Collection only reads inputs explicitly granted by the user or added as
//     managed built-in default-directory grants by the grant sync; there is no
//     other default scanning.
//   - The device is never implicitly (re)bound: draining requires an
//     existing bound device, exactly like explicit `toktrail sync`, and the
//     server preflight re-checks fresh consent before every batch.
//   - No secrets appear in command arguments, output, or errors.
//   - A server receipt that rejects records (partially or in full) never
//     reads as full sync success: the drain keeps every accepted record
//     counted and confirmed, counts the rejected ones explicitly, and the
//     run fails with ErrRecordsRejected instead of returning nil.
package collection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/cursoroutbox"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncbudget"
	synccmd "toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// DefaultMaxParallelScans bounds how many granted sources a collection round
// reads and parses at the same time. Parsing dominates a first scan and is
// read-only; filtering and commits stay serialized, so this only overlaps
// work that cannot race. Three covers the three bundled local sources without
// letting a device with many grants multiply peak memory.
const DefaultMaxParallelScans = 3

// DefaultMaxSyncBatches bounds one periodic run's drain so a large backlog
// cannot make a scheduled task run unbounded; the next scheduled run
// continues where this one stopped.
const DefaultMaxSyncBatches = 5

// DefaultSharedPOSTBudget is the §6.2 default run-wide cap on real ingest
// POST attempts a periodic run may make across every active queue (the
// device outbox drain and the account cursor uploads). The periodic CLI
// arms it whenever the caller passes neither an explicit --max-batches
// nor a positive --max-total-batches; the fair drain then empties the
// queues bounded by this shared total instead of the historical
// per-queue bound.
const DefaultSharedPOSTBudget = 100

// DefaultSharedPOSTWindow is the §6.2 default time bound of that shared
// budget, measured from the start of the periodic run: once it elapses,
// every further reserve declines with syncbudget.ErrDeadlineExceeded and
// a run with work left reports itself incomplete instead of running on.
//
// The window also bounds the run context (main.go wires the same value),
// so it covers the local source scan as well as the uploads. That is why
// it is deliberately far above the old two minutes: a real history
// directory produced a scan that could not finish in 120s, and an expired
// window aborted the run before any export commit, leaving the next run
// to repeat the same work. The window must therefore be large enough for
// a real scan to reach its first export commit; a run that still cannot
// finish reports its incomplete state and is continued by the next tick.
// The value stays a finite guard against a pathological run (a hung
// source, endless retries) and below the default 30-minute schedule
// interval, so one run never collides with the next tick's lock.
const DefaultSharedPOSTWindow = 20 * time.Minute

// ErrRecordsRejected reports a settled-but-incomplete upload: a drained
// batch's server receipt counted rejected records even though the upload
// round itself succeeded (synccmd.Run returned nil). By that point the
// syncclient has already reconciled the receipt durably — accepted records
// are confirmed with their baselines advanced and the batch is marked
// synced in the outbox — so the accepted part of the run is real and stays
// counted in Result. The rejected part means the run is NOT a full sync
// success: Run returns this sentinel (wrapped with the counts) instead of
// a nil error, and the rejected records are settled per record (they are
// never blindly resent as-is).
var ErrRecordsRejected = errors.New("records_rejected")

// ErrToolStatusReport reports a failed per-tool status report that
// followed an ALREADY-confirmed batch upload: by the time the report
// runs, the syncclient has settled the upload durably (the receipt is
// reconciled, accepted records keep their advanced baselines and the
// batch is marked synced in the outbox), so Result's confirmed counts
// and the drain's recounted pending state stay valid — only the status
// metadata round failed. Run returns this sentinel wrapping the
// underlying error (the cause stays matchable through errors.Is/Unwrap)
// instead of a nil error: a report failure after real confirmed work
// must never read as full sync success.
var ErrToolStatusReport = errors.New("tool_status_report")

// isBudgetDecline reports whether err is a shared run-budget decline
// (internal/syncbudget): the attempt was stopped BEFORE its ingest POST,
// so nothing was sent, acknowledged or dropped — the batch stays pending
// and this run may not upload anything more in any queue. Every other
// error keeps its original meaning (a real upload failure, an
// authorization stop, a context cancellation); only these sentinels turn
// the run into a budget-incomplete stop.
func isBudgetDecline(err error) bool {
	return err != nil && (errors.Is(err, syncbudget.ErrTotalExhausted) ||
		errors.Is(err, syncbudget.ErrQueueExhausted) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded))
}

type Options struct {
	StateDir   string
	ServerURL  string
	MaxBatches int
	// MaxParallelScans bounds how many granted sources are read and parsed
	// concurrently. Filtering (which may rewrite the quarantine store) and
	// every export commit stay serialized in grant order, so this only
	// overlaps the parsing work. 0 and 1 both mean "one source at a time",
	// the historical behavior.
	MaxParallelScans int
	HTTPClient       *http.Client
	// Budget, when set, limits actual device ingest POST attempts shared
	// with other queues in the run.
	Budget *syncbudget.Budget
	// Retry, when set, opts this run's device outbox drain into the
	// bounded retry policy (internal/syncretry): each pending batch's
	// send runs under the policy INSIDE syncclient (one retry loop per
	// POST, never an outer queue-level wrapper), re-running the durable
	// attempt accounting, the fresh self preflight, the scope gate and
	// the privacy gate on every attempt, resending the same batch ID
	// with the same immutable bytes, and reserving the shared Budget
	// again before every real POST — a decline stays a final plain
	// error that stops the loop without waiting. Callers that also run
	// the account cursor source should wire the SAME policy into
	// Options.Cursor.Retry so one run retries every queue under one
	// deadline; this field never propagates there by itself. Nil (the
	// default, and every explicit CLI entry like `toktrail sync`) keeps
	// the historical single-attempt behavior exactly.
	Retry *syncretry.Policy
	// FairDrain switches the run to the §6.2 drain shape. The scan/pull
	// phases stay exactly once per run (the grant scan loop below; the
	// cursor round pulls the upstream once, its own internal drains
	// capped at a single batch so the rotation governs the upload
	// order). The per-queue MaxBatches bound is then IGNORED for the
	// device drain: after the scan the run keeps holding the state lock
	// and drains the device outbox and the cursor queue in strict fair
	// rotation — one batch per queue per turn — until both queues are
	// exhausted, a full turn makes no progress, the context is
	// cancelled, or the shared budget declines (surfaced as the run
	// error so the caller reports an incomplete run; the declined
	// batches were never POSTed and stay pending). A queue that stops
	// early (server pause, a moved fence, a non-budget failure) is
	// skipped for the rest of the run while the other keeps draining,
	// and its known pending count is preserved on the result so a
	// skipped queue never reads as an empty one. False (the default)
	// keeps the historical bounded semantics exactly as before,
	// including for connect's locked rounds.
	FairDrain bool
	// HomeDir overrides the user home directory used to resolve built-in
	// tool default directories during the grant sync (tests).
	HomeDir string
	// CollectorVersion is the build-injected release version. It is
	// forwarded to the grant ack only when it is a strict SemVer release
	// string; "dev" and unknown values are omitted, never faked.
	CollectorVersion string
	// Now is injectable for deterministic batch ids in tests.
	Now func() time.Time
	// Cursor, when non-nil, runs the account-level Cursor source sync
	// inside the same runlock, under the same server grant policy, after
	// the grant sync and before the local-grant collection. Nil keeps the
	// periodic behavior exactly as before. The cursor sync is independent
	// of local file grants: a cursor-only device (no enabled local
	// grants) still syncs its account source.
	Cursor *cursorsync.Options
	// CursorDrainOnly runs the cursor round as a drain-only round: it
	// refreshes the server view (authorization, fence, source state) and
	// uploads already-persisted cursor batches, but never reads the
	// Cursor credential and never pulls upstream usage. It exists for the
	// first-connect flow, whose setup already performed the source's
	// FIRST pull (cursorsync.Enable runs the first sync immediately after
	// enabling): pulling again in the initial collection round would only
	// re-fetch the window the enable just covered. The persisted queue
	// still drains — under the same runlock, the same server preflight
	// and the same shared budget — so a backlog the enable's bounded
	// first sync left behind keeps flowing, and a budget decline still
	// stops the run honestly. It only takes effect when Cursor is
	// non-nil; false (the default) keeps the full round (preflight,
	// drain, credential, pull, persist, drain) exactly as before.
	CursorDrainOnly bool
	// CaptureSyncedBatchIDs makes the run capture the device outbox's
	// synced-batch ids at the §6.3 snapshot point — immediately after
	// the server-driven grant sync succeeds and BEFORE any source
	// scanning or upload of this round (the cursor phase, the grant scan
	// loop and the device drain below all come after it) — and expose
	// them on Result.SyncedBatchIDs. The capture happens under the
	// round's state lock, so it freezes the synced history exactly as
	// this run's authorization refresh found it; the caller (connect)
	// uses it to restrict the history retransmission to the pre-run
	// synced archive, so this run's own uploads are never immediately
	// replayed. Note the scope: this is the DEVICE outbox only. An
	// account source enabled earlier in connect's setup (under the same
	// continuous lock, but before this round) uploads through its own
	// source-batch queue and never enters the device outbox, so it is
	// deliberately outside this snapshot's universe.
	CaptureSyncedBatchIDs bool
	// Progress receives low-cardinality timing/progress events. Nil preserves
	// the historical behavior with no extra output or side effects. When
	// non-nil the events are serialized (never invoked concurrently) but
	// may originate from the heartbeat goroutine the round's emitter owns.
	Progress func(ProgressEvent)
	// RefreshDrainGrants refreshes managed authorization before and after a
	// drain-only pass so callers can detect a scope change without rescanning.
	RefreshDrainGrants bool
	// SkipDeviceDrain only refreshes grants and counts pending device batches.
	SkipDeviceDrain bool

	// probeDefaultInput overrides the default-directory probe
	// (defaultInputMissing) for in-package tests: nil (production and
	// every external caller) probes the real filesystem. It exists so
	// the fail-closed probe classification — anything other than
	// os.ErrNotExist fails the grant sync instead of masquerading as a
	// never-installed tool — can be exercised with a deterministic
	// injected error on every platform: chmod-based unreadable
	// directories do not exist on Windows and are bypassed under root.
	// Unexported on purpose: not part of the public API, and per-instance
	// so concurrent tests cannot interfere.
	probeDefaultInput func(path string) (bool, error)

	// emitter, when non-nil, is reused as this round's progress emitter
	// instead of constructing one from Progress: the caller (connect's
	// backlog passes) owns its lifecycle and its single deferred Stop, so
	// no two heartbeat tickers ever overlap. Attach it through
	// Options.WithProgressEmitter.
	emitter *ProgressEmitter
	// progressTicks overrides the heartbeat tick source and progressNow
	// the observation clock for in-package tests (deterministic
	// heartbeats and ages without sleeping; the business Now is never
	// consulted for progress).
	progressTicks <-chan time.Time
	progressNow   func() time.Time
	// runStarted records when this round began; the batch-event origins
	// label outbox entries created at or after it as fresh exports. It
	// is set internally by the round entry points.
	runStarted time.Time
}

// GrantOutcome reports what one granted source produced locally.
type GrantOutcome struct {
	Source   string
	Input    string
	Exported bool
	BatchID  string
	Records  int
	// Skipped carries a human-readable reason when this grant produced no
	// batch (no new records, disabled, or unreadable input).
	Skipped string
	// Code is the structured twin of Skipped (and of the exported
	// case): a closed GrantSkipCode assigned at every assignment site
	// of Skipped, so the §6.5 summary classifies from structure and
	// never matches message text. Empty only on a zero-valued outcome.
	Code GrantSkipCode
}

type Result struct {
	// Grants is the number of enabled grants considered.
	Grants int
	// GrantOutcomes mirrors the enabled grants in config order.
	GrantOutcomes []GrantOutcome
	// NoGrants is true when the run found no enabled grants: no local
	// source is scanned (the grant-protocol self fetch still happens for
	// a bound device so the server can enable tools again). The device
	// outbox drain still runs (§6.1): already-pending batches keep
	// uploading under the live server consent, so NoGrants does NOT
	// imply nothing was uploaded — check SyncedBatches /
	// PendingRemaining; Skipped carries the historical "nothing to
	// collect" wording only when the drained queue is actually empty.
	NoGrants bool
	// Skipped carries the reason the run was a no-op (no grants, server
	// pause, or lock content). Empty when work was attempted.
	Skipped string
	// GrantSync reports the server-driven grant authorization sync that
	// ran before any local scanning.
	GrantSync GrantSync
	// Cursor reports the account-level cursor source round (zeroed when
	// the cursor wiring is absent).
	Cursor cursorsync.Result

	ExportedBatches int
	ExportedRecords int

	SyncedBatches int
	SyncedRecords int
	// AttemptedBatches counts device outbox batch attempts, including attempts
	// that trigger scope reorganization without producing a receipt.
	AttemptedBatches int
	syncedTools      map[string]bool
	// RejectedBatches counts drained batches whose server receipt
	// reported at least one rejected record. Those batches are terminal
	// (the syncclient already reconciled the receipt: accepted records
	// confirmed, batch marked synced), so they are also counted in
	// SyncedBatches; the rejected part is carried separately here so it
	// can never silently read as accepted data.
	RejectedBatches int
	// RejectedRecords counts records the server rejected across drained
	// batches this run. Non-zero means the run is not a complete sync
	// even though every upload round itself succeeded; Run surfaces
	// ErrRecordsRejected alongside the accepted counts.
	RejectedRecords int
	// Recovered counts quarantine records re-pended during the drain.
	Recovered int
	// Quarantined counts records currently in the quarantine store after
	// the drain finished.
	Quarantined int
	// PendingRemaining counts outbox batches still pending after the
	// bounded drain.
	PendingRemaining int
	// SyncedBatchIDs lists the device outbox batches that were already
	// synced when this run started, captured at the §6.3 snapshot point
	// (after the grant sync, before any scan or upload of this round,
	// under the round's state lock). It is only populated when
	// Options.CaptureSyncedBatchIDs is set; an empty non-nil-capacity
	// slice means nothing was synced yet (a first install). Callers use
	// it to scope a history retransmission to the pre-run archive.
	SyncedBatchIDs []string
	// DrainStopped is set when the drain stopped early (batch bound reached
	// or an upload failed) while batches were still pending.
	DrainStopped string
	// DrainStop is the structured twin of DrainStopped: a closed
	// DrainStopCode assigned at every DrainStopped site, so the §6.5
	// summary classifies the stop from structure and never matches
	// message text. The round initializes it to DrainStopNotRun and
	// clears it when the drain phase starts, so every pre-drain exit
	// (an authorization pause, a scan failure, an early error) reports
	// an honestly not-run drain.
	DrainStop DrainStopCode
	// PendingCounted reports whether PendingRemaining is a real
	// measurement of the device outbox (a successful count). It is set
	// ONLY where a count actually succeeded — never at a phase entry —
	// so an uncounted queue reports observed=false in the §6.5 summary
	// instead of implying that zero means empty.
	PendingCounted bool
}

// Run performs one periodic collection cycle. It acquires the process lock
// for the entire run (export + drain), so the caller must not already hold
// the state lock; a caller that does must hand the lock to RunLocked
// instead (connect bridges its setup lock that way, with no releasing gap
// between its setup and the initial collection round).
//
// Shared upload budget: when Options.Budget (and, for the account source,
// Options.Cursor.Budget — the CLI wires both to the same run-wide pool)
// is set and declines an attempt before its ingest POST, the run stops
// and returns the decline wrapped in the syncbudget sentinel. The
// declined batches are never POSTed and stay pending; the caller reports
// the run as incomplete (non-zero exit) and the next run resumes the
// backlog. A budget decline is the ONLY cursor-round failure that fails
// the whole run; every other cursor failure keeps the historical
// non-fatal recording in Result.Cursor.
//
// Cursor round shape: by default the account-source round is the full
// cursorsync.Sync (preflight, drain, credential, pull, persist, drain).
// Options.CursorDrainOnly restricts it to the persisted-queue drain
// (cursorsync.DrainPendingLocked under this run's lock) — no credential
// read, no upstream pull — for callers whose own setup already performed
// the source's first pull (connect's first-time enable).
//
// No local file grants (§6.1): the scan reads nothing (no grant — the
// NoGrants fact and, when the sendable queue is empty, the historical
// skip wording are reported), but the device outbox drain still runs, so
// already-pending batches keep uploading under the live server consent
// preflight instead of hiding behind PendingRemaining=0.
func Run(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	// Lock before anything else: validation, local reads, and any network
	// all happen while this process exclusively owns the state directory.
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()
	return runLocked(ctx, opt, lock)
}

// RunLocked is Run's already-held-lock path: the identical collection
// round WITHOUT acquiring the collector runlock. The caller must hold
// the state lock for opt.StateDir across the whole call and hand it in;
// the handle is verified first (runlock.Lock.Validate: non-nil, not
// closed, bound to this state directory's lock file), so a nil,
// released or foreign lock fails closed before any local-state or
// network work — busy content alone (another process holding the
// directory) can never read as "the caller holds the lock". The caller
// must not close the lock before this call returns and keeps owning the
// release afterwards (Run defers its own; connect's initial-round
// wrapper releases exactly when the round ends). Callers that cannot
// guarantee a held lock must use the self-locking Run. Single-writer
// serialization of the outbox, grant store, quarantine and export-commit
// writes below relies entirely on that caller-held lock.
//
// It exists so connect can bridge the state lock it has held since its
// setup began into the initial collection round with NO releasing gap:
// without it, a scheduled collection task could acquire the lock
// between connect's setup and the initial round — syncing pending
// batches (possibly against a receipt that rejected records) under the
// old authorization — and connect's own round would then mistake the
// already-mutated state for its own clean coverage.
func RunLocked(ctx context.Context, opt Options, lock *runlock.Lock) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	if err := lock.Validate(stateDir); err != nil {
		return Result{}, fmt.Errorf("collection run requires the caller's state lock: %w", err)
	}
	return runLocked(ctx, opt, lock)
}

// runLocked is the collection body both Run and RunLocked funnel into.
// It never acquires or closes the lock: the caller owns it for the whole
// call (Run via Acquire/defer Close; RunLocked's caller by contract).
func runLocked(ctx context.Context, opt Options, lock *runlock.Lock) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	// Force-recollect journal guard, before ANY recovery, grant sync,
	// scan or export: while a reset is in flight, ordinary collection
	// must neither read sources (it would advance baselines under the
	// old epoch) nor export batches (they would be stamped with the old
	// epoch and strand the outbox). Periodic collection offers no
	// bypass; only the recollect driver's own syncclient calls continue,
	// under its journal's request id.
	if err := synccmd.CheckResetJournal(stateDir); err != nil {
		return Result{DrainStop: DrainStopNotRun}, err
	}
	// DrainStop starts as not-run: every exit before the drain phase
	// (an authorization pause, a grant-sync or scan failure, an early
	// error) keeps the honest not-run code; the drain entry below
	// clears it.
	res := Result{DrainStop: DrainStopNotRun}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if opt.FairDrain && opt.Cursor != nil {
		cursor := *opt.Cursor
		if cursor.Budget != nil && cursor.Budget != opt.Budget {
			return res, errors.New("fair drain requires one shared budget for device and cursor queues")
		}
		cursor.Budget = opt.Budget
		opt.Cursor = &cursor
	}
	if opt.FairDrain && opt.Budget == nil && opt.MaxBatches <= 0 {
		opt.MaxBatches = DefaultMaxSyncBatches
	}

	// Batch payloads land in <stateDir>/batches; ensure the directory exists
	// before recovering any pending export transaction or committing new batches.
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		return res, fmt.Errorf("prepare batches dir: %w", err)
	}

	// Finish any pending export transaction left behind by an earlier crash
	// before validating grants or draining outbox, so the uncommitted batch
	// is materialized, registered as pending in outbox, and drained even if
	// all configured grants are currently idle.
	if _, err := exportcommit.Recover(stateDir); err != nil {
		return res, fmt.Errorf("recover pending export transaction: %w", err)
	}

	grantStore := grants.New(stateDir)
	// Persist legacy grants only while holding the same lock as collection.
	// Migration failures stop before scanning inputs or refreshing consent.
	if err := grantStore.MigrateLegacy(); err != nil {
		return res, fmt.Errorf("migrate source grants: %w", err)
	}

	now := opt.Now
	if now == nil {
		now = time.Now
	}
	progress := opt.Progress

	// The round's progress emitter: it serializes every event of the
	// round and owns the heartbeat ticker goroutine. A caller-attached
	// emitter (connect's backlog passes, via WithProgressEmitter) is
	// reused as-is — its owner keeps the single deferred Stop; otherwise
	// the round constructs and stops its own. A nil Progress keeps
	// everything exactly as before: no emitter, no goroutine, no output,
	// and no extra clock or file IO of any kind.
	var emitter *ProgressEmitter
	if progress != nil || opt.emitter != nil {
		switch {
		case opt.emitter != nil:
			emitter = opt.emitter
		case opt.progressTicks != nil:
			emitter = newProgressEmitterWithTicks(ctx, progress, opt.progressTicks, opt.progressNow)
			defer emitter.Stop()
		default:
			emitter = NewProgressEmitter(ctx, progress, DefaultProgressHeartbeat)
			defer emitter.Stop()
		}
		opt.emitter = emitter
		progress = emitter.Dispatch
		// runStarted backs the account round's provable-backlog check —
		// read from the OBSERVATION clock, never the business Options.Now
		// (whose call count must not change when progress is enabled).
		opt.runStarted = emitter.obsNow()
	}

	// Server-driven grant sync: refresh the authoritative device grant view
	// with the device's own credentials BEFORE any local scanning, inside
	// the same runlock. It applies managed default-directory grants for
	// newly confirmed tools, enforces pause/narrowing for this run's reads,
	// and fails closed when a previously active grant protocol cannot be
	// refreshed. It never re-runs connect or bind and never touches device
	// identity, progress, or the outbox.
	grantStart, grantWall := startProgress(progress, "grant_sync", "", "")
	emitter.EnterStage("grant_sync")
	grantSync, policy, err := syncGrants(ctx, opt, stateDir, grantStore, now)
	endProgress(progress, "grant_sync", "", "", grantStart, grantWall, err, ProgressEvent{})
	if err != nil {
		return res, err
	}
	res.GrantSync = grantSync

	// §6.3 snapshot point: capture the synced-batch ids of the DEVICE
	// outbox now — after the authorization refresh succeeded and before
	// this round's cursor phase, source scanning or any upload (all of
	// which come after this line) — still under the round's state lock.
	// Scope caveat: an account source first-enabled earlier in connect's
	// setup (under the same continuous lock, before this round) uploads
	// through its own source-batch queue under the enable's own fresh
	// server preflight; it never writes the device outbox, so it is
	// deliberately outside this snapshot's universe — the snapshot
	// freezes exactly the device-outbox history this run's collection
	// and backlog phases may add to.
	if opt.CaptureSyncedBatchIDs {
		ids, idsErr := syncedBatchIDsUnderLock(stateDir)
		if idsErr != nil {
			return res, idsErr
		}
		res.SyncedBatchIDs = ids
	}

	// Report per-tool restriction states through the existing tool-status
	// channel so the server's device view can distinguish "last confirmed"
	// from "currently applied": a tool whose default directory vanished or
	// whose grant the user disabled must not silently ride an old ack.
	// Best-effort: a failure here never blocks collection.
	if len(grantSync.Pending) > 0 && !grantSync.Paused {
		// Retry also covers this run's tool-status metadata reports
		// (grant restrictions, cursor receipts, per-batch "synced"
		// statuses): the same policy retries their transient preflight
		// and POST failures inside syncclient. Metadata attempts never
		// consume the ingest Budget — that counts ingest POSTs only —
		// but they stay governed by the run's context deadline.
		if statuses := pendingToolStatuses(grantSync.Pending); len(statuses) > 0 {
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient, Retry: opt.Retry, ToolStatuses: statuses}); err != nil {
				if !errors.Is(err, synccmd.ErrDevicePaused) && grantSync.Note == "" {
					grantSync.Note = fmt.Sprintf("restricted-tool status report failed: %v", err)
					res.GrantSync = grantSync
				}
			}
		}
	}

	if policy.Paused {
		res.Skipped = fmt.Sprintf("server reports collection paused for this device (consent revision %d); no local reading or uploads this run", grantSync.ConsentRevision)
		return res, nil
	}

	// Account-level cursor source: runs under the same lock and server
	// grant policy, independent of local file grants (a cursor-only
	// device has no local grants but still syncs). Failures are
	// non-fatal for the local tools: they are recorded and surfaced,
	// never allowed to block the device-batch collection or drain.
	// The one deliberate exception is a shared-budget decline: it means
	// this run may upload nothing more in ANY queue, so the run cannot
	// finish its remaining work and must surface the decline instead of
	// reporting success — a cursor-only device would otherwise read as a
	// complete exit while its account queue still holds the declined,
	// never-POSTed batches.
	//
	// CursorDrainOnly switches the round to cursorsync.DrainPendingLocked
	// (under this run's own lock): the same authorization preflight and
	// the same persisted-queue upload, but no credential read and no
	// upstream pull. The first-connect flow sets it after its setup
	// enable already pulled the authorized window once.
	var cursorBudgetErr error
	// gate is the grant sync's effective policy overlay for the cursor
	// round(s): the pull phase below and every rotation step of the fair
	// drain apply the same server-driven scope (pause, allowed tools,
	// history window).
	gate := cursorsync.Gate{
		Paused:       policy.Paused,
		AllowedTools: policy.AllowedTools,
		HistoryFrom:  policy.HistoryFrom,
	}
	if opt.Cursor != nil {
		// Account-queue batch events: the per-phase adapter dispatches
		// into this round's emitter and folds the drain counters. The
		// origin label reflects the round's locally-known provenance (a
		// drain-only round cannot correlate events to entries
		// positionally, so it reports unknown).
		if emitter != nil {
			cursor := *opt.Cursor
			cursor.Progress = CursorProgressEvents(emitter, cursorRoundOrigin(stateDir, opt.CursorDrainOnly, opt.runStarted))
			opt.Cursor = &cursor
			emitter.SetCursorInScope(true)
		}
		cursorStart, cursorWall := startProgress(progress, "cursor_sync", "", "")
		emitter.EnterStage("cursor_sync")
		var cursorRes cursorsync.Result
		var cursorErr error
		if opt.FairDrain {
			// §6.2 pull phase: the account upstream is pulled exactly
			// once per run. The round's own internal drains are capped
			// at ONE batch (the smallest bound cursorsync.Options
			// allows) so the fair rotation after the scan governs the
			// upload order; a shared-budget decline still stops this
			// round before its credential read and pull. The rotation
			// enforces the per-queue bound (Options.MaxBatches, when
			// positive) across the pull phase's upload and its own
			// steps together.
			phaseOpt := *opt.Cursor
			phaseOpt.MaxBatches = 1
			if opt.CursorDrainOnly {
				cursorRes, cursorErr = cursorsync.DrainPendingLocked(ctx, phaseOpt, gate, lock)
			} else {
				cursorRes, cursorErr = cursorsync.Sync(ctx, phaseOpt, gate)
			}
		} else if opt.CursorDrainOnly {
			cursorRes, cursorErr = cursorsync.DrainPendingLocked(ctx, *opt.Cursor, gate, lock)
		} else {
			cursorRes, cursorErr = cursorsync.Sync(ctx, *opt.Cursor, gate)
		}
		endProgress(progress, "cursor_sync", "", "", cursorStart, cursorWall, cursorErr, ProgressEvent{
			ExportedBatches:  cursorRes.ExportedBatches,
			SyncedBatches:    cursorRes.SyncedBatches,
			SyncedRecords:    cursorRes.SyncedRecords,
			PendingRemaining: cursorRes.PendingRemaining,
		})
		if cursorErr != nil {
			if cursorRes.Skipped == "" {
				cursorRes.Skipped = cursorErr.Error()
			} else {
				cursorRes.Note = cursorRes.Note + "; " + cursorErr.Error()
			}
			// Belt-and-suspenders: every error exit of Sync and
			// DrainPendingLocked already sets its structured outcome, but
			// a future exit path that forgets must never read as a clean
			// round — an error is always at least RoundError.
			if cursorRes.Outcome == cursorsync.RoundAbsent {
				cursorRes.Outcome = cursorsync.RoundError
			}
		}
		res.Cursor = cursorRes
		if err := ctx.Err(); err != nil {
			return res, err
		}
		// Remember a shared-budget decline for the run epilogue: the
		// declined batch was never POSTed and stays pending, so the run
		// stays incomplete even when every later stage succeeds. In the
		// fair drain this is the pull-phase decline; a decline during
		// the rotation itself is returned directly by rotateQueues, so
		// neither flavor can be swallowed into a success exit.
		if isBudgetDecline(cursorErr) {
			cursorBudgetErr = cursorErr
		}
		// Tool-status receipt for the account-level source. A cursor-only
		// device has no local grant outcome, so without this report its
		// first successful round would never produce a "connected"
		// receipt on the server. It is sent ONLY for a fully successful,
		// fully drained round — no error, ran, nothing skipped or noted,
		// nothing pending — so failures, pauses, fence/consent stops and
		// undrained backlogs are never dressed up as success. The report
		// rides the existing tool-status channel (fresh consent preflight
		// and fixed detail vocabulary). A report failure never blocks the
		// local tools; it is surfaced as a note on the cursor round.
		//
		// In the fair drain this is deferred: the cursor queue is only
		// fully drained by the rotation after the scan, so the receipt is
		// evaluated on the aggregated result after rotateQueues below.
		if !opt.FairDrain && cursorErr == nil && cursorRes.Ran && cursorRes.Skipped == "" &&
			cursorRes.Note == "" && cursorRes.PendingRemaining == 0 {
			status, detail := "synced", ""
			if cursorRes.SyncedBatches == 0 {
				status, detail = "no_new_records", "no new records since last confirmed baseline"
			}
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{
				StateDir:     stateDir,
				ServerURL:    opt.ServerURL,
				HTTPClient:   opt.HTTPClient,
				Retry:        opt.Retry,
				ToolStatuses: []synccmd.ToolStatus{{Tool: cursorsource.ToolName, Status: status, Detail: detail}},
			}); err != nil && !errors.Is(err, synccmd.ErrDevicePaused) {
				// Note is empty on this path by construction.
				cursorRes.Note = fmt.Sprintf("cursor tool-status report failed: %v", err)
				res.Cursor = cursorRes
			}
		}
	}

	// (Re)load grants after the sync: newly confirmed tools may have gained
	// managed default-directory grants that this run must already collect.
	enabledGrants, err := grantStore.Enabled()
	if err != nil {
		return res, err
	}
	res.Grants = len(enabledGrants)
	// A cursor-only device (no local file grants) with a round that ran
	// or a live permit is NOT a no-op: its outcome lives in res.Cursor,
	// so it must not be reported as NoGrants/"nothing to collect".
	noLocalGrants := len(enabledGrants) == 0
	cursorOutcomeVisible := opt.Cursor != nil && (res.Cursor.Ran || res.Cursor.Status != "")
	if noLocalGrants && !cursorOutcomeVisible {
		res.NoGrants = true
	}
	// §6.1: with no enabled local file grants nothing may be SCANNED —
	// local reading requires an explicit grant, and the scan loop below
	// iterates zero grants — but the device outbox may still hold
	// batches earlier runs exported. The drain therefore still runs
	// (fall through, no early return): a grant-less or cursor-only
	// device empties its sendable queue instead of hiding the backlog
	// behind PendingRemaining=0. Sending stays gated exactly as before —
	// synccmd.Run re-checks fresh server consent before every upload —
	// and a cursor-round budget decline still fails the run through the
	// cursorBudgetErr return at the end. The NoGrants fact is reported
	// either way; the "nothing to collect" skip wording is only attached
	// when the drained queue is actually empty (see below), so a run
	// that uploaded or still holds pending batches never reads as a
	// no-op.

	var historyFrom *time.Time
	if policy.Active {
		// The server-confirmed effective cutoff governs (it may widen or
		// narrow); the bind-time cutoff must not permanently cap it.
		historyFrom = policy.HistoryFrom
	} else if devState, err := statedir.New(stateDir).Load(); err == nil && devState.HistoryFrom != nil && !devState.HistoryFrom.IsZero() {
		historyFrom = devState.HistoryFrom
	}

	// Scan preparation runs in two stages so the expensive parsing can
	// overlap without touching shared state:
	//   1. classify the grants, then read+parse the eligible ones
	//      concurrently (pipeline.LoadSource is read-only);
	//   2. filter, commit and record each grant strictly in grant order
	//      (filtering may rewrite the quarantine store, and commits must
	//      stay deterministic).
	// A single eligible grant, or MaxParallelScans<=1, keeps the original
	// one-at-a-time path exactly.
	type scanItem struct {
		grant    grants.Grant
		output   string
		batchID  string
		outcome  GrantOutcome
		eligible bool
		loaded   adapter.LoadResult
		loadErr  error
	}
	items := make([]scanItem, len(enabledGrants))
	var eligibleIdx []int
	for idx, grant := range enabledGrants {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("collection stopped before source scan: %w", err)
		}
		item := scanItem{grant: grant, outcome: GrantOutcome{Source: grant.Source, Input: grant.Input}}
		if !policy.SourceAllowed(grant.Source) {
			item.outcome.Skipped = "source not allowed by the server grant scope for this device"
			item.outcome.Code = GrantNotAllowed
			items[idx] = item
			continue
		}
		// Re-validate the granted input before reading it: the filesystem
		// may have changed since the grant was recorded. A missing input
		// skips that grant without failing the whole run.
		if err := grants.ValidateInput(grant.Input); err != nil {
			item.outcome.Skipped = fmt.Sprintf("input not accessible: %v", err)
			item.outcome.Code = GrantInputInaccessible
			items[idx] = item
			continue
		}
		batchID, berr := newBatchID(now, idx)
		if berr != nil {
			return res, berr
		}
		item.batchID = batchID
		item.output = filepath.Join(stateDir, "batches", batchID+".json")
		item.eligible = true
		items[idx] = item
		eligibleIdx = append(eligibleIdx, idx)
	}
	// One recovery for the whole scan: adapters read the message baselines
	// and the quarantine store, so a half-applied filter transaction must be
	// completed before any of them loads.
	if err := pipeline.RecoverPendingFilter(stateDir); err != nil {
		return res, err
	}
	parallel := opt.MaxParallelScans > 1 && len(eligibleIdx) > 1
	if parallel {
		emitter.EnterStage("source_scan")
		width := opt.MaxParallelScans
		if width > len(eligibleIdx) {
			width = len(eligibleIdx)
		}
		sem := make(chan struct{}, width)
		var wg sync.WaitGroup
		for _, idx := range eligibleIdx {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					items[idx].loadErr = ctx.Err()
					return
				}
				defer func() { <-sem }()
				items[idx].loaded, items[idx].loadErr = pipeline.LoadSource(adapter.Options{
					Context:  ctx,
					Source:   items[idx].grant.Source,
					Input:    items[idx].grant.Input,
					StateDir: stateDir,
				})
			}(idx)
		}
		wg.Wait()
	}

	for idx := range items {
		item := &items[idx]
		grant := item.grant
		if !item.eligible {
			res.GrantOutcomes = append(res.GrantOutcomes, item.outcome)
			continue
		}
		outcome := item.outcome
		sourceStart, sourceWall := startProgress(progress, "source_scan", grant.Source, grant.Input)
		emitter.EnterStage("source_scan")
		var prepared pipeline.PreparedExport
		var err error
		if parallel {
			err = item.loadErr
			if err == nil {
				prepared, err = pipeline.PrepareFromLoaded(adapter.Options{
					Context:     ctx,
					Source:      grant.Source,
					Input:       grant.Input,
					Output:      item.output,
					BatchID:     item.batchID,
					StateDir:    stateDir,
					HistoryFrom: historyFrom,
				}, item.loaded)
			}
		} else {
			prepared, err = pipeline.PrepareExport(adapter.Options{
				Context:     ctx,
				Source:      grant.Source,
				Input:       grant.Input,
				Output:      item.output,
				BatchID:     item.batchID,
				StateDir:    stateDir,
				HistoryFrom: historyFrom,
			})
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
				return res, fmt.Errorf("collection stopped during source scan: %w", err)
			}
			outcome.Skipped = fmt.Sprintf("export preparation failed: %v", err)
			outcome.Code = GrantExportFailed
			endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		if prepared.Records == 0 {
			outcome.Skipped = "no new records since the last confirmed baselines"
			outcome.Code = GrantNoNewRecords
			// Nothing was exported because nothing new exists: every
			// considered file is either unchanged since its records were
			// committed or yields no records at all, so recording the
			// observed states is safe and lets the next scan skip them.
			if err := saveScanStates(stateDir, grant.Source, prepared.ScanStates); err != nil {
				endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
				return res, fmt.Errorf("save scan state for source %s: %w", grant.Source, err)
			}
			endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, nil, ProgressEvent{})
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		chunks, err := pipeline.SplitPreparedExport(prepared)
		if err != nil {
			outcome.Skipped = fmt.Sprintf("export split failed: %v", err)
			outcome.Code = GrantSplitFailed
			endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
			res.GrantOutcomes = append(res.GrantOutcomes, outcome)
			continue
		}
		for _, chunk := range chunks {
			if err := ctx.Err(); err != nil {
				endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
				return res, fmt.Errorf("collection stopped before export commit: %w", err)
			}
			committed, err := exportcommit.CommitExport(exportcommit.ExportOptions{
				StateDir: stateDir,
				Prepared: chunk,
				Source:   grant.Source,
				Input:    grant.Input,
			})
			if err != nil {
				endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
				return res, fmt.Errorf("commit export for source %s: %w", grant.Source, err)
			}
			// Extend the known-record cache with the batch just written, so
			// the next scan does not have to re-read and re-canonicalise
			// every historical batch file. A failure here is not fatal: the
			// loader validates the cache against the outbox and rebuilds
			// when it does not cover it.
			if payload, rerr := os.ReadFile(committed.Output); rerr == nil {
				_ = knowncache.AppendCommittedBatch(stateDir, grant.Source, committed.BatchID, payload)
			}
			outcome.Exported = true
			outcome.Code = GrantExported
			outcome.BatchID = committed.BatchID
			outcome.Records += committed.Records
			res.ExportedBatches++
			res.ExportedRecords += committed.Records
		}
		// Every record this scan produced is committed now, so the files'
		// content states may be advanced: the next scan skips them until
		// their content changes. Advancing BEFORE the commit would drop
		// records whenever an export failed, so it happens strictly after.
		if err := saveScanStates(stateDir, grant.Source, prepared.ScanStates); err != nil {
			endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, err, ProgressEvent{})
			return res, fmt.Errorf("save scan state for source %s: %w", grant.Source, err)
		}
		endProgress(progress, "source_scan", grant.Source, grant.Input, sourceStart, sourceWall, nil, ProgressEvent{
			ExportedBatches: len(chunks),
			ExportedRecords: outcome.Records,
		})
		res.GrantOutcomes = append(res.GrantOutcomes, outcome)
	}

	drainStart, drainWall := startProgress(progress, "drain", "", "")
	emitter.EnterStage("drain")
	// Drain-boundary queue snapshots (best-effort observation; the
	// drain's own fail-closed pending counts stay with countPending).
	publishDeviceQueue(emitter, stateDir, "drain")
	if opt.Cursor != nil {
		publishCursorQueue(emitter, stateDir, "drain")
	}
	emitter.BeginDrain()
	// The drain phase starts here: clear the constructor's not-run
	// marker. The phase's own stop paths record their codes, and every
	// count below sets PendingCounted only on a successful read.
	res.DrainStop = ""
	var drainErr error
	if opt.FairDrain {
		// §6.2 fair drain: the device outbox and the cursor queue rotate
		// under this run's already-held lock, one batch per queue per
		// turn, until both are exhausted (or their per-queue bounds are
		// reached), a full turn makes no progress, the context is
		// cancelled, or the shared budget declines.
		drainErr = rotateQueues(ctx, &res, opt, gate, lock)
	} else {
		drainErr = drain(ctx, &res, opt)
	}
	endProgress(progress, "drain", "", "", drainStart, drainWall, drainErr, ProgressEvent{
		SyncedBatches:    res.SyncedBatches,
		SyncedRecords:    res.SyncedRecords,
		PendingRemaining: res.PendingRemaining,
	})
	// Post-drain snapshots and one final heartbeat carrying the run's
	// drain counters (rate/ETA only when samples exist).
	publishDeviceQueue(emitter, stateDir, "drain")
	if opt.Cursor != nil {
		publishCursorQueue(emitter, stateDir, "drain")
	}
	emitter.EmitHeartbeatNow()
	if drainErr != nil {
		return res, drainErr
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	// Fair-drain cursor success receipt: with the rotation the cursor
	// queue is only fully drained here, so the receipt (sent ONLY for a
	// fully successful, fully drained round — see the legacy block above)
	// is evaluated on the aggregated result. A pull-phase budget decline
	// (cursorBudgetErr) suppresses it: that run is incomplete.
	if opt.FairDrain && opt.Cursor != nil && cursorBudgetErr == nil &&
		res.Cursor.Ran && res.Cursor.Skipped == "" && res.Cursor.Note == "" &&
		res.Cursor.PendingRemaining == 0 {
		status, detail := "synced", ""
		if res.Cursor.SyncedBatches == 0 {
			status, detail = "no_new_records", "no new records since last confirmed baseline"
		}
		if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{
			StateDir:     stateDir,
			ServerURL:    opt.ServerURL,
			HTTPClient:   opt.HTTPClient,
			Retry:        opt.Retry,
			ToolStatuses: []synccmd.ToolStatus{{Tool: cursorsource.ToolName, Status: status, Detail: detail}},
		}); err != nil && !errors.Is(err, synccmd.ErrDevicePaused) {
			// Note is empty on this path by construction.
			res.Cursor.Note = fmt.Sprintf("cursor tool-status report failed: %v", err)
		}
	}
	if noLocalGrants && !cursorOutcomeVisible && res.SyncedBatches == 0 && res.PendingRemaining == 0 {
		// The grant-less run truly had nothing left to do: the scan had
		// no grant and the sendable queue is empty. Only then is the
		// historical "nothing to collect" skip wording honest. A run
		// that uploaded or still holds pending batches keeps Skipped
		// empty ("empty when work was attempted") while NoGrants above
		// still carries the fact, so callers (the periodic CLI's
		// summary, connect's round report) show the drained counts
		// instead of suppressing them behind a no-op reason.
		res.Skipped = "no enabled source grants; nothing to collect (sources enable requires explicit --source and --input)"
	}
	// Only successful empty scans qualify. Failed reads and undrained usage
	// must not be presented as a completed empty scan.
	if res.PendingRemaining == 0 {
		statuses := []synccmd.ToolStatus{}
		seen := map[string]bool{}
		blocked := map[string]bool{}
		for _, outcome := range res.GrantOutcomes {
			if outcome.Skipped != "no new records since the last confirmed baselines" {
				blocked[toolForSource(outcome.Source)] = true
			}
		}
		for _, outcome := range res.GrantOutcomes {
			if outcome.Skipped != "no new records since the last confirmed baselines" {
				continue
			}
			tool := toolForSource(outcome.Source)
			if tool == "" || seen[tool] || blocked[tool] || res.syncedTools[tool] {
				continue
			}
			seen[tool] = true
			statuses = append(statuses, synccmd.ToolStatus{Tool: tool, Status: "no_new_records", Detail: "no new records since last confirmed baseline"})
		}
		if len(statuses) > 0 {
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(stateDir), synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient, Retry: opt.Retry, ToolStatuses: statuses}); err != nil {
				// A paused device sends no status metadata either; that is
				// a state, not a failure of the run.
				if errors.Is(err, synccmd.ErrDevicePaused) {
					return res, cursorBudgetErr
				}
				return res, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	// §6.5: an account round that failed, drifted or paused never emits
	// the "complete" progress event — the run is not a full success even
	// when it exits zero (a paused round with nothing pending keeps the
	// historical exit but still must not claim completion). The caller's
	// incomplete judgment reads the same structured outcome.
	cursorIncomplete := cursorRoundIncomplete(res.Cursor.Outcome)
	if cursorBudgetErr == nil && !cursorIncomplete && !drainStopSuppressesComplete(res.DrainStop) {
		emitProgress(progress, ProgressEvent{
			Kind:             ProgressCount,
			Stage:            "complete",
			ExportedBatches:  res.ExportedBatches,
			ExportedRecords:  res.ExportedRecords,
			SyncedBatches:    res.SyncedBatches,
			SyncedRecords:    res.SyncedRecords,
			PendingRemaining: res.PendingRemaining,
		})
	}
	// A cursor-round budget decline makes the run incomplete even when
	// every later stage finished cleanly: the account queue still holds
	// the declined (never-POSTed) batches, and no "complete" progress
	// event may claim otherwise. The next run resumes them under its own
	// fresh budget.
	return res, cursorBudgetErr
}

// DrainPending drains already-persisted device outbox batches without scanning
// any local source inputs or refreshing server-managed grants. It is the P1
// building block for separating collection from queue transmission: callers
// can first materialize batches once, then repeatedly call this drain-only path
// to make progress through a backlog. Every upload still goes through
// syncclient's fresh device self preflight and receipt reconciliation.
//
// Single-writer safety: DrainPending acquires the collector runlock
// (internal/local/runlock) itself for the entire round, so a concurrent
// holder fails fast with runlock.ErrBusy before any work. Callers that
// already hold the runlock for the state directory must NOT call this —
// the lock is per open file description, so even a nested acquire from
// the same process fails with ErrBusy; they use DrainPendingLocked,
// which runs the identical round under the caller's own lock.
func DrainPending(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()
	return DrainPendingLocked(ctx, opt, lock)
}

// DrainPendingLocked is DrainPending's already-held-lock path: the identical
// drain-only round WITHOUT acquiring the collector runlock. The caller must
// hold the state lock for opt.StateDir across the whole call and hand it in;
// the handle is verified first (runlock.Lock.Validate: non-nil, not closed,
// bound to this state directory's lock file), so a nil, released or foreign
// lock fails closed before any local-state or network work instead of
// silently running unlocked next to whoever actually holds the directory.
// The caller must not close the lock before this call returns. Callers that
// cannot guarantee a held lock must use the self-locking DrainPending.
// Single-writer serialization of the outbox, grant store and quarantine
// writes below relies entirely on that caller-held lock.
func DrainPendingLocked(ctx context.Context, opt Options, lock *runlock.Lock) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("collector state directory is required")
	}
	if err := lock.Validate(stateDir); err != nil {
		return Result{}, fmt.Errorf("drain-only run requires the caller's state lock: %w", err)
	}
	// Force-recollect journal guard, before the export-transaction
	// recovery, the grant refresh and any upload: a drain during a reset
	// would upload old-epoch batches (the syncclient fence refuses them,
	// but the run should stop before doing the work at all) and could
	// refresh grants against a state the reset is about to swap.
	if err := synccmd.CheckResetJournal(stateDir); err != nil {
		return Result{DrainStop: DrainStopNotRun}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if opt.FairDrain && opt.Budget == nil && opt.MaxBatches <= 0 {
		opt.MaxBatches = DefaultMaxSyncBatches
	}

	// DrainStop starts as not-run (see runLocked); the drain and
	// count-only branches below clear or measure it.
	res := Result{DrainStop: DrainStopNotRun}
	batchesDir := filepath.Join(stateDir, "batches")
	if err := os.MkdirAll(batchesDir, 0o700); err != nil {
		return res, fmt.Errorf("prepare batches dir: %w", err)
	}
	if _, err := exportcommit.Recover(stateDir); err != nil {
		return res, fmt.Errorf("recover pending export transaction: %w", err)
	}
	if opt.RefreshDrainGrants {
		grantStore := grants.New(stateDir)
		if err := grantStore.MigrateLegacy(); err != nil {
			return res, fmt.Errorf("migrate source grants: %w", err)
		}
		now := opt.Now
		if now == nil {
			now = time.Now
		}
		grantSync, policy, err := syncGrants(ctx, opt, stateDir, grantStore, now)
		if err != nil {
			return res, err
		}
		res.GrantSync = grantSync
		if policy.Paused {
			res.PendingRemaining, err = countPending(outbox.New(stateDir))
			if err != nil {
				return res, err
			}
			res.PendingCounted = true
			res.DrainStopped = "server reports collection paused"
			res.DrainStop = DrainStopPaused
			return res, nil
		}
	}

	progress := opt.Progress

	// The drain-only round's emitter, identical in shape to runLocked's:
	// a caller-attached emitter is reused (its owner keeps the single
	// deferred Stop), otherwise the round constructs and stops its own.
	// A nil Progress (and no attached emitter) keeps the historical
	// path: no emitter, no goroutine, no output, and no extra clock or
	// file IO of any kind.
	var emitter *ProgressEmitter
	if progress != nil || opt.emitter != nil {
		switch {
		case opt.emitter != nil:
			emitter = opt.emitter
		case opt.progressTicks != nil:
			emitter = newProgressEmitterWithTicks(ctx, progress, opt.progressTicks, opt.progressNow)
			defer emitter.Stop()
		default:
			emitter = NewProgressEmitter(ctx, progress, DefaultProgressHeartbeat)
			defer emitter.Stop()
		}
		opt.emitter = emitter
		progress = emitter.Dispatch
		// Observation clock only — never the business Options.Now.
		opt.runStarted = emitter.obsNow()
	}

	drainStart, drainWall := startProgress(progress, "drain", "", "")
	emitter.EnterStage("drain")
	// Drain-boundary queue snapshot (best-effort observation; the
	// count-only branch's fail-closed semantics stay with countPending).
	publishDeviceQueue(emitter, stateDir, "drain")
	emitter.BeginDrain()
	var drainErr error
	if opt.SkipDeviceDrain {
		res.PendingRemaining, drainErr = countPending(outbox.New(stateDir))
		if drainErr == nil {
			// The count-only pass measured the queue; the drain itself
			// stays not-run.
			res.PendingCounted = true
		}
		res.DrainStop = DrainStopNotRun
	} else {
		// The drain phase starts here: clear the constructor's not-run
		// marker (the phase's stop paths record their own codes).
		res.DrainStop = ""
		drainErr = drain(ctx, &res, opt)
	}
	endProgress(progress, "drain", "", "", drainStart, drainWall, drainErr, ProgressEvent{
		SyncedBatches:    res.SyncedBatches,
		SyncedRecords:    res.SyncedRecords,
		PendingRemaining: res.PendingRemaining,
	})
	// Post-drain snapshot and one final heartbeat with the round's drain
	// counters (rate/ETA only when samples exist).
	publishDeviceQueue(emitter, stateDir, "drain")
	emitter.EmitHeartbeatNow()
	if drainErr != nil {
		return res, drainErr
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if opt.RefreshDrainGrants {
		now := opt.Now
		if now == nil {
			now = time.Now
		}
		initial := res.GrantSync
		latest, policy, err := syncGrants(ctx, opt, stateDir, grants.New(stateDir), now)
		if err != nil {
			return res, err
		}
		res.GrantSync = latest
		// The second authorization check distinguishes its outcomes
		// structurally: a pause that landed mid-drain is a pause (the
		// batches stay queued), while only an actual revision or
		// active-state drift is a scope change.
		switch {
		case policy.Paused:
			res.DrainStopped = "server reports collection paused"
			res.DrainStop = DrainStopPaused
		case initial.Active && (!latest.Active || initial.ConsentRevision != latest.ConsentRevision):
			res.DrainStopped = "server authorization changed during backlog drain; a new collection is required"
			res.DrainStop = DrainStopScope
		}
	}
	if !drainStopSuppressesComplete(res.DrainStop) {
		emitProgress(progress, ProgressEvent{
			Kind:             ProgressCount,
			Stage:            "complete",
			SyncedBatches:    res.SyncedBatches,
			SyncedRecords:    res.SyncedRecords,
			PendingRemaining: res.PendingRemaining,
		})
	}
	return res, nil
}

// drainStopSuppressesComplete reports whether a recorded drain stop
// must suppress the "complete" progress event: a mid-drain pause or an
// authorization drift means the run did not finish cleanly, so it may
// never claim completion. Bounded stops keep the historical event (the
// exit-zero bounded shape), and the pre-drain early exits never reach
// an emit site.
func drainStopSuppressesComplete(code DrainStopCode) bool {
	return code == DrainStopPaused || code == DrainStopScope
}

func toolForSource(source string) string {
	for _, tool := range registry.SupportedTools() {
		if tool.Source == source {
			return tool.Tool
		}
	}
	return ""
}

// drain uploads pending outbox batches up to the bound and, when the
// pending queue runs empty while the quarantine store still holds records,
// performs one recovery round through the syncclient so records that the
// current authorization allows again are re-pended and drained in the same
// run. The recovery round goes through the normal sync path — bound
// device, fresh server-consent preflight, no ingest POST — so it never
// evaluates the scope locally and never bypasses the server's
// authorization.
//
// Authorization model (the same as the pending-batch drain, plus the
// syncclient's recovery gate): local grants gate READING (which inputs the
// export phase scans), while SENDING is authorized by the server's live
// consent scope, re-checked fresh on every round and enforced again
// server-side at ingest. Quarantine recovery additionally requires an
// enabled local grant for the record's (source, input) once the device has
// a configured grant store — the syncclient enforces that on every
// recovery path, so a grant the user disabled or connect closed keeps its
// quarantined records held even when the server scope would allow them
// again. A device that never configured grants keeps the historical
// grant-agnostic recovery, matching the manual sync path.
//
// Partial receipts: synccmd.Run can succeed (nil error) with a receipt
// that rejected some or all of the batch's records — the syncclient has
// already reconciled such a receipt (accepted records confirmed, rejected
// messages settled per record, batch marked synced), so the drain neither
// retries nor rolls anything back. The accepted part stays counted; the
// rejected part is counted separately and the drain epilogue turns an
// otherwise-clean run into ErrRecordsRejected so a partial or fully
// rejected batch can never be reported as full sync success.
//
// Implementation: drain is the historical bounded loop over the shared
// deviceQueueDrain stepper below; the §6.2 fair rotation (rotateQueues)
// consumes the same stepper one batch per turn, so both shapes keep
// identical per-batch behavior.
func drain(ctx context.Context, res *Result, opt Options) error {
	d := newDeviceQueueDrain(res, opt)
	for d.canStep() {
		if _, err := d.step(ctx); err != nil {
			return err
		}
		if d.finished {
			break
		}
	}
	return d.finish()
}

// deviceQueueDrain holds the per-run state of the device outbox drain:
// the upload bound, the at-most-once quarantine recovery flag and the
// first-rejected-batch diagnosis. Every branch, counter, message and
// error of the original bounded drain loop lives on in step; only the
// loop control moved to the callers (drain's bounded loop, rotateQueues'
// fair rotation).
type deviceQueueDrain struct {
	res      *Result
	opt      Options
	stateDir string
	ledger   outbox.Store
	// bound caps attempted batch uploads per run; <= 0 means unbounded
	// (the §6.2 fair drain without an explicit --max-batches).
	bound             int
	uploads           int
	recoveryAttempted bool
	// firstRejectedBatch remembers the first batch whose receipt carried
	// rejected records, for the epilogue's diagnosis message.
	firstRejectedBatch string
	// finished is set once the queue can make no further progress this
	// run: drained (with nothing recoverable), paused, budget-stopped or
	// failed. A later rotation turn skips a finished queue.
	finished bool
}

// newDeviceQueueDrain derives the drain bound from the options: the fair
// drain ignores the historical default (an unset or non-positive
// MaxBatches means "no per-queue bound"), while a positive MaxBatches
// caps the queue in both shapes; the legacy drain keeps the historical
// DefaultMaxSyncBatches fallback for an unset bound.
func newDeviceQueueDrain(res *Result, opt Options) *deviceQueueDrain {
	stateDir := strings.TrimSpace(opt.StateDir)
	bound := opt.MaxBatches
	switch {
	case opt.FairDrain:
		// positive = explicit per-queue cap; <=0 = unbounded
	case bound <= 0:
		bound = DefaultMaxSyncBatches
	}
	return &deviceQueueDrain{
		res:      res,
		opt:      opt,
		stateDir: stateDir,
		ledger:   outbox.New(stateDir),
		bound:    bound,
	}
}

// recentRecordWindow is how far back a batch's newest record may be for the
// drain to treat it as current. It matches the leaderboard's 30-day view: data
// a user can still see there should not wait behind older history.
const recentRecordWindow = 30 * 24 * time.Hour

// selectPendingBatch chooses the next device batch to upload.
//
// Ordering rules, in priority:
//   - preferOldest forces the globally oldest pending batch (the
//     anti-starvation turn);
//   - otherwise a pending batch whose newest record falls inside
//     recentWindow wins, newest data first;
//   - otherwise the oldest pending batch (the historical order).
//
// Batches written before the record window existed carry no timestamps and
// are therefore never "recent": they keep the historical oldest-first order
// instead of being reordered by a guess.
func selectPendingBatch(entries []outbox.BatchEntry, now time.Time, recentWindow time.Duration, preferOldest bool) (outbox.BatchEntry, bool) {
	var pending []outbox.BatchEntry
	for _, entry := range entries {
		if entry.Status == outbox.StatusPending {
			pending = append(pending, entry)
		}
	}
	if len(pending) == 0 {
		return outbox.BatchEntry{}, false
	}
	oldest := pending[0]
	if preferOldest || recentWindow <= 0 {
		return oldest, true
	}
	var best outbox.BatchEntry
	found := false
	for _, entry := range pending {
		if entry.NewestRecordAt.IsZero() {
			continue
		}
		if now.Sub(entry.NewestRecordAt) > recentWindow {
			continue
		}
		if !found || entry.NewestRecordAt.After(best.NewestRecordAt) {
			best = entry
			found = true
		}
	}
	if found {
		return best, true
	}
	return oldest, true
}

// canStep reports whether the bound still allows another attempted
// upload.
func (d *deviceQueueDrain) canStep() bool {
	return !d.finished && (d.bound <= 0 || d.uploads < d.bound)
}

// nowFn is the round's injectable clock for queue-snapshot ages.
func (d *deviceQueueDrain) nowFn() func() time.Time {
	if d.opt.Now != nil {
		return d.opt.Now
	}
	return time.Now
}

// step drains at most one pending device batch, or performs at most one
// quarantine recovery round when the pending queue runs empty. progressed
// reports whether the queue advanced (a receipt, a completed scope
// reorganization, or a recovery that re-pended records); a no-progress
// step always marks the stepper finished, so no caller can spin on it.
func (d *deviceQueueDrain) step(ctx context.Context) (progressed bool, err error) {
	ledger, err := d.ledger.Load()
	if err != nil {
		return false, err
	}
	// Recent data first, oldest first every fourth upload: a device that
	// rejoins with a large old backlog otherwise keeps today's usage queued
	// behind hundreds of historical batches, while pure newest-first would
	// starve the backlog whenever new data keeps arriving.
	entry, ok := selectPendingBatch(ledger.Batches, d.nowFn()(), recentRecordWindow, d.uploads%4 == 3)
	if !ok {
		entries, qErr := quarantine.New(d.stateDir).Load()
		if qErr != nil {
			return false, qErr
		}
		// No upload is in flight, so the store's current size is the
		// authoritative post-drain quarantine count.
		d.res.Quarantined = len(entries)
		if len(entries) == 0 || d.recoveryAttempted {
			// Nothing pending and nothing (more) recoverable this run:
			// the drain is complete. With an empty quarantine store
			// this path performs no network at all.
			d.finished = true
			return false, nil
		}
		// Empty pending queue but quarantined records: without a round
		// here a device with no new data would never recover them —
		// recovery only runs inside the syncclient, which the drain
		// otherwise calls exclusively while a pending batch exists.
		// Attempted at most once per run: records the fresh snapshot
		// still excludes cannot become recoverable within the same
		// run (recovery requires a strictly newer consent revision
		// and, where grants are configured, an enabled local grant).
		d.recoveryAttempted = true
		// The recovery may re-pend quarantined records: the held queue
		// snapshot can no longer be proven — unknown until the next
		// bounded re-sample.
		d.opt.emitter.InvalidateDeviceQueue()
		// synccmd.Run re-checks device binding and fetches a fresh
		// server-consent snapshot before deciding; it never binds.
		syncResult, err := synccmd.Run(ctx, statedir.New(d.stateDir), synccmd.Options{
			StateDir:   d.stateDir,
			ServerURL:  d.opt.ServerURL,
			HTTPClient: d.opt.HTTPClient,
			Retry:      d.opt.Retry,
		})
		d.res.Recovered += syncResult.Recovered
		if err != nil {
			// A failed round still leaves consistent recovery state
			// (replayed journals apply atomically), so reload the
			// authoritative count instead of trusting either the
			// pre-round snapshot or the zeroed error result.
			count, qErr := quarantineStoreCount(d.stateDir)
			if qErr != nil {
				return false, qErr
			}
			d.res.Quarantined = count
			if errors.Is(err, synccmd.ErrQuarantineHeld) {
				// Quarantined records the current authorization still
				// excludes — the live consent scope, or on a grant-
				// configured device a disabled or closed local
				// (source, input) grant — are a normal steady state,
				// not a run failure: they stay recoverable until the
				// authorization widens again.
				d.finished = true
				return false, nil
			}
			remaining, countErr := countPending(d.ledger)
			if countErr != nil {
				return false, countErr
			}
			d.res.PendingRemaining = remaining
			d.res.PendingCounted = true
			d.res.DrainStopped = fmt.Sprintf("quarantine recovery round failed: %v", err)
			d.res.DrainStop = DrainStopFailed
			d.finished = true
			return false, err
		}
		d.res.Quarantined = syncResult.Quarantined
		if syncResult.Recovered > 0 {
			// The recovered records are pending batches now; the next
			// step drains them.
			return true, nil
		}
		// Defensive: the syncclient only succeeds the recovery round
		// when something was recovered; if that ever changes, finish
		// cleanly instead of spinning.
		d.finished = true
		return false, nil
	}
	// uploads bounds the drain by attempted batch uploads. A quarantine
	// recovery round sends no batch and therefore never consumes an upload
	// slot: a run whose only work is recovery still drains what it
	// recovered, whatever the batch bound is.
	d.uploads++
	d.res.AttemptedBatches++
	// synccmd.Run re-checks device binding and fresh server consent
	// (preflight self GET) before every upload. It never binds. The
	// per-attempt events (preflight/HTTP/ACK timings, payload size,
	// receipt counts behind their Observed/Known gates) flow through
	// this round's emitter; the heartbeat sees the attempt as in flight.
	d.opt.emitter.BeginAttempt(ProgressQueueDevice)
	syncResult, err := synccmd.Run(ctx, statedir.New(d.stateDir), synccmd.Options{
		StateDir:      d.stateDir,
		ServerURL:     d.opt.ServerURL,
		HTTPClient:    d.opt.HTTPClient,
		Budget:        d.opt.Budget,
		BudgetQueue:   "device",
		Retry:         d.opt.Retry,
		PreferBatchID: entry.BatchID,
		Progress:      deviceAttemptEvents(d.opt.emitter, entry.OriginConsentRevision != 0),
	})
	d.opt.emitter.EndAttempt()
	d.res.Recovered += syncResult.Recovered
	d.res.Quarantined = syncResult.Quarantined
	if err != nil {
		if errors.Is(err, synccmd.ErrDevicePaused) {
			// The server paused the device mid-run (between the grant
			// sync and this upload): stop sending, keep every pending
			// batch queued — pause is temporary, never a quarantine.
			remaining, countErr := countPending(d.ledger)
			if countErr != nil {
				return false, countErr
			}
			d.res.PendingRemaining = remaining
			d.res.PendingCounted = true
			d.res.DrainStopped = fmt.Sprintf("server reports collection paused; %d batch(es) stay queued for the next run", remaining)
			d.res.DrainStop = DrainStopPaused
			d.finished = true
			return false, nil
		}
		if isBudgetDecline(err) {
			// The run's shared upload budget declined this attempt
			// BEFORE its ingest POST: the batch was not uploaded and
			// stays pending. Stop the drain with the budget sentinel
			// so the caller reports an incomplete run (never a
			// failed upload and never a quiet bounded stop); the next
			// run, with its own fresh budget, resumes exactly here.
			remaining, countErr := countPending(d.ledger)
			if countErr != nil {
				return false, countErr
			}
			d.res.PendingRemaining = remaining
			d.res.PendingCounted = true
			d.res.DrainStopped = fmt.Sprintf("shared upload budget exhausted with %d batch(es) still pending; the next run continues", remaining)
			d.res.DrainStop = DrainStopBudget
			d.finished = true
			return false, fmt.Errorf("device batch %s was stopped by the shared upload budget before its upload: %w", entry.BatchID, err)
		}
		if errors.Is(err, synccmd.ErrOutsideScope) {
			complete, checkErr := synccmd.ScopeReorganizationComplete(d.stateDir, entry.BatchID)
			if checkErr != nil {
				return false, checkErr
			}
			if complete {
				// The batch settled through the server-side scope
				// reorganization: the queue advanced without a receipt,
				// so the held snapshot is no longer provable.
				d.opt.emitter.InvalidateDeviceQueue()
				return true, nil
			}
		}
		// The failure may have mutated the ledger underneath the held
		// queue snapshot — a scope_changed rejection, for one, has the
		// syncclient complete a durable reorganization before this
		// error ever surfaces here. The failure and exit semantics stay
		// exactly as they were; the snapshot is just conservatively
		// marked unknown (budget declines and pauses returned above
		// without mutating anything), and the drain's closing bounded
		// re-sample restores it.
		d.opt.emitter.InvalidateDeviceQueue()
		remaining, countErr := countPending(d.ledger)
		if countErr != nil {
			return false, countErr
		}
		d.res.PendingRemaining = remaining
		d.res.PendingCounted = true
		d.res.DrainStopped = fmt.Sprintf("upload of batch %s failed: %v", entry.BatchID, err)
		d.res.DrainStop = DrainStopFailed
		d.finished = true
		return false, err
	}
	if syncResult.Receipt.BatchID != "" {
		d.res.SyncedBatches++
		d.res.SyncedRecords += syncResult.Receipt.AcceptedRecords
		// Per-batch queue update (§10 逐批更新): the INCREMENTAL fold —
		// no ledger re-read, no whole-queue stat; a split child or a
		// recovery marks the held snapshot unknown until the next
		// bounded re-sample. The drain counters themselves are folded by
		// the per-attempt adapter, never here.
		d.opt.emitter.ApplyDeviceDrain(d.stateDir, entry, syncResult.Receipt.BatchID, syncResult.Recovered)
		if syncResult.Receipt.RejectedRecords > 0 {
			// A partial or fully rejected receipt with a nil error:
			// the syncclient already reconciled it (accepted records
			// confirmed, batch marked synced), so the accepted part
			// stays counted above and the drain keeps going — later
			// batches must not lose their chance to upload. The
			// rejected part is recorded here and surfaced by the
			// drain epilogue, never as full sync success.
			d.res.RejectedBatches++
			d.res.RejectedRecords += syncResult.Receipt.RejectedRecords
			if d.firstRejectedBatch == "" {
				d.firstRejectedBatch = syncResult.Receipt.BatchID
			}
		}
		if tool := toolForSource(entry.Source); tool != "" && syncResult.Receipt.AcceptedRecords > 0 {
			if d.res.syncedTools == nil {
				d.res.syncedTools = map[string]bool{}
			}
			d.res.syncedTools[tool] = true
			if _, err := synccmd.ReportToolStatuses(ctx, statedir.New(d.stateDir), synccmd.Options{StateDir: d.stateDir, ServerURL: d.opt.ServerURL, HTTPClient: d.opt.HTTPClient, Retry: d.opt.Retry, ToolStatuses: []synccmd.ToolStatus{{Tool: tool, Status: "synced"}}}); err != nil {
				remaining, countErr := countPending(d.ledger)
				if countErr != nil {
					return false, countErr
				}
				d.res.PendingRemaining = remaining
				// The recount above really measured the durable queue,
				// so the summary may report it: an uncounted queue here
				// used to render the backlog as "device pending unknown"
				// even though this stop knows the exact count. Every
				// other stop path of this stepper already sets the flag.
				d.res.PendingCounted = true
				d.res.DrainStopped = fmt.Sprintf("source status report failed: %v", err)
				d.res.DrainStop = DrainStopFailed
				d.finished = true
				// The upload itself already succeeded and was confirmed
				// durably (receipt reconciled, batch marked synced); the
				// failure is the metadata report that follows it. The
				// sentinel lets callers classify this stop without
				// trusting the underlying free text, while the wrapped
				// cause keeps every errors.Is match it had.
				return false, fmt.Errorf("%w: source status report after the confirmed upload of device batch %s: %w", ErrToolStatusReport, entry.BatchID, err)
			}
		}
	}
	return true, nil
}

// finish writes the drain epilogue: the authoritative pending count, the
// stop reason for a bounded stop, and — only for an otherwise-clean drain
// — the ErrRecordsRejected sentinel (real errors always win unchanged and
// are returned by step directly).
func (d *deviceQueueDrain) finish() error {
	remaining, err := countPending(d.ledger)
	if err != nil {
		return err
	}
	d.res.PendingRemaining = remaining
	d.res.PendingCounted = true
	if remaining > 0 && d.res.DrainStopped == "" {
		if d.bound > 0 {
			d.res.DrainStopped = fmt.Sprintf("batch bound %d reached with %d batches still pending; the next scheduled run continues", d.bound, remaining)
			d.res.DrainStop = DrainStopBounded
		} else {
			d.res.DrainStopped = fmt.Sprintf("%d batch(es) still pending after the drain stopped; the next run continues", remaining)
			// No code: every real fair-drain stop records its own code
			// above (pause, budget, failure, a scope stop); reaching this
			// defensive branch with pending batches means no specific
			// stop was recorded, which the §6.5 summary reports as the
			// honest "unknown" rather than guessing a cause.
		}
	}
	if d.res.RejectedRecords == 0 {
		return nil
	}
	detail := ""
	if d.firstRejectedBatch != "" {
		detail = fmt.Sprintf(" (first rejected batch: %s)", d.firstRejectedBatch)
	}
	return fmt.Errorf("%w: the server rejected %d record(s) across %d drained batch(es)%s; accepted records were confirmed and kept, rejected records are settled per record and are not resent as-is",
		ErrRecordsRejected, d.res.RejectedRecords, d.res.RejectedBatches, detail)
}

// rotateQueues is the §6.2 fair drain: after the run's single scan/pull
// phase it keeps the caller's state lock and drains the device outbox and
// the account cursor queue in strict rotation — one batch per queue per
// turn, device first — until both queues are exhausted (or reach their
// per-queue bound, when Options.MaxBatches is positive), a full turn
// makes no progress, or the shared budget declines. A budget decline is
// returned as the run error (never swallowed): the declined batch was
// never POSTed and stays pending, so the caller reports an incomplete
// run and the next run resumes. Cancellation and run-context timeouts
// surface through the steps themselves (synccmd.Run's preflight, the
// cursor round's fetchSelf) with the same per-batch error accounting the
// legacy drain has — including the device stepper's pending recount and
// stop reason on a failed upload.
//
// No-progress safety: every no-progress step marks its queue finished
// (empty queue, server pause, a moved fence, a non-budget failure), and
// the loop additionally breaks whenever a full turn makes no progress —
// so a paused or skipped queue can never make the rotation spin. A queue
// that stops early keeps its known pending count: the cursor stepper
// recounts the durable queue on every skip (cursorsync's skip paths do
// not count it themselves), so a skipped queue never reads as an empty
// one while the other queue keeps draining.
//
// The cursor steps run through cursorsync.DrainPendingLocked under THIS
// run's already-held lock (no nested acquisition): each step refreshes
// the server authorization (fetchSelf), re-checks the source fence and
// state, and uploads at most one batch — the same per-batch preflight
// cadence the device path's synccmd.Run performs.
func rotateQueues(ctx context.Context, res *Result, opt Options, gate cursorsync.Gate, lock *runlock.Lock) error {
	dev := newDeviceQueueDrain(res, opt)
	var cur *cursorQueueDrain
	if opt.Cursor != nil {
		one := *opt.Cursor
		one.MaxBatches = 1
		// The rotation drains persisted batches: the conservative
		// round-origin check applies (a pull earlier in this same run
		// created batches, in which case the label is unknown).
		if opt.emitter != nil {
			one.Progress = CursorProgressEvents(opt.emitter, cursorRoundOrigin(opt.StateDir, true, opt.runStarted))
		}
		cur = &cursorQueueDrain{
			opt:     one,
			gate:    gate,
			lock:    lock,
			agg:     &res.Cursor,
			bound:   opt.MaxBatches,
			emitter: opt.emitter,
		}
	}
	for {
		if dev.finished && (cur == nil || cur.finished) {
			break
		}
		progressed := false
		if dev.canStep() {
			p, err := dev.step(ctx)
			if err != nil {
				return err
			}
			progressed = p
		} else {
			dev.finished = true
		}
		if cur != nil && !cur.finished {
			p, err := cur.step(ctx)
			if err != nil {
				// The cursor step stopped the run (a shared-budget
				// decline): the device queue's pending count must still
				// be reported honestly — the device stepper only
				// recounts on its own stops, and a cursor-side stop
				// must never leave the device backlog reading as zero.
				if remaining, countErr := countPending(dev.ledger); countErr == nil {
					res.PendingRemaining = remaining
					res.PendingCounted = true
					if res.DrainStopped == "" && remaining > 0 {
						res.DrainStopped = fmt.Sprintf("the account cursor queue stopped the run with %d device batch(es) still pending; the next run continues", remaining)
						// cur.step returns an error only for a shared
						// budget decline.
						res.DrainStop = DrainStopBudget
					}
				}
				return err
			}
			progressed = progressed || p
		}
		if !progressed {
			break
		}
	}
	return dev.finish()
}

// cursorQueueDrain rotates the account cursor queue one batch per step
// under the run's own lock, aggregating every step into the run's cursor
// result (which starts as the pull phase's result, so its uploads count
// toward the per-queue bound too). bound <= 0 means no per-queue cap.
type cursorQueueDrain struct {
	opt   cursorsync.Options
	gate  cursorsync.Gate
	lock  *runlock.Lock
	agg   *cursorsync.Result
	bound int
	// emitter is the round's progress emitter (nil when no progress):
	// the cursor steps publish in-flight markers and per-step queue
	// snapshots through it.
	emitter *ProgressEmitter
	// finished is set once this queue can make no further progress this
	// run (exhausted, its per-queue bound reached, a skip reason, or a
	// non-budget failure recorded on the aggregate).
	finished bool
}

// canStep reports whether the per-queue bound still allows the cursor
// queue another upload. The bound counts the pull phase's upload too
// (agg.SyncedBatches already includes it).
func (c *cursorQueueDrain) canStep() bool {
	return !c.finished && (c.bound <= 0 || c.agg.SyncedBatches < c.bound)
}

// step drains at most one pending cursor batch through
// cursorsync.DrainPendingLocked. progressed reports whether a batch was
// uploaded; a budget decline is returned as the error (stopping the whole
// run), while every other failure is recorded non-fatally on the
// aggregate — the historical cursor semantics — and finishes this queue.
func (c *cursorQueueDrain) step(ctx context.Context) (bool, error) {
	if !c.canStep() {
		c.finished = true
		if n, err := cursoroutbox.New(c.opt.StateDir).CountPending(); err == nil && n > 0 {
			c.agg.Note = appendCursorNote(c.agg.Note, fmt.Sprintf("cursor upload stopped at the per-queue batch bound %d with %d batch(es) pending; the next run continues", c.bound, n))
			// The run-level per-queue bound stopped the queue with work
			// left: a normal bounded stop (exit-zero compatibility for
			// an explicit --max-batches), never a failure.
			c.agg.Outcome = mergeCursorOutcome(c.agg.Outcome, cursorsync.RoundBounded, true)
		}
		return false, nil
	}
	c.emitter.BeginAttempt(ProgressQueueCursor)
	stepRes, stepErr := cursorsync.DrainPendingLocked(ctx, c.opt, c.gate, c.lock)
	c.emitter.EndAttempt()
	// Per-step queue update: the incremental fold — no ledger re-read;
	// bytes and the oldest age become unknown until the next bounded
	// re-sample. The drain counters are folded by the per-phase adapter
	// wired into c.opt.Progress, never here.
	c.emitter.ApplyCursorDrain(stepRes.SyncedBatches, stepRes.SyncedRecords)
	// Work already ran this round: the escalation signal for a mid-run
	// narrowing. Only ACTUAL work counts — uploaded batches, pulled
	// events, persisted batches, or a completed first sync — never Ran
	// alone: Ran is set before any upload or pull happens, so a pre-work
	// skip must stay a verdict instead of escalating to drift.
	workRan := c.agg.SyncedBatches > 0 || c.agg.PulledEvents > 0 ||
		c.agg.ExportedBatches > 0 || c.agg.FirstSyncCompleted
	progressed := stepRes.SyncedBatches > 0
	c.agg.SyncedBatches += stepRes.SyncedBatches
	c.agg.SyncedRecords += stepRes.SyncedRecords
	if stepRes.Ran {
		c.agg.Ran = true
	}
	if stepRes.Status != "" {
		c.agg.Status = stepRes.Status
	}
	if stepRes.FirstSyncCompleted {
		c.agg.FirstSyncCompleted = true
	}
	next := stepRes.Outcome
	if stepErr != nil && next == cursorsync.RoundAbsent {
		next = cursorsync.RoundError
	}
	c.agg.Outcome = mergeCursorOutcome(c.agg.Outcome, next, workRan)
	if stepErr != nil {
		if isBudgetDecline(stepErr) {
			// Run-wide stop: the declined batch was never POSTed and
			// stays pending. Surface the backlog honestly and return
			// the sentinel so the caller reports an incomplete run.
			c.preservePending(stepRes.PendingRemaining, stepRes.PendingCounted)
			c.finished = true
			return false, stepErr
		}
		// Non-budget failure: the historical non-fatal recording —
		// never blocks the device queue, but this queue is done for
		// the run (the historical cursor round attempts once).
		if c.agg.Skipped == "" {
			c.agg.Skipped = stepErr.Error()
		} else {
			c.agg.Note = appendCursorNote(c.agg.Note, stepErr.Error())
		}
		c.preservePending(stepRes.PendingRemaining, stepRes.PendingCounted)
		c.finished = true
		return false, nil
	}
	if stepRes.Skipped != "" {
		// A skip reason (paused, fence moved, source reassigned, ...)
		// ends this queue's turns for the run while the device queue
		// keeps draining.
		if c.agg.Skipped == "" {
			c.agg.Skipped = stepRes.Skipped
		} else if c.agg.Skipped != stepRes.Skipped {
			c.agg.Note = appendCursorNote(c.agg.Note, stepRes.Skipped)
		}
		c.preservePending(stepRes.PendingRemaining, stepRes.PendingCounted)
		c.finished = true
		return progressed, nil
	}
	if !progressed {
		// Clean round, nothing uploaded: the queue is exhausted.
		c.finished = true
	}
	if stepRes.PendingCounted {
		c.agg.PendingRemaining = stepRes.PendingRemaining
		c.agg.PendingCounted = true
	} else {
		c.preservePending(stepRes.PendingRemaining, false)
	}
	return progressed, nil
}

// preservePending keeps the aggregate's pending count honest for a round
// that did not drain: cursync's skip and failure paths do not always
// count the queue themselves, so recount the durable outbox and never
// let a skipped queue read as an empty one. A failed recount keeps the
// last known count.
func (c *cursorQueueDrain) preservePending(reported int, observed bool) {
	if observed {
		c.agg.PendingRemaining = reported
		c.agg.PendingCounted = true
		return
	}
	if n, err := cursoroutbox.New(c.opt.StateDir).CountPending(); err == nil {
		c.agg.PendingRemaining = n
		c.agg.PendingCounted = true
	}
}

// appendCursorNote joins a diagnostic onto the aggregate cursor note the
// same way the pull phase records its errors.
func appendCursorNote(note, add string) string {
	if note == "" {
		return add
	}
	return note + "; " + add
}

// mergeCursorOutcome folds a later cursor phase/step outcome into the
// accumulated round outcome (plan §6.5):
//
//   - RoundError and RoundFenceStop stick: a real failure, or an
//     authorization-boundary drift after uploads already happened, is
//     never erased by later progress;
//   - RoundAuthWithheld escalates to RoundFenceStop when work already ran
//     this round — an authorization that withheld the source BEFORE any
//     work is a verdict (workRan=false), but the same signal observed
//     after a pull or uploads is a mid-run narrowing, i.e. drift;
//   - every other outcome reflects the latest state: a pause that
//     lifted, or a phase-level bound the rotation later drained past,
//     yields to the round's eventual result.
func mergeCursorOutcome(prev, next cursorsync.RoundOutcome, workRan bool) cursorsync.RoundOutcome {
	switch {
	case prev == cursorsync.RoundError || next == cursorsync.RoundError:
		return cursorsync.RoundError
	case prev == cursorsync.RoundFenceStop || next == cursorsync.RoundFenceStop:
		return cursorsync.RoundFenceStop
	case next == cursorsync.RoundAuthWithheld && workRan:
		return cursorsync.RoundFenceStop
	case next == cursorsync.RoundAbsent:
		return prev
	default:
		return next
	}
}

// cursorRoundIncomplete reports whether the structured cursor round
// outcome means the run is not a complete success — the progress layer
// suppresses its "complete" event for these, and the periodic CLI layer
// (see periodicCursorIncomplete) turns them into exit reasons. Paused is
// included: a paused round, even with nothing pending, never claims
// completion.
func cursorRoundIncomplete(outcome cursorsync.RoundOutcome) bool {
	switch outcome {
	case cursorsync.RoundError, cursorsync.RoundFenceStop, cursorsync.RoundPaused:
		return true
	default:
		return false
	}
}

func countPending(ledger outbox.Store) (int, error) {
	out, err := ledger.Load()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, batch := range out.Batches {
		if batch.Status == outbox.StatusPending {
			count++
		}
	}
	return count, nil
}

// syncedBatchIDsUnderLock lists the device outbox entries already marked
// synced, in outbox order. It must only be called while holding the state
// lock (the §6.3 capture inside runLocked does) — the outbox is
// process-shared state. The result is always a usable slice (empty,
// never nil, when nothing is synced) so a snapshot built from it keeps
// the empty-set semantics distinct from "no snapshot".
func syncedBatchIDsUnderLock(stateDir string) ([]string, error) {
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Batches))
	for _, b := range out.Batches {
		if b.Status == outbox.StatusSynced {
			ids = append(ids, b.BatchID)
		}
	}
	return ids, nil
}

// quarantineStoreCount reports how many records currently sit in the
// quarantine store.
func quarantineStoreCount(stateDir string) (int, error) {
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// newBatchID builds a unique local batch id: timestamp plus a short random
// suffix so concurrent grants and rapid successive runs never collide. The
// exportcommit journal freezes the id before any state mutation, so crash
// recovery replays the exact same id.
func newBatchID(now func() time.Time, grantIndex int) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate batch id: %w", err)
	}
	return fmt.Sprintf("local-%s-%02d-%s", now().UTC().Format("20060102T150405Z"), grantIndex, hex.EncodeToString(buf[:])), nil
}

// saveScanStates persists the per-file content states a resumed scan
// observed, AFTER that source's records were committed. It is a no-op for a
// loader that reports no states (every source but the incremental ones).
func saveScanStates(stateDir, source string, states map[string]scanledger.FileState) error {
	if len(states) == 0 {
		return nil
	}
	return scanledger.New(stateDir).Save(source, states)
}
