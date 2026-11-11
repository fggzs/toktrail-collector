package connect

// The shared post-authorization sync orchestration. connect.Run uses it
// after its setup phases (bind, grants, scheduler install), and the
// resync CLI can drive the exact same semantics so both entry points
// agree on what a complete sync means.
//
// Phase order and why:
//  1. One normal collection round first — it refreshes the server-driven
//     authorization (grant sync), scans local sources, recovers the
//     export WAL and quarantine store, and drains a bounded number of
//     pending batches. Retransmitting history before the authorization
//     refresh would plan against a stale local grant view.
//  2. Then, in BUDGETED runs (connect, and every drive with a Budget or
//     a positive MaxTotalBatches), the backlog drain passes while the
//     NEW queues (device outbox and account source) still hold pending
//     batches: fresh pending data is the current authorization's own
//     coverage and must not wait behind the history retransmission,
//     which only replays what the server already holds (de-duplicated).
//     Each pass drains BOTH queues under one lock (fair rotation: no
//     queue starves the other) and keeps passing until the queues are
//     empty, the budget declines, or a pass makes no progress.
//  3. The history retransmission (internal/app/resync) of already-synced
//     outbox batches under an exclusive state lock. resync.Run never
//     locks itself, so this phase owns the runlock for it. When the
//     caller captured a synced-batch snapshot (connect does, in the
//     initial collection round after the authorization refresh), the
//     pass is restricted to it: the batches this run's own collection
//     uploads are never immediately replayed — on a first install the
//     pass is simply empty. Without a snapshot (the resync CLI) the pass
//     keeps the original full-archive semantics, which the server
//     de-duplicates by replay.
//
// Unbudgeted runs — the explicit resync CLI, which sets neither Budget
// nor MaxTotalBatches — keep the ORIGINAL phase order instead:
// initial collection → history retransmission → backlog drain. The CLI's
// interactive confirmation plan lists the already-synced archive only,
// and draining the backlog before the retransmission would fold this
// run's backlog uploads (up to DefaultMaxBacklogPasses ×
// DefaultMaxSyncBatches batches) into the executed retransmission the
// user never confirmed. The unbudgeted backlog keeps the historical
// bounded-pass behavior.
//
// Budget: SyncOptions.Budget (or MaxTotalBatches, which builds one) caps
// the real ingest POST attempts of ALL THREE queues — device, account
// source and history retransmission — through the shared
// internal/syncbudget budget the sending layers reserve under right
// before each POST. A decline is never a failure: the declined batch
// stays pending, the history job stays resumable, and the run reports
// ErrSyncIncomplete (SyncResult.BudgetExhausted) instead of success. A
// nil budget (the resync CLI, and every caller that sets neither field)
// keeps the unbudgeted behavior exactly as before.
//
// Locking: the caller must NOT hold the state lock. Phase 1 goes through
// collection.Run, which acquires and releases the state lock per pass
// (retrying while it is busy). Each phase-2 backlog pass acquires the
// lock ONCE — through the same bounded busy retry — and holds it
// continuously across the whole pass (device authorization refresh and
// drain, account-source drain, terminal authorization check; see
// runBacklogPass), so no other collector process can interleave between
// a pass's sub-phases. Phase 3 acquires the lock with the bounded busy
// retry and holds it across resync.Run.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/local/cursorsource"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncbudget"
	"toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// DefaultMaxBacklogPasses bounds the extra collection passes after the
// initial round for UNBUDGETED runs (the resync CLI and every caller
// that passes no budget). Each pass drains up to
// collection.DefaultMaxSyncBatches device batches (plus the cursor
// source's own bounded drain), so the default gives a reconnect a
// reasonable full-drain effort (~50 device batches) while keeping one
// run finite; whatever remains is reported as incomplete and is
// continued by re-running connect, the scheduled collection, or the
// resync CLI. A budgeted run lifts this pass bound (see Sync): the
// budget's own total and deadline bound the run instead, so the
// hardcoded 10×5 ceiling cannot stop a run whose budget still allows
// POSTs.
const DefaultMaxBacklogPasses = 10

const (
	// DefaultBudgetTotal is the default run-wide ingest-POST budget
	// connect.Run gives its sync phase when the caller sets no explicit
	// total: every real POST of the device, account-source and history
	// queues reserves one unit of it.
	DefaultBudgetTotal = 1000

	// DefaultBudgetDeadline is the default time bound of that budget,
	// measured from the start of connect.Run (the budget's clock and the
	// deadline are derived from the same injectable Now, so a test's
	// fixed clock can never accidentally expire the deadline).
	DefaultBudgetDeadline = 10 * time.Minute

	// budgetQueueDevice is the syncbudget queue name the device outbox
	// drain reserves under (collection's own wiring); connect consults it
	// to detect a queue-specific device cap.
	budgetQueueDevice = "device"

	// budgetQueueCursor is the syncbudget queue name the account-source
	// (cursor) uploads reserve under (sourcebatch's own wiring); connect
	// consults it to detect a queue-specific account cap, mirroring the
	// device-side check.
	budgetQueueCursor = "cursor"

	// backlogBudgetStopped is the Backlog.Stopped / Resync.Skipped
	// marker for a stop caused by the shared run budget declining
	// further attempts. It deliberately matches resync's own stopped
	// marker text so the two phases report one consistent vocabulary.
	backlogBudgetStopped = "sync budget exhausted"

	// maxBacklogPassesUnbounded is the pass bound used for budgeted runs
	// whose caller did not configure one: effectively no pass bound, so
	// only the budget (total, deadline, queue caps), the drained queues
	// and the no-progress guard end the loop. A plain large constant
	// keeps the counter arithmetic honest for every realistic run.
	maxBacklogPassesUnbounded = 1 << 30
)

// ErrSyncIncomplete reports that the orchestration finished without
// covering the current authorization completely. The error message lists
// every reason; callers can distinguish it with errors.Is.
var ErrSyncIncomplete = errors.New("connect sync incomplete")

// Lock-retry budget for phases that must take the exclusive state lock
// while a scheduled collection task may legitimately hold it. Tests
// shrink both.
var (
	stateLockRetryTotal = 30 * time.Second
	stateLockRetryDelay = 250 * time.Millisecond
)

// noNewRecordsSkip is the exact GrantOutcome.Skipped wording collection
// uses for a healthy empty scan. It is the only grant skip that is normal
// (not an incompleteness); the coupling to collection's wording is
// deliberate — collection only signals this through Skipped, and connect
// must not modify that package. A wording drift degrades to an
// incompleteness report, never to a silently swallowed real failure.
const noNewRecordsSkip = "no new records since the last confirmed baselines"

// SyncOptions configures one Sync orchestration run.
type SyncOptions struct {
	// StateDir is the collector state directory (required).
	StateDir string
	// ServerURL is the server the authorization points at. Empty lets
	// resync default to the bound server (device.json).
	ServerURL string
	// HTTPClient is an optional client override (tests); it is wrapped
	// by the same safety clone connect uses.
	HTTPClient *http.Client
	// Now is an injectable clock for deterministic tests.
	Now func() time.Time
	// Out receives progress output (defaults to io.Discard).
	Out io.Writer
	// Verbose switches the human display to its detailed mode: per-pass
	// collection rounds and per-batch retransmission lines join the
	// concise phase output. Never a secret: URLs, tickets, device ids
	// and server-controlled free text stay unprinted in every mode.
	Verbose bool

	// HomeDir and CollectorVersion forward to the collection rounds.
	HomeDir          string
	CollectorVersion string

	// Cursor carries the account-level Cursor wiring. Nil keeps the
	// collection behavior exactly as before (no cursor round). The first
	// collection pass forces one full-range cursor recovery round
	// (cursorsync.Options.ForceResync); backlog passes do not.
	Cursor *cursorsync.Options

	// CursorFreshlyEnabled reports that this run's setup just performed
	// the first-time account-source enable, whose own first sync already
	// pulled the full authorized window once and uploaded it. The initial
	// collection round then runs its cursor phase DRAIN-ONLY
	// (collection.Options.CursorDrainOnly): the server authorization
	// preflight and the persisted-queue upload still run, but the round
	// never reads the Cursor credential and never pulls the upstream a
	// second time — one first connect, exactly one upstream pull. The
	// backlog passes continue any queue the enable's bounded first sync
	// left pending (uploads only, never a pull), and a budget decline
	// still stops the run honestly. It is only ever set by connect.Run
	// after a SUCCESSFUL enable whose first sync ran; a reconnect over an
	// existing permit (never freshly enabled) keeps the full forced round
	// exactly as before.
	CursorFreshlyEnabled bool

	// CursorFirstSyncFailed carries the first-time account-source enable's
	// FIRST-SYNC failure (connect's setup already reported it to the
	// user): the first sync attempt executed — this command's single
	// upstream pull is spent (or the round stopped before pulling) — so
	// the initial collection round runs its cursor phase DRAIN-ONLY and
	// never pulls a second time in the same command. One upstream pull
	// per command, success or failure. The failure is reported as an
	// incompleteness reason (never as success); the permit keeps its
	// honest state (pending_first_sync with no watermark advance on a
	// pull failure) and the next run — a connect or the scheduled
	// collection — retries it. It is only set by connect.Run when the
	// enable's first sync actually ran and failed (a declined
	// confirmation, a capability or credential failure before any permit
	// existed leaves it empty: no permit exists, so the initial round
	// keeps its historical clean skip).
	CursorFirstSyncFailed string

	// InitialLock is a state lock the CALLER already holds and hands over
	// for this run's INITIAL collection round (phase 1): Sync runs that
	// round through collection.RunLocked under this exact lock instead of
	// letting collection.Run acquire its own, so connect's setup and its
	// initial collection become one continuous hold — no window in which
	// a scheduled collection task could interleave, sync pending batches
	// under the old authorization and make this run mistake the mutated
	// state for its own clean coverage.
	//
	// Ownership: once passed, Sync owns the release and guarantees it
	// exactly once on every path — normally right after the initial
	// collection round ends (success, budget decline, pause, refresh
	// failure and cancellation alike), so the later phases (backlog
	// passes, history retransmission) can acquire their own locks; and on
	// any exit that never reaches that round (validation errors, the
	// dry-run and override branches — which release before anything that
	// acquires — and a confirmation abort) through the deferred safety
	// release. The caller must not close the lock itself once handed
	// over. Nil (every caller but connect.Run) keeps the self-locking
	// behavior: phase 1 acquires and releases the lock itself, retrying
	// while it is busy.
	InitialLock *runlock.Lock

	// CaptureResyncSnapshot switches the history retransmission's scope
	// from the caller's static ResyncSnapshot to the snapshot the INITIAL
	// collection round captures in-lock (collection.Options.
	// CaptureSyncedBatchIDs): the device outbox's synced-batch ids frozen
	// after the authorization refresh succeeded and before any source
	// scanning or upload of this run. It is the §6.3 point — with
	// InitialLock the capture sits inside the same continuous hold that
	// started at connect's setup, so nothing can sync batches between the
	// authorization refresh and the freeze. (One documented ordering
	// exception: an account source first-enabled in connect's setup
	// uploads through its own source-batch queue BEFORE this round, under
	// the enable's own fresh server preflight; it never writes the device
	// outbox, so it is outside the snapshot's universe by design.)
	//
	// It is only meaningful for callers that run the collection phase
	// (connect); an explicit ResyncSnapshot still takes precedence, and
	// neither field set (the resync CLI) keeps the full-archive
	// semantics exactly as before.
	CaptureResyncSnapshot bool

	// AuthorizedTools lists the tools the driving authorization activated
	// (connect passes its activated set). It disambiguates the
	// "no enabled source grants" collection skip: with no authorized
	// local tool there is nothing to collect, which is not an
	// incompleteness.
	AuthorizedTools []string

	// AccountTools lists the account-network tools the authorization
	// named (e.g. Cursor), regardless of whether their local setup
	// succeeded. A named account tool whose round did not complete marks
	// the sync incomplete.
	AccountTools []string

	// ResyncConfirm is the caller's interactive confirmation hook (the
	// resync CLI's prompt). Sync invokes it BEFORE any collection, scan
	// or upload: it first produces a read-only offline plan and passes it
	// to the hook; returning an error aborts the whole sync with nothing
	// collected or uploaded. The pre-run plan lists the ALREADY-SYNCED
	// archive only — batches the collection phase will sync during this
	// run are not in it; without a ResyncSnapshot the executed
	// retransmission re-plans after collection so they join then, while
	// a snapshot keeps them excluded (see ResyncSnapshot). Nil (connect)
	// skips interaction entirely: the connect link is itself the user's
	// authorization gesture, and the executed phase prints its plan
	// instead.
	ResyncConfirm func(resync.Plan) error
	// ResyncSnapshot restricts the history retransmission to the outbox
	// batches that were already synced when it was captured. connect's
	// automatic flow no longer passes one here — it sets
	// CaptureResyncSnapshot, and the initial collection round captures
	// the snapshot in-lock after the authorization refresh and before
	// any of this run's uploads (the §6.3 point) — so the automatic pass
	// covers exactly the pre-run synced history and never immediately
	// replays the batches this run's own collection uploads (on a first
	// install it retransmits nothing). An explicitly passed snapshot
	// still takes precedence over the captured one.
	//
	// nil (the resync CLI and every other caller) keeps the original
	// full-archive semantics. The snapshot only shapes a NEW
	// retransmission job: an unfinished journal resumes its frozen plan,
	// and a consent-scope change re-plans the complete synced history —
	// both deliberately ignore it. A non-nil snapshot with zero batch
	// ids means "nothing was synced yet" and is distinct from nil.
	ResyncSnapshot *resync.SyncedBatchSnapshot
	// ResyncProgress reports each batch outcome during retransmission.
	ResyncProgress func(resync.ProgressEvent)
	// ResyncDryRun plans the retransmission offline: no collection phase,
	// no backlog drain, no state lock, no writes. The collection phase
	// mutates state and has no dry-run, and the remote consent scope is
	// NOT verified — the limitation is inherent, not incidental.
	ResyncDryRun bool
	// ResyncMaxBatches is an optional per-run retransmission upload
	// budget (0 walks the whole frozen plan).
	ResyncMaxBatches int
	// ResyncReplaceExisting switches the resync CLI entry into the
	// explicitly confirmed override pass: scan the CURRENT Codex and
	// DeepSeek Harness sources and replace same-key server records with
	// the current scanned record. It is a manual-only mode: connect's own
	// automatic flow never sets it, and when set the sync runs ONLY the
	// override pass (no cursor round, no collection phase, no backlog
	// drain — normal collection resumes on the next ordinary sync once
	// the repair is done).
	ResyncReplaceExisting bool
	// ResyncOverrideConfirm is the interactive confirmation hook for the
	// override pass (the resync CLI's prompt). Sync invokes it with the
	// ACTUAL current-scan override plan before any state change or
	// network traffic; returning an error aborts with zero writes.
	// Required for a non-dry-run override pass.
	ResyncOverrideConfirm func(resync.OverridePlan) error
	// ResyncOverrideProgress reports each override batch outcome.
	ResyncOverrideProgress func(resync.OverrideProgressEvent)
	// MaxBacklogPasses bounds the extra drain passes (defaults to
	// DefaultMaxBacklogPasses for unbudgeted runs; a budgeted run that
	// leaves this unset is bounded by the budget itself instead — see
	// Budget).
	MaxBacklogPasses int
	// MaxTotalBatches optionally caps the total real ingest POST attempts
	// across ALL THREE queues of the run — the device outbox drain, the
	// account-source uploads and the history retransmission. When Budget
	// is nil and this is positive, Sync builds a total-only shared budget
	// from it. Zero means no total cap. Negative is rejected. The
	// per-pass bounds (collection/cursorsync MaxBatches) are preserved on
	// top of it: they bound each pass, the budget bounds the run.
	MaxTotalBatches int
	// Budget optionally supplies the shared run budget directly. Every
	// sending layer of the phases below — the device outbox drain
	// ("device" queue), the account-source uploads ("cursor" queue) and
	// the history retransmission ("history" queue) — reserves one unit
	// under it immediately before its real POST, so the three queues
	// share one total (and, when configured, one deadline and per-queue
	// caps). A decline stops the affected phase gracefully: the declined
	// batch was never POSTed and stays pending, the history job stays
	// resumable, and the run reports ErrSyncIncomplete (never a hard
	// failure, never success). It takes precedence over MaxTotalBatches.
	//
	// Nil with MaxTotalBatches > 0 builds a total-only budget; nil with
	// MaxTotalBatches == 0 keeps the run completely unbudgeted — the
	// explicit resync CLI semantics, exactly as before (bounded backlog
	// passes, no total cap).
	Budget *syncbudget.Budget
	// Retry is the run's single bounded retry policy
	// (internal/syncretry) for TRANSIENT ingest send failures. connect's
	// automatic flow wires one policy built against the run's ctx
	// deadline; the resync CLI leaves it nil and keeps the historical
	// single-shot semantics. When set it threads — unchanged — into
	// every sending queue of the run: the device outbox drain
	// (collection.Options.Retry), the account-source uploads
	// (cursorsync.Options.Retry, the first-time enable's round included)
	// and the history retransmission (resync.Options.Retry). The retry
	// loop stays INSIDE each POST's send (one layer, never wrapped
	// around a queue or a pass): every attempt resends the same batch ID
	// with the same immutable bytes, re-runs the fresh self preflight
	// and the scope/privacy gates, and reserves the shared Budget again
	// before its real POST — a decline stays a final error that stops
	// the loop without waiting. Callers must build the policy with an
	// explicit run deadline (WithRunDeadline, ideally the ctx deadline)
	// and a non-zero random Jitter.
	Retry *syncretry.Policy
	// Progress receives the unified collection progress events: the
	// collection rounds (initial and backlog passes) emit their stage,
	// queue-snapshot, per-batch and heartbeat events through their own
	// emitters; connect adds its own phase markers (backlog, history)
	// and adapts the history retransmission's per-batch outcomes into
	// the same stream. Nil keeps the behavior identical. Invocations are
	// serialized (never concurrent) but may originate from a heartbeat
	// goroutine.
	Progress func(collection.ProgressEvent)
}

// ResyncStopCode classifies how the history retransmission phase ended
// (plan §6.5's history block). It is a closed enum assigned at every
// site that sets ResyncSummary.Skipped / NotApplicable / Err, so the
// stable summary classifies from structure and never matches the
// message text. The empty value means the phase never recorded an end
// (it did not run).
type ResyncStopCode string

const (
	// ResyncStopCompleted: the phase ran and completed (a dry run with
	// a plan counts as completing its offline scope).
	ResyncStopCompleted ResyncStopCode = "completed"
	// ResyncStopBusy: the state lock stayed busy; nothing ran.
	ResyncStopBusy ResyncStopCode = "busy"
	// ResyncStopPaused: the server paused the device; nothing ran.
	ResyncStopPaused ResyncStopCode = "paused"
	// ResyncStopBudget: the shared run budget declined the phase's
	// uploads; the job stays resumable.
	ResyncStopBudget ResyncStopCode = "budget"
	// ResyncStopNothingEligible: no synced history matches the current
	// local grants (an authorization verdict, not a failure).
	ResyncStopNothingEligible ResyncStopCode = "nothing_eligible"
	// ResyncStopFailed: the phase failed with a hard error.
	ResyncStopFailed ResyncStopCode = "failed"
	// ResyncStopStopped: the job ran but stopped before finishing
	// (resumable).
	ResyncStopStopped ResyncStopCode = "stopped"
)

// ResyncSummary is connect's compact view of one retransmission round.
// It never claims full coverage: Remaining carries exactly what a resume
// run would still retransmit, and Blocked / SkippedOutOfScopeRecords /
// ExcludedLocalGrant carry what the current authorization withholds.
type ResyncSummary struct {
	// Ran is true when the retransmission executed (a dry run counts as
	// running: it produced a plan).
	Ran bool
	// DryRun is true when only an offline plan was produced.
	DryRun bool
	// Skipped carries why the phase did not execute in a way that leaves
	// the sync incomplete (state busy, or the server paused the device).
	Skipped string
	// NotApplicable carries why the phase had nothing to retransmit under
	// the current authorization (for example: no synced batch matches a
	// currently enabled local grant because this authorization disabled
	// its sources). That is an authorization verdict, not a failure.
	NotApplicable string
	// Err is the phase's hard error, if any.
	Err string
	// Stop is the structured twin of Skipped / NotApplicable / Err and
	// the completion state: a closed ResyncStopCode assigned at every
	// phase-end site, so the §6.5 summary classifies from structure.
	Stop ResyncStopCode

	JobID     string
	Resumed   bool
	Completed bool
	// ConsentRevision is the live consent scope revision the
	// retransmission prefetched (or, for an empty or nothing-eligible
	// pass that never prefetches, the fresh self confirmation connect
	// performed on its behalf). Zero means unconfirmed.
	ConsentRevision int64

	Uploads         int
	UploadedRecords int
	AcceptedRecords int
	RejectedRecords int
	ReplayReceipts  int

	Blocked                  int
	SkippedOutOfScopeRecords int
	Remaining                int

	ExcludedPending     int
	ExcludedReorganized int
	ExcludedLocalGrant  int
	// ExcludedAfterSnapshot counts synced batches the retransmission
	// plan excluded because they were synced after connect captured its
	// snapshot — the batches this run's own collection uploaded, which
	// are deliberately not replayed immediately. Zero whenever no
	// snapshot restricted the pass.
	ExcludedAfterSnapshot int
	QuarantinedRecords    int
	Stopped               string
}

// BacklogSummary reports the extra drain passes.
type BacklogSummary struct {
	// Passes counts the collection rounds after the initial one.
	Passes int
	// Result accumulates the pass totals; its PendingRemaining (and
	// Cursor.PendingRemaining) reflect the LAST pass.
	Result collection.Result
	// PendingRemaining is the final count of pending outbox batches.
	PendingRemaining int
	// CursorPendingRemaining is the final count of pending cursor-source
	// batches.
	CursorPendingRemaining int
	// Stopped carries why draining stopped with work left (pass bound
	// reached, or a pass made no progress).
	Stopped string
	// Err is the hard error of a failed pass, if any.
	Err string
}

// SyncResult reports what one Sync orchestration did. Incomplete lists
// every reason the current authorization was not fully covered; a
// non-empty list always comes with a non-nil error (ErrSyncIncomplete)
// unless a harder phase error was returned instead.
type SyncResult struct {
	// Collection is the initial collection round.
	Collection collection.Result
	// Resync summarizes the history retransmission.
	Resync ResyncSummary
	// Backlog summarizes the extra drain passes.
	Backlog BacklogSummary
	// BudgetExhausted is true when the run-wide POST total or deadline
	// prevents further attempts. A queue-only cap is reported separately
	// through the backlog stop reason and pending counts.
	BudgetExhausted bool
	// Incomplete lists every incompleteness reason, in phase order.
	Incomplete []string
	// accountIncomplete is the structural twin of the account-source
	// completion reasons evaluateIncomplete appends (the accountTools
	// loop): set exactly when at least one such reason was actually
	// added, so the §6.5 summary can key its account verdict codes on
	// the marker plus the cursor round outcome — never on the outcome
	// alone, which a run whose authorization never owed the account
	// source holds as its clean steady state. Unexported on purpose:
	// connect-internal classification state, not contract surface.
	// Zeroed at the start of every evaluation.
	accountIncomplete bool
	// firstSyncIncomplete is the structural twin of the
	// CursorFirstSyncFailed reason: this run's setup attempted the
	// first-time account-source enable and its first sync executed
	// without completing (the permit keeps pending_first_sync and the
	// collection round ran drain-only). Set exactly when that reason
	// was added, so the summary never has to guess from the permit's
	// observed status whether a pending_first_sync permit is this
	// run's failed first sync or an unrelated leftover. Zeroed at the
	// start of every evaluation.
	firstSyncIncomplete bool
}

// Sync performs the post-authorization sync orchestration: initial
// collection, backlog drain passes over the pending device and
// account-source queues, then the history retransmission under an
// exclusive lock. The caller must not hold the state lock.
//
// For the resync CLI: drive it with the bound server URL, your
// interactive ResyncConfirm (Sync invokes it before ANY collection or
// upload, passing a read-only plan of the already-synced archive), and
// the ResyncMaxBatches passthrough; use ResyncDryRun for the offline
// plan (it skips collection — there is no collection dry-run — and never
// touches the lock or disk). Without ResyncConfirm there is no
// interaction: connect proceeds under its own authorization gesture.
// Leaving ResyncSnapshot nil (the CLI does) keeps the explicit pass's
// original full-archive semantics; connect.Run instead sets
// CaptureResyncSnapshot (plus InitialLock), so its history phase is
// restricted to the snapshot the initial collection round captures
// in-lock after the authorization refresh. Leaving Budget and
// MaxTotalBatches unset (the CLI does) keeps the run unbudgeted with the
// historical bounded-pass backlog behavior.
func Sync(ctx context.Context, opt SyncOptions) (SyncResult, error) {
	// The setup-lock handoff safety net comes FIRST, before any
	// validation: a caller that handed its state lock in must get it
	// back released on EVERY exit — including the early parameter
	// failures below (an empty state directory, a negative total) —
	// otherwise the lock would leak and every later process would see
	// ErrBusy. The one-shot release is normally consumed by the phase-1
	// wrapper (right after the initial collection round: success, budget
	// decline, pause, refresh failure and cancellation alike, so the
	// backlog and history phases can acquire their own locks); the
	// deferred call below is the net for every exit that never reaches
	// that round.
	releaseInitial := func() {}
	if opt.InitialLock != nil {
		initialLock := opt.InitialLock
		initialReleased := false
		releaseInitial = func() {
			if !initialReleased {
				initialReleased = true
				_ = initialLock.Close()
			}
		}
		defer releaseInitial()
	}

	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return SyncResult{}, errors.New("collector state directory is required")
	}
	// Force-recollect journal guard, before any collection round,
	// backlog pass, history retransmission, dry-run plan or lock
	// handoff consumes the state: while a reset is in flight, the sync
	// orchestration stops with the sentinel instead of reading sources
	// or moving old-epoch batches around. Only the recollect driver
	// continues, through syncclient under its journal's request id.
	if err := syncclient.CheckResetJournal(stateDir); err != nil {
		return SyncResult{}, err
	}
	out := opt.Out
	if out == nil {
		out = io.Discard
	}
	// The human display layer: concise phase output by default, detail
	// under Verbose. Display only — nothing reads it back.
	d := newDisplay(out, opt.Verbose)
	// The serialized dispatch for connect's own phase markers and the
	// history adapter. The collection rounds construct their own
	// emitters over opt.Progress (serialized by construction); this
	// wrapper serializes everything connect dispatches BETWEEN rounds.
	progress := collection.SerialProgress(opt.Progress)
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	opt.HTTPClient = newSafeHTTPClient(opt.HTTPClient)
	opt.StateDir = stateDir
	if opt.MaxTotalBatches < 0 {
		return SyncResult{}, errors.New("max total batches must be non-negative")
	}
	// Shared run budget: an explicit Budget wins; otherwise a positive
	// MaxTotalBatches builds a total-only one; otherwise the run is
	// unbudgeted (the resync CLI semantics).
	budget := opt.Budget
	if budget == nil && opt.MaxTotalBatches > 0 {
		budget = syncbudget.New(syncbudget.WithTotal(opt.MaxTotalBatches))
	}
	opt.Budget = budget
	// A budgeted run is bounded by the budget itself (total, deadline,
	// per-queue caps), so the historical 10-pass × 5-batch ceiling must
	// not stop a run whose budget still grants POSTs: the backlog keeps
	// passing until the queues drain, the budget declines, or a pass
	// makes no progress. An explicitly configured MaxBacklogPasses always
	// wins — a caller that asks for a tight pass bound keeps it.
	maxBacklogPasses := opt.MaxBacklogPasses
	if maxBacklogPasses <= 0 {
		if budget != nil {
			maxBacklogPasses = maxBacklogPassesUnbounded
		} else {
			maxBacklogPasses = DefaultMaxBacklogPasses
		}
	}

	syncRes := SyncResult{}

	// Dry run: plan-only retransmission. Collection and the backlog
	// drain mutate state (export, drain, quarantine recovery) and have no
	// dry-run; the state lock is not even created.
	if opt.ResyncDryRun {
		// The handoff (if any) was only meant for the initial
		// collection round, which never runs here — release it before
		// planning.
		releaseInitial()
		res, err := resync.Run(ctx, resync.Options{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
			DryRun:     true,
			Snapshot:   opt.ResyncSnapshot,
			Now:        now,
		})
		syncRes.Resync = summarizeResync(res, true)
		if err != nil {
			syncRes.Resync.Err = err.Error()
			syncRes.Resync.Stop = ResyncStopFailed
			return syncRes, fmt.Errorf("history retransmission planning failed: %w", err)
		}
		syncRes.Resync.Stop = ResyncStopCompleted
		d.phase("dry-run: offline, no files changed, remote consent scope NOT verified; execution checks consent before every upload")
		return syncRes, nil
	}

	// Override pass (manual `resync --all --replace-existing`): runs ONLY
	// the repair — no cursor round, no collection phase, no backlog
	// drain. Normal collection is blocked fail-closed while override
	// attempts are pending and resumes on the next ordinary sync once the
	// repair completes. Connect's own automatic flow never sets this
	// mode; it exists solely for the explicitly confirmed CLI gesture.
	if opt.ResyncReplaceExisting {
		// The handoff (if any) is released BEFORE this branch's own
		// lock acquisition — the initial collection round it was meant
		// for never runs here, and holding it through acquireStateLock
		// would deadlock the retry budget with a self-inflicted
		// ErrBusy.
		releaseInitial()
		if opt.ResyncDryRun {
			res, err := resync.RunOverride(ctx, resync.OverrideOptions{
				StateDir:   stateDir,
				ServerURL:  opt.ServerURL,
				HTTPClient: opt.HTTPClient,
				DryRun:     true,
				Now:        now,
			})
			syncRes.Resync = summarizeOverride(res, true)
			if err != nil {
				syncRes.Resync.Err = err.Error()
				syncRes.Resync.Stop = ResyncStopFailed
				return syncRes, fmt.Errorf("override planning failed: %w", err)
			}
			syncRes.Resync.Stop = ResyncStopCompleted
			d.phase("dry-run: offline, no files changed, remote consent scope and server capability NOT verified")
			return syncRes, nil
		}
		if err := checkHistoryOwnership(stateDir); err != nil {
			return syncRes, err
		}
		lock, err := acquireStateLock(ctx, stateDir)
		if err != nil {
			if errors.Is(err, runlock.ErrBusy) {
				syncRes.Resync.Skipped = fmt.Sprintf("the state directory stayed busy for %s (another collector process — likely the scheduled task — holds the lock); the override pass was NOT run", stateLockRetryTotal)
				syncRes.Resync.Stop = ResyncStopBusy
				d.phase("override pass: not run (the state directory stayed busy; another collector process holds the lock)")
				return syncRes, nil
			}
			return syncRes, fmt.Errorf("acquire state lock for the override pass: %w", err)
		}
		// RunOverride plans from the CURRENT scan and invokes the
		// confirmation hook with that exact plan before any state change
		// or network traffic — under the lock, so what the user confirms
		// is precisely what executes.
		res, overrideErr := resync.RunOverride(ctx, resync.OverrideOptions{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
			MaxBatches: opt.ResyncMaxBatches,
			Confirm:    opt.ResyncOverrideConfirm,
			Progress:   progressOverrideOrDefault(opt.ResyncOverrideProgress, d),
			Now:        now,
		})
		_ = lock.Close()
		syncRes.Resync = summarizeOverride(res, true)
		if overrideErr != nil {
			if errors.Is(overrideErr, syncclient.ErrDevicePaused) {
				syncRes.Resync.Skipped = overrideErr.Error()
				syncRes.Resync.Stop = ResyncStopPaused
				d.phase("override pass: skipped (device paused)")
				return syncRes, nil
			}
			syncRes.Resync.Err = overrideErr.Error()
			syncRes.Resync.Stop = ResyncStopFailed
			return syncRes, fmt.Errorf("override pass failed: %w", overrideErr)
		}
		syncRes.Resync.Stop = ResyncStopCompleted
		d.phase("override pass: complete")
		d.detail("override pass: uploads=%d replaced=%d inserted=%d confirmedKeys=%d", res.Uploads, res.ReplacedRecords, res.InsertedRecords, res.ConfirmedKeys)
		d.phase("normal collection resumes on the next ordinary sync or scheduled run")
		return syncRes, nil
	}

	// Pre-flight, before anything mutates state or uploads: the history
	// ownership guard, and — for callers that require interactive
	// confirmation (the resync CLI) — the user's confirmation. Both must
	// happen BEFORE the collection phase scans or uploads anything, so
	// an abort or a refusal leaves the state directory untouched.
	if err := checkHistoryOwnership(stateDir); err != nil {
		return syncRes, err
	}
	if opt.ResyncConfirm != nil {
		planRes, planErr := resync.Run(ctx, resync.Options{
			StateDir:   stateDir,
			ServerURL:  opt.ServerURL,
			HTTPClient: opt.HTTPClient,
			DryRun:     true,
			Snapshot:   opt.ResyncSnapshot,
			Now:        now,
		})
		if planErr != nil {
			if !errResyncNothingEligible(planErr) {
				syncRes.Resync = summarizeResync(planRes, true)
				syncRes.Resync.Err = planErr.Error()
				syncRes.Resync.Stop = ResyncStopFailed
				return syncRes, fmt.Errorf("history retransmission planning failed: %w", planErr)
			}
			d.phase("plan note: no synced history is eligible under the current local grants; source scanning may still upload usage")
		} else {
			d.phase("plan note: the confirmed plan lists the already-synced archive only; batches this run's collection syncs join the executed retransmission afterwards")
		}
		if err := opt.ResyncConfirm(planRes.Plan); err != nil {
			return syncRes, fmt.Errorf("sync aborted before any collection or upload: %w", err)
		}
	}

	// Phase 1: initial collection round. The pass bound stays the
	// per-pass DefaultMaxSyncBatches (lock granularity); the shared
	// budget — not a pre-min of the pass bound — enforces any total,
	// declining mid-drain without losing the drained part. A run whose
	// setup just performed the first-time cursor enable runs the round's
	// cursor phase drain-only (no second upstream pull); every other
	// run — a reconnect, the resync CLI — keeps the full cursor round.
	// The initial round's start line prints immediately (the user-
	// approved phase progress); its healthy outcome is carried by the
	// final result summary, and the detailed counters are verbose.
	d.phase("Collecting local usage...")
	collectOpts := collection.Options{
		StateDir:              stateDir,
		ServerURL:             opt.ServerURL,
		MaxBatches:            collection.DefaultMaxSyncBatches,
		HTTPClient:            opt.HTTPClient,
		Now:                   now,
		HomeDir:               opt.HomeDir,
		CollectorVersion:      opt.CollectorVersion,
		Budget:                budget,
		Retry:                 opt.Retry,
		Cursor:                cursorOptionsForCollection(opt, true),
		CursorDrainOnly:       opt.CursorFreshlyEnabled || opt.CursorFirstSyncFailed != "",
		CaptureSyncedBatchIDs: opt.CaptureResyncSnapshot,
		Progress:              opt.Progress,
		MaxParallelScans:      collection.DefaultMaxParallelScans,
	}
	if collectOpts.Cursor != nil {
		collectOpts.Cursor.Budget = budget
	}
	var collectRes collection.Result
	var collectErr error
	if opt.InitialLock != nil {
		// The continuous hold: the initial round runs under the
		// handed-over setup lock (no releasing gap between connect's
		// setup and this round — a scheduled task cannot interleave).
		// The wrapper releases the handoff exactly when the round ends —
		// success, budget decline, pause, refresh failure and
		// cancellation alike — so the backlog and history phases below
		// acquire their own locks. No busy retry here: the lock is held
		// by construction, and a nested acquire would be a bug.
		collectRes, collectErr = func() (collection.Result, error) {
			defer releaseInitial()
			return collection.RunLocked(ctx, collectOpts, opt.InitialLock)
		}()
	} else {
		collectRes, collectErr = runCollectionPass(ctx, collectOpts)
	}
	syncRes.Collection = collectRes
	if collectErr != nil {
		if budgetDeclined(collectErr) {
			// The shared budget declined the next POST mid-round: the
			// drained part stands, the declined batch stays pending, and
			// the run continues to the backlog/history phases so they can
			// report their own honest state under the same budget (a
			// queue-only decline may even leave room for them).
			if budgetTotalOrDeadlineDeclined(collectErr) {
				syncRes.BudgetExhausted = true
			}
			d.phase("initial collection: stopped at the shared sync budget (the drained part stands, the rest stays pending)")
		} else {
			return syncRes, fmt.Errorf("initial collection failed: %w", collectErr)
		}
	}
	printCollectionRound(d, "initial collection", collectRes)

	// The history retransmission's scope: the caller's explicit snapshot
	// wins; a capture-flagged run (connect) uses the §6.3 snapshot the
	// initial collection round froze in-lock — after the authorization
	// refresh, before any of this run's uploads (with InitialLock that
	// capture sits inside the same continuous hold that started at
	// connect's setup). Nil (the resync CLI and every other caller)
	// keeps the original full-archive semantics.
	resyncSnapshot := opt.ResyncSnapshot
	if resyncSnapshot == nil && opt.CaptureResyncSnapshot {
		resyncSnapshot = resync.NewSyncedBatchSnapshot(collectRes.SyncedBatchIDs)
	}

	var runErr error

	// Phase order. A BUDGETED run (connect, and every direct drive with
	// a Budget or a positive MaxTotalBatches) drains the NEW queues
	// FIRST: pending device and account-source batches are the current
	// authorization's fresh data and must not wait behind the history
	// replay. An UNBUDGETED run — the explicit resync CLI and every
	// caller that sets neither field — keeps the ORIGINAL order (history
	// retransmission BEFORE the backlog drain): its interactive
	// confirmation plan lists the already-synced archive only, and
	// draining the backlog first would fold this run's backlog uploads
	// (up to DefaultMaxBacklogPasses × DefaultMaxSyncBatches batches)
	// into the executed retransmission the user never confirmed. In both
	// orders the initial collection round runs first and its own uploads
	// do join the executed plan (the documented confirm semantics).
	runBacklogDrain := func() {
		// Phase: backlog drain. Each pass drains both queues under one
		// lock (fair rotation); on a budgeted run the loop keeps passing
		// until the queues are empty or the budget declines.
		stageStarted := emitProgressStageStart(progress, "backlog")
		var backlogErr error
		syncRes, backlogErr = drainBacklog(ctx, syncRes, collectOpts, d, maxBacklogPasses, budget)
		emitProgressStageEnd(progress, "backlog", stageStarted)
		if backlogErr != nil && runErr == nil {
			runErr = backlogErr
		}
	}
	runHistoryRetransmission := func() {
		// Phase: history retransmission under the exclusive state lock.
		// With a snapshot (connect — captured by the initial collection
		// round after the authorization refresh) the pass is restricted
		// to the batches already synced before this run's collection — a
		// first install retransmits nothing; without one (the resync
		// CLI) the pass replays the complete synced archive, which the
		// server de-duplicates. Either way the phase runs: the snapshot
		// was captured under the run's own continuous lock, so no
		// unlocked outbox read is needed to detect the first-install
		// case.
		historyStageStarted := emitProgressStageStart(progress, "history")
		defer emitProgressStageEnd(progress, "history", historyStageStarted)
		d.detail("retransmitting history...")
		switch {
		case collectRes.GrantSync.Paused:
			// Pause is a server state, not a run failure — collection
			// treats it as a skip, and so does this phase. The
			// completeness evaluation still reports it.
			syncRes.Resync.Skipped = "server reports collection paused for this device; history retransmission not attempted"
			syncRes.Resync.Stop = ResyncStopPaused
			d.phase("history retransmission: skipped (device paused)")
		case historyBlockedByBudget(syncRes, resyncSnapshot, budget):
			// The shared budget can no longer grant ANY history POST
			// (the run-wide total is spent, or a total/deadline decline
			// already surfaced in an earlier phase) and the phase has
			// targets to cover. Skip it BEFORE any lock, plan or
			// preflight: nothing could be sent, and the honesty contract
			// is served by the incompleteness report, not by a doomed
			// preflight round trip.
			syncRes.Resync.Skipped = "the run's shared sync budget was exhausted before the history retransmission; re-run connect or toktrail resync --all to resume it under a fresh budget"
			syncRes.Resync.Stop = ResyncStopBudget
			syncRes.BudgetExhausted = true
			d.phase("history retransmission: not started because the run's upload budget was reached")
		default:
			summary, hardErr, budgetStopped := runResyncPhase(ctx, stateDir, opt, resyncSnapshot, d, now, progress)
			syncRes.Resync = summary
			if budgetStopped {
				syncRes.BudgetExhausted = true
			}
			if hardErr != nil {
				syncRes.Resync.Err = hardErr.Error()
				runErr = fmt.Errorf("history retransmission failed: %w", hardErr)
			}
		}
	}
	if budget == nil {
		runHistoryRetransmission()
		runBacklogDrain()
	} else {
		runBacklogDrain()
		runHistoryRetransmission()
	}

	// Completeness: an authorization that was not fully covered is
	// reported as incomplete and never as success.
	syncRes.Incomplete = evaluateIncomplete(&syncRes, opt)
	if codes := incompleteCodes(syncRes); len(codes) > 0 {
		// The closed-code mirror of the incompleteness reasons: the
		// free-text reasons embed grant inputs, OS errors and unvetted
		// server strings, so they are never echoed in any mode. The
		// codes are verbose detail; the final result summary renders
		// the same boundaries in natural language, and the reasons stay
		// on the error chain (the command layer never prints them
		// raw).
		d.detail("incomplete: %s", strings.Join(codes, ", "))
	}
	if runErr != nil {
		return syncRes, runErr
	}
	if len(syncRes.Incomplete) > 0 {
		return syncRes, fmt.Errorf("%w: %s", ErrSyncIncomplete, strings.Join(syncRes.Incomplete, "; "))
	}
	return syncRes, nil
}

// checkHistoryOwnership fails closed when the synced outbox history in
// the state directory belongs to a different device than the currently
// bound one. The outbox does not record per-device attribution and
// cross-device de-duplication is not promised, so a mismatch must never
// retransmit — it would double count the history under the new device.
func checkHistoryOwnership(stateDir string) error {
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		return err
	}
	if st.DeviceID == "" {
		return nil
	}
	ownership, has, err := loadOwnership(stateDir)
	if err != nil {
		return err
	}
	if has && ownership.DeviceID != st.DeviceID {
		return fmt.Errorf("history retransmission blocked: the synced history in this state directory belongs to device %s, but this collector is bound as %s; cross-device de-duplication is not guaranteed, so connect refuses to retransmit it — use a separate state directory, or remove %s only if you accept abandoning the ownership record", ownership.DeviceID, st.DeviceID, ownershipPath(stateDir))
	}
	return nil
}

// runResyncPhase executes the retransmission under an exclusive state
// lock. A busy lock after the retry budget and a server-side pause are
// reported through ResyncSummary.Skipped (the completeness evaluation
// turns them into an incomplete result); an authorization-driven "nothing
// eligible" outcome is reported through NotApplicable; a decline of the
// shared run budget is a graceful stop (budgetStopped=true, the journal
// stays resumable); every other failure is a hard error returned as-is
// for the caller to wrap.
func runResyncPhase(ctx context.Context, stateDir string, opt SyncOptions, snapshot *resync.SyncedBatchSnapshot, d *display, now func() time.Time, progress func(collection.ProgressEvent)) (summary ResyncSummary, hardErr error, budgetStopped bool) {
	summary = ResyncSummary{}

	// The history phase's own emitter: the retransmission can be long,
	// and no collection round is alive at this point (the backlog
	// passes have finished), so its ticker never overlaps a round's. A
	// nil progress keeps everything unwired.
	var emitter *collection.ProgressEmitter
	resyncProgress := progressResyncOrDefault(opt.ResyncProgress, d)
	if progress != nil {
		emitter = collection.NewProgressEmitter(ctx, progress, collection.DefaultProgressHeartbeat)
		defer emitter.Stop()
		emitter.EnterStage("history")
		base := resyncProgress
		resyncProgress = func(ev resync.ProgressEvent) {
			// The human line prints only under --verbose (the concise
			// default carries the phase summary and the final result
			// instead); the unified stream gets the adapted batch event
			// alongside either way. The done outcome's counts are
			// aggregates over the parent's stored receipts (earlier
			// rounds included), so they are NEVER folded into this
			// round's processing rate — the history phase reports no
			// rate of its own.
			base(ev)
			emitter.Dispatch(historyBatchEvent(ev))
		}
	}

	// resync.Run never locks; this phase owns the exclusive state lock.
	// A scheduled collection task may hold it right after connect
	// installed it, hence the bounded retry.
	lock, err := acquireStateLock(ctx, stateDir)
	if err != nil {
		if errors.Is(err, runlock.ErrBusy) {
			summary.Skipped = fmt.Sprintf("the state directory stayed busy for %s (another collector process — likely the scheduled task — holds the lock); the history was NOT retransmitted", stateLockRetryTotal)
			summary.Stop = ResyncStopBusy
			d.phase("history retransmission: not run (the state directory stayed busy; another collector process holds the lock)")
			return summary, nil, false
		}
		return summary, fmt.Errorf("acquire state lock for history retransmission: %w", err), false
	}
	res, resyncErr := resync.Run(ctx, resync.Options{
		StateDir:   stateDir,
		ServerURL:  opt.ServerURL,
		HTTPClient: opt.HTTPClient,
		MaxBatches: opt.ResyncMaxBatches,
		Budget:     opt.Budget,
		Retry:      opt.Retry,
		Snapshot:   snapshot,
		Confirm:    confirmResyncOrDefault(opt, d),
		Progress:   resyncProgress,
		Now:        now,
	})
	_ = lock.Close()

	summary = summarizeResync(res, true)
	// Even an empty or nothing-eligible retransmission must confirm the
	// live consent scope: an empty pass finalizes offline and a
	// nothing-eligible plan never prefetches, so without a round trip
	// here those outcomes could not observe a scope change that happened
	// after the initial collection. A failed confirmation leaves the
	// revision at zero, which the completeness evaluation reports as
	// unconfirmed — never as success.
	if summary.ConsentRevision <= 0 && (resyncErr == nil || errResyncNothingEligible(resyncErr)) {
		// Durable authorization-attempt accounting precedes this
		// authenticated self GET, mirroring the grant sync, the sync
		// preflight and resync's own authorization check. If the
		// accounting write fails, ZERO HTTP happens: the confirmation is
		// best-effort by design, so the run keeps its honest unconfirmed
		// revision (reported as an incompleteness, never as success) and
		// the next run re-attempts it — nothing is mutated, so the
		// failure is fully recoverable.
		if _, aErr := outbox.New(stateDir).RecordPreflightAttempt(now().UTC()); aErr == nil {
			if self, err := syncclient.FetchDeviceSelf(ctx, statedir.New(stateDir), syncclient.Options{
				ServerURL:  opt.ServerURL,
				HTTPClient: opt.HTTPClient,
			}); err == nil {
				summary.ConsentRevision = self.ConsentRevision
			}
		}
	}
	if resyncErr != nil {
		if errors.Is(resyncErr, syncclient.ErrDevicePaused) {
			// Pause mirrors collection's semantics: a server state, not
			// a run failure. Nothing was sent; the job stays resumable.
			summary.Skipped = resyncErr.Error()
			summary.Stop = ResyncStopPaused
			d.phase("history retransmission: skipped (device paused)")
			return summary, nil, false
		}
		if errResyncNothingEligible(resyncErr) {
			// No synced batch matches the currently enabled local grants.
			// After connect applied this authorization's tool set that is
			// an authorization verdict (sources deliberately disabled or
			// narrowed), not a failure: report it, do not alarm.
			summary.NotApplicable = resyncErr.Error()
			summary.Stop = ResyncStopNothingEligible
			d.phase("history retransmission: nothing eligible under the current authorization")
			return summary, nil, false
		}
		if budgetDeclined(resyncErr) {
			// The shared run budget declined the next history POST after
			// its authorization preflight but before the POST itself:
			// nothing was submitted, the declined target was NOT marked
			// failed, and the journal keeps the job resumable (resync's
			// own stop contract). A budget stop is an honest incomplete,
			// never a hard run failure.
			summary.Stop = ResyncStopBudget
			d.phase("history retransmission: stopped at the shared sync budget (the job stays resumable; nothing was marked failed)")
			return summary, nil, true
		}
		summary.Stop = ResyncStopFailed
		return summary, resyncErr, false
	}
	// A clean round that did not finish its plan is a resumable stop,
	// not a completion (resync's own stop contract).
	if summary.Completed {
		summary.Stop = ResyncStopCompleted
	} else {
		summary.Stop = ResyncStopStopped
	}
	printResyncSummary(d, summary)
	return summary, nil, false
}

// errResyncNothingEligible matches the stable wordings resync uses when
// planning found no eligible batch because of the local grant state
// (nothing matches an enabled grant, or no grant config exists). Those
// are authorization verdicts — connect itself disables grants the
// authorization dropped — unlike a corrupt or unreadable grant store,
// which surfaces as a different error and stays a hard failure. The
// wording coupling mirrors how collection matches syncclient diagnoses;
// resync's own tests pin these strings.
func errResyncNothingEligible(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "match a currently enabled local source grant") ||
		strings.Contains(msg, "no local source grants are configured")
}

// budgetDeclined reports whether err is a decline of the shared run
// budget — the run-wide total, a queue's own cap, or the budget's own
// deadline ran out BEFORE an ingest POST was made (the sending layers
// reserve right before the POST and return the sentinel on a decline).
// It mirrors resync's own budgetDecline classification. A canceled
// caller context is deliberately NOT a decline: it keeps the original
// failure semantics instead of being dressed up as a budget stop.
func budgetDeclined(err error) bool {
	return errors.Is(err, syncbudget.ErrTotalExhausted) ||
		errors.Is(err, syncbudget.ErrQueueExhausted) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded)
}

// budgetTotalOrDeadlineDeclined reports whether the decline leaves no
// room for ANY queue: the run-wide total is spent, or the budget's own
// deadline is past (Reserve checks it before every grant, so a passed
// deadline declines every later attempt too). A queue-only decline does
// not: the other queues may still post.
func budgetTotalOrDeadlineDeclined(err error) bool {
	return errors.Is(err, syncbudget.ErrTotalExhausted) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded)
}

// deviceQueueSpent reports whether the device outbox queue already spent
// a configured per-queue cap of its own (the account and history queues
// are unaffected by it). A budget without a device queue cap — the
// default — never reports true.
func deviceQueueSpent(budget *syncbudget.Budget) bool {
	remaining, capped := budget.QueueRemaining(budgetQueueDevice)
	return capped && remaining <= 0
}

// cursorQueueSpent is deviceQueueSpent's mirror for the account-source
// ("cursor") queue: true only when that queue spent a configured
// per-queue cap of its own, which the device and history queues are
// unaffected by. A budget without a cursor queue cap never reports true.
func cursorQueueSpent(budget *syncbudget.Budget) bool {
	remaining, capped := budget.QueueRemaining(budgetQueueCursor)
	return capped && remaining <= 0
}

// historyBlockedByBudget reports whether the history retransmission
// phase must be skipped because the shared budget can no longer grant
// ANY history POST, and the phase actually has targets to cover. It is
// true only when both hold:
//
//   - the run-wide total is spent or a total/deadline decline already
//     surfaced in an earlier phase (a queue-only decline of the device or
//     account queue leaves the history queue its room, and an
//     unconfirmed deadline is left to the phase itself, which stops
//     gracefully on its first declined target); and
//   - the phase has possible targets: a caller snapshot with batch ids
//     (or no snapshot at all, meaning the full synced archive). An empty
//     connect snapshot — a first install — plans nothing and completes
//     offline, so it runs and completes honestly rather than being
//     reported as not-run.
//
// Skipping is what keeps a budget-exhausted run from burning a lock
// acquisition, a job plan and an authorization preflight on a POST that
// the budget has already declined.
func historyBlockedByBudget(syncRes SyncResult, snapshot *resync.SyncedBatchSnapshot, budget *syncbudget.Budget) bool {
	if budget == nil {
		return false
	}
	blocked := syncRes.BudgetExhausted
	if !blocked {
		if remaining, ok := budget.Remaining(); ok && remaining <= 0 {
			blocked = true
		}
	}
	if !blocked {
		return false
	}
	return snapshot == nil || len(snapshot.BatchIDs) > 0
}

// runBacklogPass runs ONE backlog drain pass under a single exclusive state
// lock, acquired through the shared bounded busy retry: while another
// collector process (typically the scheduled task) holds the lock, the pass
// waits and retries instead of failing the drain; past the retry budget it
// returns runlock.ErrBusy having performed no work, which drainBacklog
// reports as the pass's failure exactly like a failed drain.
//
// The lock is held CONTINUOUSLY across the pass's three sub-phases (see
// runBacklogPassLocked): the device authorization refresh and drain, the
// account-source drain, and the terminal authorization check. One lock for
// all three is the point: with per-sub-phase locking, a scheduled collection
// could interleave between them — mutating the outbox and the grant view the
// terminal check compares against — so the pass would either work on stale
// state or fail with spurious lock contention. The locked entry points never
// take the runlock themselves (the flock is per open file description, so a
// nested acquire would fail with ErrBusy); they verify the handed-over lock
// handle instead (runlock.Lock.Validate).
func runBacklogPass(ctx context.Context, collectOpts collection.Options, cursorPending int, skipDevice, skipCursor bool) (collection.Result, error) {
	// One emitter for the WHOLE pass (device drain, account drain and
	// the terminal authorization check): the collection rounds inside
	// reuse it through WithProgressEmitter, so no two heartbeat tickers
	// ever overlap and this single deferred Stop owns the goroutine. A
	// nil Progress keeps the pass completely unwired.
	if collectOpts.Progress != nil {
		emitter := collection.NewProgressEmitter(ctx, collectOpts.Progress, collection.DefaultProgressHeartbeat)
		defer emitter.Stop()
		collectOpts = collectOpts.WithProgressEmitter(emitter)
		if collectOpts.Cursor != nil {
			// The backlog's account drain cannot correlate events to
			// entries positionally, so its provenance label is unknown.
			cursor := *collectOpts.Cursor
			cursor.Progress = collection.CursorProgressEvents(emitter, collection.OriginUnknown)
			collectOpts.Cursor = &cursor
		}
	}
	lock, err := acquireStateLock(ctx, collectOpts.StateDir)
	if err != nil {
		if errors.Is(err, runlock.ErrBusy) {
			// Past the retry budget: no work was performed. The pass
			// stays a hard failure (the initial collection pass treats
			// an exhausted budget the same way); the pending counts the
			// caller already holds remain the honest state.
			return collection.Result{}, fmt.Errorf("the state directory stayed busy for %s (another collector process — likely the scheduled task — holds the lock); the backlog pass was NOT run: %w", stateLockRetryTotal, err)
		}
		// A cancelled context or a hard lock failure.
		return collection.Result{}, err
	}
	defer lock.Close()
	return runBacklogPassLocked(ctx, collectOpts, cursorPending, skipDevice, skipCursor, lock)
}

// runBacklogPassLocked is runBacklogPass's already-held-lock path: the whole
// pass — device drain, account drain, terminal authorization check — under
// the caller's lock. It drains persisted device and account queues without
// rescanning source files or pulling account history; authorization is
// refreshed around each sub-phase and account-source fence checks still run
// before uploads.
func runBacklogPassLocked(ctx context.Context, collectOpts collection.Options, cursorPending int, skipDevice, skipCursor bool, lock *runlock.Lock) (collection.Result, error) {
	collectOpts.RefreshDrainGrants = true
	collectOpts.SkipDeviceDrain = skipDevice
	res, err := collection.DrainPendingLocked(ctx, collectOpts, lock)
	if err != nil || cursorPending == 0 || skipCursor {
		// skipCursor: the account queue already spent its own budget
		// cap, so this pass deliberately drains the device queue only —
		// the caller keeps the known cursor pending count (this result
		// carries no cursor recount to adopt).
		return res, err
	}
	if res.GrantSync.Paused {
		res.Cursor.PendingRemaining = cursorPending
		res.Cursor.Skipped = "server reports collection paused"
		return res, nil
	}
	if collectOpts.Cursor == nil {
		res.Cursor.PendingRemaining = cursorPending
		return res, errors.New("cursor backlog exists but cursor options are unavailable")
	}
	cursor, err := cursorsync.DrainPendingLocked(ctx, *collectOpts.Cursor, cursorsync.Gate{AllowedTools: res.GrantSync.AllowedTools}, lock)
	if cursor.Skipped != "" && cursor.PendingRemaining == 0 {
		cursor.PendingRemaining = cursorPending
	}
	res.Cursor = cursor
	if err != nil {
		return res, err
	}
	checkOpts := collectOpts
	checkOpts.SkipDeviceDrain = true
	checked, err := collection.DrainPendingLocked(ctx, checkOpts, lock)
	if err != nil {
		return res, err
	}
	// The terminal check's verdict is passed through structurally: a
	// mid-drain pause stays a pause (batches stay queued), only an
	// actual revision or active-state drift is a scope change.
	if res.GrantSync.Active && (!checked.GrantSync.Active || res.GrantSync.ConsentRevision != checked.GrantSync.ConsentRevision) {
		res.DrainStopped = "server authorization changed during account backlog drain; a new collection is required"
		res.DrainStop = collection.DrainStopScope
	} else if checked.DrainStopped != "" {
		res.DrainStopped = checked.DrainStopped
		res.DrainStop = checked.DrainStop
	}
	res.GrantSync = checked.GrantSync
	res.PendingRemaining = checked.PendingRemaining
	res.PendingCounted = checked.PendingCounted
	return res, nil
}

// drainBacklog runs the backlog drain passes over the two NEW queues —
// the device outbox and the account source — until they are empty or a
// bound stops the loop. Each pass drains BOTH queues under one state
// lock (see runBacklogPass), so the queues rotate fairly: neither can
// starve the other while the other still holds batches. On a budgeted
// run (budget != nil and no explicit pass bound) the loop is bounded
// only by the budget and the no-progress guard — it drains the queues to
// empty instead of stopping at the historical pass bound. A budget
// decline from a pass is a graceful stop, never a failure: the declined
// batch was never POSTed and stays pending, and the loop records why it
// stopped for the completeness evaluation.
func drainBacklog(ctx context.Context, syncRes SyncResult, collectOpts collection.Options, d *display, maxPasses int, budget *syncbudget.Budget) (SyncResult, error) {
	if collectOpts.Cursor != nil {
		cursor := *collectOpts.Cursor
		cursor.ForceResync = false
		collectOpts.Cursor = &cursor
	}
	// The backlog passes drain BOTH queues without pulling anything by
	// construction (runBacklogPassLocked drives cursorsync's drain-only
	// path directly), so the initial round's drain-only marker must not
	// ride along and suggest a collection.Run cursor phase here.
	collectOpts.CursorDrainOnly = false
	var passErr error
	pending := syncRes.Collection.PendingRemaining
	cursorPending := syncRes.Collection.Cursor.PendingRemaining
	if pending > 0 || cursorPending > 0 {
		d.detail("draining backlog...")
	}
	// A queue that already spent its OWN budget cap cannot post; skip
	// its drain so the OTHER queue still advances (once the other queue
	// is empty too, the loop head below stops). Fairness is symmetric:
	// a spent device cap must not starve the account queue, and a spent
	// account (cursor) cap must not starve the device queue.
	skipDevice := deviceQueueSpent(budget)
	skipCursor := false
	for pending > 0 || cursorPending > 0 {
		if skipDevice && cursorPending == 0 {
			syncRes.Backlog.Stopped = "the device queue's own sync budget cap is exhausted"
			break
		}
		if skipCursor && pending == 0 {
			syncRes.Backlog.Stopped = "the cursor queue's own sync budget cap is exhausted"
			break
		}
		if skipDevice && skipCursor {
			// Both queues spent their own caps while the run-wide
			// budget still has room: nothing is drainable this run.
			syncRes.Backlog.Stopped = "both queues' own sync budget caps are exhausted"
			break
		}
		if syncRes.Backlog.Passes >= maxPasses {
			syncRes.Backlog.Stopped = fmt.Sprintf("backlog pass bound (%d) reached", maxPasses)
			break
		}
		if n, ok := budget.Remaining(); ok && n <= 0 {
			// The run-wide total is spent: no queue may POST anything,
			// so no pass is run at all — the pending counts this run
			// already holds are the honest state.
			syncRes.Backlog.Stopped = backlogBudgetStopped
			syncRes.BudgetExhausted = true
			break
		}
		d.detail("draining backlog (pendingBatches=%d pendingCursorBatches=%d)...", pending, cursorPending)
		passRes, err := runBacklogPass(ctx, collectOpts, cursorPending, skipDevice, skipCursor)
		if cursorPending == 0 && syncRes.Backlog.Passes == 0 {
			passRes.Cursor.Ran = syncRes.Collection.Cursor.Ran
			passRes.Cursor.Skipped = syncRes.Collection.Cursor.Skipped
			passRes.Cursor.Status = syncRes.Collection.Cursor.Status
			passRes.Cursor.Note = syncRes.Collection.Cursor.Note
		}
		syncRes.Backlog.Passes++
		accumulateCollection(&syncRes.Backlog.Result, passRes)
		if err != nil {
			if budgetDeclined(err) {
				// Graceful budget stop. The declining sub-phase already
				// recounted its own queue (the declined batch stays
				// pending); the other queue's count is only adopted when
				// its sub-phase actually ran this pass.
				pending = passRes.PendingRemaining
				if passRes.Cursor.Ran || passRes.Cursor.Skipped != "" || passRes.Cursor.PendingRemaining > 0 {
					cursorPending = passRes.Cursor.PendingRemaining
				}
				if !skipDevice && errors.Is(err, syncbudget.ErrQueueExhausted) && cursorPending > 0 && deviceQueueSpent(budget) {
					// Only the DEVICE queue hit its own cap while the
					// run-wide budget still has room: keep draining the
					// account queue with the device drain skipped. This
					// continuation happens at most once — a later decline
					// (the account queue's own cap, the total, the
					// deadline) breaks below, so a capped account queue
					// can never spin the loop.
					skipDevice = true
					continue
				}
				if !skipCursor && errors.Is(err, syncbudget.ErrQueueExhausted) && pending > 0 && cursorQueueSpent(budget) {
					// The MIRROR case: only the CURSOR (account) queue
					// hit its own cap while the run-wide budget still has
					// room and the device queue still holds batches: keep
					// draining the device queue with the cursor drain
					// skipped. Like the device-side continuation this
					// happens at most once — a later decline (the device
					// queue's own cap, the total, the deadline) breaks
					// below, so neither queue can starve the other or
					// spin the loop.
					skipCursor = true
					continue
				}
				if errors.Is(err, syncbudget.ErrQueueExhausted) && cursorQueueSpent(budget) {
					syncRes.Backlog.Stopped = "the cursor queue's own sync budget cap is exhausted"
				} else if errors.Is(err, syncbudget.ErrQueueExhausted) && deviceQueueSpent(budget) {
					syncRes.Backlog.Stopped = "the device queue's own sync budget cap is exhausted"
				} else {
					syncRes.Backlog.Stopped = backlogBudgetStopped
				}
				if budgetTotalOrDeadlineDeclined(err) {
					syncRes.BudgetExhausted = true
				}
				break
			}
			syncRes.Backlog.Err = err.Error()
			passErr = fmt.Errorf("backlog drain failed: %w", err)
			break
		}
		if d.verbose {
			// Per-pass rounds are verbose-only: a long drain shows its
			// progress through the heartbeat and its totals in the final
			// backlog summary, never as pass-by-pass noise.
			printCollectionRound(d, fmt.Sprintf("backlog pass %d", syncRes.Backlog.Passes), passRes)
		}
		if !backlogPassMadeProgress(passRes, pending, cursorPending, skipCursor) {
			// No batch moved and nothing was drained: paused, restricted,
			// or otherwise stuck. Stop instead of spinning; the
			// completeness evaluation reports it.
			syncRes.Backlog.Stopped = "a drain pass made no progress (paused, restricted, or nothing drainable)"
			break
		}
		pending = passRes.PendingRemaining
		if !skipCursor || passRes.Cursor.Ran || passRes.Cursor.Skipped != "" || passRes.Cursor.PendingRemaining > 0 {
			// A skip-cursor pass never runs the cursor sub-phase, so its
			// zeroed cursor result must not erase the known pending
			// count; adopt the recount only when the sub-phase ran (or
			// reported something).
			cursorPending = passRes.Cursor.PendingRemaining
		}
	}
	syncRes.Backlog.PendingRemaining = pending
	syncRes.Backlog.CursorPendingRemaining = cursorPending
	if syncRes.Backlog.Passes > 0 {
		// The concise default carries the phase outcome and its
		// boundary only; the counters are verbose detail (the final
		// result summary carries the natural-language totals).
		if pending > 0 || cursorPending > 0 {
			d.phase("backlog: not fully drained; batches remain pending")
		} else {
			d.phase("backlog: drained")
		}
		if syncRes.Backlog.Stopped != "" {
			// The stop reason renders behind a closed phrase derived
			// from structure; the stored free text is never echoed.
			d.phase("backlog: %s", backlogStopPhrase(syncRes, budget, maxPasses))
		}
		d.detail("backlog: passes=%d syncedBatches=%d syncedRecords=%d pendingBatches=%d pendingCursorBatches=%d",
			syncRes.Backlog.Passes, syncRes.Backlog.Result.SyncedBatches, syncRes.Backlog.Result.SyncedRecords,
			pending, cursorPending)
	}
	return syncRes, passErr
}

// backlogStopPhrase renders why the backlog drain stopped behind a
// fixed phrase derived from structure (the budget flags, the pass
// bound, the per-queue caps) - never the stored free text, which the
// sending layers may compose from unvetted error chains.
func backlogStopPhrase(syncRes SyncResult, budget *syncbudget.Budget, maxPasses int) string {
	switch {
	case syncRes.BudgetExhausted:
		return "stopped at the shared sync budget"
	case syncRes.Backlog.Passes >= maxPasses:
		return "stopped at the backlog pass bound"
	case budget != nil && deviceQueueSpent(budget):
		return "stopped at the device queue's own budget cap"
	case budget != nil && cursorQueueSpent(budget):
		return "stopped at the account queue's own budget cap"
	default:
		return "stopped early (paused, restricted, or a pass made no progress)"
	}
}

func backlogPassMadeProgress(pass collection.Result, devicePending, cursorPending int, skipCursor bool) bool {
	cursorUnchanged := skipCursor || pass.Cursor.PendingRemaining == cursorPending
	return pass.PendingRemaining != devicePending || !cursorUnchanged || pass.SyncedBatches != 0 || pass.Cursor.SyncedBatches != 0
}

// evaluateIncomplete lists every reason the current authorization was not
// fully covered. It never treats a bounded drain as success, never treats
// a pause as success, and never claims full retransmission coverage.
// Authorization-driven withholding — sources this run's grants disabled,
// history outside the live consent scope — is reported in the phase
// summaries but is deliberately NOT an incompleteness.
func evaluateIncomplete(syncRes *SyncResult, opt SyncOptions) []string {
	reasons := make([]string, 0)
	seen := map[string]bool{}
	add := func(format string, args ...any) {
		reason := fmt.Sprintf(format, args...)
		if !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}
	// Zero the structural twin flags this evaluation owns: a stale
	// marker from an earlier evaluation must never leak into the next.
	syncRes.accountIncomplete = false
	syncRes.firstSyncIncomplete = false

	// Source grants: every skip except a healthy empty scan is a failure
	// outcome collection reports only through GrantOutcomes.Skipped.
	outcomes := syncRes.Collection.GrantOutcomes
	outcomes = append(outcomes, syncRes.Backlog.Result.GrantOutcomes...)
	for _, o := range outcomes {
		if o.Skipped != "" && o.Skipped != noNewRecordsSkip {
			add("source %s (%s) did not complete: %s", o.Source, o.Input, o.Skipped)
		}
	}

	// An authorized source whose pending restriction could not be
	// classified (a reason outside the closed wire vocabulary) must not
	// read as success: the authorization names it, but nothing on this
	// device collected it. User-disabled and unsupported tools are
	// no-concern states, and a default input that was never detected is
	// the normal skip of a tool this device never installed (observable
	// through the pending map and the tool-status report, not an
	// incompleteness). Either round's grant view counts (the backlog
	// passes refresh it): the tools are merged by UNIQUE name, so a
	// tool restricted in both the initial round and a backlog pass
	// counts once while a real restriction from EITHER round is never
	// dropped.
	concernTools := collection.PendingConcernTools(
		syncRes.Collection.GrantSync.Pending,
		syncRes.Backlog.Result.GrantSync.Pending,
	)
	if len(concernTools) > 0 {
		add("%d authorized source(s) are not covered on this device (unclassified restriction); the next run retries them", len(concernTools))
	}

	// Whole-run skips: pause is a server state that must not look like
	// success; a missing grant set is only normal when the authorization
	// activated no local tool. A no-grants round that drained the
	// sendable queue (§6.1) has an empty Skipped — the drained counts
	// speak — so the reason text falls back to a fixed wording.
	c := syncRes.Collection
	if c.GrantSync.Paused {
		add("collection paused by the server: %s", c.Skipped)
	} else if c.NoGrants && hasAuthorizedLocalTool(opt.AuthorizedTools) {
		if c.Skipped != "" {
			add("no enabled source grants despite authorized tools: %s", c.Skipped)
		} else {
			add("no enabled source grants despite authorized tools; the device outbox was drained but no local source is scanning")
		}
	}

	// Final drain state (the last pass's numbers).
	final := c
	if syncRes.Backlog.Passes > 0 {
		final = syncRes.Backlog.Result
	}
	if final.PendingRemaining > 0 || final.Cursor.PendingRemaining > 0 {
		add("%d outbox batch(es) and %d cursor batch(es) are still pending; re-run connect, or let the scheduled collection continue them", final.PendingRemaining, final.Cursor.PendingRemaining)
	}
	if final.DrainStopped != "" {
		add("drain stopped early: %s", final.DrainStopped)
	}

	// A budget stop is its own named incompleteness: the queues above
	// already carry their honest pending counts, and this reason states
	// WHY the run stopped covering them — the shared budget, not a
	// failure — and that nothing was lost.
	if syncRes.BudgetExhausted {
		add("the run's shared sync POST budget declined further uploads before the authorization was fully covered; nothing was lost — pending batches stay queued and the history job stays resumable — re-run connect or let the scheduled collection continue under a fresh budget")
	}

	// Account sources named by the authorization must have completed a
	// round: only Skipped, Ran and the pending count judge completion —
	// a Note alone is never a failure. Callers that do not name account
	// tools explicitly (the resync CLI passes a nil list) must still not
	// swallow a failed cursor round: when a cursor permit exists locally
	// — whatever its status, since the current authorization needs the
	// data — under a grant the fresh sync allows, it joins the list. A
	// cursor the live authorization excludes — or one the device never
	// enabled or explicitly logged out — skipping normally is an
	// authorization verdict or the never-enabled steady state, never an
	// incompleteness.
	accountTools := opt.AccountTools
	if !namesTool(accountTools, cursorsource.ToolName) &&
		cursorRoundExpected(opt.StateDir, final.Cursor.Ran, final.GrantSync.AllowedTools) {
		accountTools = append(append([]string(nil), accountTools...), cursorsource.ToolName)
	}
	accountReasonsBefore := len(reasons)
	for _, tool := range accountTools {
		cur := final.Cursor
		switch {
		case !cur.Ran && cur.Skipped != "":
			add("account source %s did not run: %s", tool, cur.Skipped)
		case !cur.Ran:
			add("account source %s did not run this sync", tool)
		case cur.Skipped != "":
			add("account source %s failed: %s", tool, cur.Skipped)
		case cur.PendingRemaining > 0:
			add("account source %s has %d batch(es) still pending", tool, cur.PendingRemaining)
		}
	}
	// The account-source loop actually appended at least one
	// completion reason: record the structural twin the §6.5 summary
	// keys its account verdict codes on.
	syncRes.accountIncomplete = len(reasons) > accountReasonsBefore

	// A first-time enable whose first sync failed inside this run's
	// setup (CursorFirstSyncFailed): the command already spent its
	// single upstream pull — or stopped right before it — and the
	// initial round ran drain-only over the permit, so a clean cursor
	// round above must NOT read as success. The failure is its own
	// incompleteness reason; the permit and its queue keep their state
	// and the next run (connect or the scheduled collection) continues
	// the source.
	if opt.CursorFirstSyncFailed != "" {
		syncRes.firstSyncIncomplete = true
		add("account source %s did not complete its first sync in this run's setup: %s; the permit and its queue keep their state and the next run continues them", cursorsource.ToolName, opt.CursorFirstSyncFailed)
	}

	// A cursor round that skipped rows without a stable upstream event id
	// left usage events uncounted: no complete success may hide that gap,
	// regardless of who named the account source. The counter is only
	// ever produced by an actual round (initial or backlog pass), so a
	// non-zero sum is direct evidence of a real run that dropped data.
	if skipped := syncRes.Collection.Cursor.SkippedNoStableID + syncRes.Backlog.Result.Cursor.SkippedNoStableID; skipped > 0 {
		add("account source %s skipped %d usage event(s) without a stable upstream id; those events are not counted", cursorsource.ToolName, skipped)
	}

	// History retransmission: incomplete only when the phase did not run
	// (busy, paused) or the job is unfinished and resumable. Batches the
	// current authorization withholds (blocked, out of scope, grant
	// disabled) and server rejections are carried by the phase summaries
	// and resync's own error semantics, not counted here.
	r := syncRes.Resync
	if r.Skipped != "" {
		add("history retransmission not completed: %s", r.Skipped)
	}
	if r.Ran && r.Remaining > 0 {
		add("%d history batch(es) remain un-retransmitted; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)", r.Remaining)
	}
	if r.Ran && !r.Completed && r.Stopped != "" {
		// A stopped job (upload failure, budget reached) is unfinished
		// even when the error path did not populate Remaining.
		add("history retransmission stopped before finishing: %s; re-run connect or toktrail resync --all to resume (the scheduled task does not continue a resync job)", r.Stopped)
	}

	// Cross-phase scope consistency (active grant protocol only): the
	// initial collection, the history retransmission AND the backlog
	// drain passes must all have observed the same consent revision. A
	// run that straddled a server-side scope change must not report
	// success — the collection drain recovered quarantine and uploaded
	// under the old scope, so records the new scope governs (for example
	// quarantined data a widened scope would allow again) were never
	// re-covered this run. An unconfirmed retransmission revision is
	// refused the same way: unknown is never success.
	if syncRes.Collection.GrantSync.Active && r.Ran {
		collected := syncRes.Collection.GrantSync.ConsentRevision
		switch {
		case r.ConsentRevision <= 0:
			add("history retransmission could not confirm the live consent scope (collection ran under revision %d); re-run to cover the current authorization", collected)
		case r.ConsentRevision != collected:
			add("the consent scope moved between the collection (revision %d) and the history retransmission (revision %d); re-run to cover the current authorization", collected, r.ConsentRevision)
		}
		// The backlog passes re-run the grant sync; the accumulated
		// GrantSync carries the LAST pass's applied revision. A drain
		// that ran under a newer scope than the initial collection mixes
		// old-scope and new-scope uploads, and one that ran under an
		// older scope cannot cover the current authorization either.
		if syncRes.Backlog.Passes > 0 {
			if last := syncRes.Backlog.Result.GrantSync.ConsentRevision; last != collected {
				add("the consent scope moved between the collection (revision %d) and the backlog drain (revision %d); re-run to cover the current authorization", collected, last)
			}
		}
	}
	return reasons
}

// hasAuthorizedLocalTool reports whether any activated tool maps to a
// local directory grant (account-network tools do not).
func hasAuthorizedLocalTool(tools []string) bool {
	for _, name := range tools {
		if spec, ok := registry.LookupTool(name); ok && !spec.IsAccountNetwork() {
			return true
		}
	}
	return false
}

// cursorRoundExpected reports whether this sync must hold the cursor
// account source to the completion contract even though the caller did
// not name it explicitly (the resync CLI passes no account-tool list).
// Two signals identify a cursor source this run owes data for:
//
//   - the round already RAN: direct evidence the source was enabled and
//     authorized this run. A mid-round failure — even one that pauses
//     the permit afterwards (an expired login) — must never be
//     swallowed, so this short-circuits true.
//   - otherwise, a cursor permit that EXISTS locally — whatever its
//     status — under a grant the fresh sync allows for Cursor. The
//     current authorization needs the account data, so a paused or
//     login_expired permit skipping its round is an incompleteness to
//     report, never a silent success. Logout REMOVES the permit, so an
//     absent permit (never enabled, or explicitly logged out) is the
//     only local steady state that owes nothing; an unreadable permit
//     file fails toward reporting (the source exists but cannot be
//     verified).
//
// A cursor the authorization allows but the device never enabled owes
// nothing here — enabling is a local confirmation gesture, reported via
// the explicit list by the connect authorization that names Cursor.
func cursorRoundExpected(stateDir string, cursorRan bool, allowedTools []string) bool {
	if cursorRan {
		return true
	}
	if !cursorAllowedByTools(allowedTools) {
		return false
	}
	_, ok, err := cursorsource.New(stateDir).Load()
	if err != nil {
		return true
	}
	return ok
}

// cursorAllowedByTools mirrors the grant-scope semantics
// (cursorsync.Gate.cursorAllowed; managedconsent's empty-list means
// unrestricted): an empty tool list is unrestricted, a non-empty list
// must name the cursor tool.
func cursorAllowedByTools(tools []string) bool {
	return len(tools) == 0 || namesTool(tools, cursorsource.ToolName)
}

// namesTool reports whether the list names the tool (trimmed
// comparison, matching the grant-scope semantics).
func namesTool(tools []string, name string) bool {
	for _, t := range tools {
		if strings.TrimSpace(t) == name {
			return true
		}
	}
	return false
}

// runCollectionPass runs one collection round, retrying while the state
// lock is busy: a scheduled task installed moments ago (or a pre-existing
// one on a reconnect) may hold it, and a busy collection.Run performed no
// work, so the retry is safe.
func runCollectionPass(ctx context.Context, opt collection.Options) (collection.Result, error) {
	deadline := time.Now().Add(stateLockRetryTotal)
	for {
		res, err := collection.Run(ctx, opt)
		if !errors.Is(err, runlock.ErrBusy) {
			return res, err
		}
		if time.Now().After(deadline) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(stateLockRetryDelay):
		}
	}
}

// acquireStateLock acquires the exclusive state lock, retrying while
// another process (typically a scheduled collection run) holds it.
func acquireStateLock(ctx context.Context, stateDir string) (*runlock.Lock, error) {
	deadline := time.Now().Add(stateLockRetryTotal)
	for {
		lock, err := runlock.Acquire(stateDir)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, runlock.ErrBusy) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(stateLockRetryDelay):
		}
	}
}

// cursorOptionsForCollection clones the cursor wiring for a collection
// round. The first (initial) round forces one full-range recovery pull;
// backlog rounds must not force again — the forced round re-emits
// unchanged events at a fresh revision, which is a recovery semantic, not
// something to repeat every pass. A run whose setup just performed the
// first-time enable (CursorFreshlyEnabled) runs the initial round's
// cursor phase drain-only instead (SyncOptions.CursorFreshlyEnabled
// drives collection.Options.CursorDrainOnly), so the enable's own first
// sync stays the run's single upstream pull; the ForceResync flag is
// then moot for that round but stays cleared for clarity. A failed
// enable — or a reconnect over an existing permit — never sets the
// marker and keeps the forced full round below exactly as before.
func cursorOptionsForCollection(opt SyncOptions, force bool) *cursorsync.Options {
	if opt.Cursor == nil {
		return nil
	}
	c := *opt.Cursor
	c.StateDir = opt.StateDir
	c.ServerURL = opt.ServerURL
	c.HTTPClient = opt.HTTPClient
	c.Out = opt.Out
	c.ForceResync = force && !opt.CursorFreshlyEnabled
	// One run, one retry policy: the account-source uploads retry under
	// the same bounded policy (and the same run deadline) as the device
	// and history queues. An explicitly wired Cursor.Retry still wins so
	// a specialized caller keeps control.
	if c.Retry == nil {
		c.Retry = opt.Retry
	}
	return &c
}

// syncedBatchIDs lists the outbox entries already marked synced, in outbox
// order. It must only be called while holding the state lock (connect's
// setup phase does) — the outbox is process-shared state. The result is
// always a usable slice (empty, never nil, when nothing is synced) so the
// snapshot built from it keeps the empty-set semantics distinct from nil.
func syncedBatchIDs(stateDir string) ([]string, error) {
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

// confirmResyncOrDefault builds the confirm hook for the EXECUTED
// retransmission. The caller's interactive hook (the resync CLI) already
// confirmed this run up front, before any collection or upload; the
// executed plan may additionally contain batches this run's collection
// synced, so it is printed for transparency but not re-prompted. Without
// a caller hook (connect) there is no interaction at all: the connect
// link is itself the user's authorization gesture, and the plan is
// printed for the record.
func confirmResyncOrDefault(opt SyncOptions, d *display) func(resync.Plan) error {
	return func(plan resync.Plan) error {
		printResyncPlan(d, plan)
		if opt.ResyncConfirm != nil {
			d.detail("history retransmission proceeding under the confirmation given before this run started")
		} else {
			d.detail("history retransmission confirmed by this authorization")
		}
		return nil
	}
}

func progressResyncOrDefault(progress func(resync.ProgressEvent), d *display) func(resync.ProgressEvent) {
	if progress != nil {
		return progress
	}
	return func(ev resync.ProgressEvent) {
		if !d.verbose {
			// Per-batch lines are verbose-only: the default output keeps
			// the phase summary and the heartbeat, never per-batch noise.
			return
		}
		d.detail("history batch: %s submitted=%d accepted=%d rejected=%d skipped=%d replay=%t",
			sealedOutcome(ev.Outcome), ev.Uploaded, ev.Accepted, ev.Rejected, ev.Skipped, ev.Replay)
	}
}

func progressOverrideOrDefault(progress func(resync.OverrideProgressEvent), d *display) func(resync.OverrideProgressEvent) {
	if progress != nil {
		return progress
	}
	return func(ev resync.OverrideProgressEvent) {
		if !d.verbose {
			return
		}
		d.detail("override batch: %s records=%d accepted=%d rejected=%d replay=%t",
			sealedOutcome(ev.Outcome), ev.Records, ev.Accepted, ev.Rejected, ev.Replay)
	}
}

// summarizeOverride maps an override result onto the connect summary.
// It never claims more than the receipts proved: RejectedRecords and
// RemainingPending (mapped to Remaining) carry what was NOT repaired.
func summarizeOverride(res resync.OverrideResult, ran bool) ResyncSummary {
	return ResyncSummary{
		Ran:                      ran,
		DryRun:                   res.DryRun,
		Completed:                res.Completed,
		ConsentRevision:          res.Self.ConsentRevision,
		Uploads:                  res.Uploads,
		UploadedRecords:          res.UploadedRecords,
		AcceptedRecords:          res.ReplacedRecords + res.InsertedRecords,
		RejectedRecords:          res.RejectedRecords,
		SkippedOutOfScopeRecords: res.WithheldOutOfScope,
		Remaining:                res.RemainingPending,
	}
}

// printResyncPlan prints the frozen plan (the same summary the resync CLI
// prints) so the user sees exactly what will be retransmitted and what
// the phase does NOT cover.
func printResyncPlan(d *display, plan resync.Plan) {
	// The target line (server URL, device id) is never printed in ANY
	// mode: both are unvetted reflection surfaces.
	if len(plan.Batches) == 0 {
		// An empty plan has nothing to confirm and nothing to cover: a
		// first install's automatic pass prints nothing by default (the
		// verbose detail below keeps the record).
		d.detail("plan: empty - no synced history is eligible under the current authorization")
	} else {
		if plan.Resumed {
			// A resumed journal carries the batch list and the done count
			// but not necessarily a records total (the resume path may
			// leave PlannedRecords unset); the provable batch count is the
			// only claim - an unknown record total is never shown as zero.
			d.phase("plan: resuming an unfinished retransmission job; %d batch(es) remain in the plan.", len(plan.Batches))
		} else {
			d.phase("plan: %d batch(es) (%d record(s)) to retransmit.", len(plan.Batches), plan.PlannedRecords)
		}
		// The coverage limitation in ONE short fixed line (the long
		// local note stays verbose). The PLAN's own SnapshotRestricted
		// marker is the single authority - it is set for a fresh
		// connect pass (CaptureResyncSnapshot), for an explicitly
		// passed snapshot, and for a resumed job's journal-frozen
		// universe alike - so the wording never depends on how the
		// caller wired the option. A resumed restricted job names its
		// ORIGINAL snapshot (frozen when the job was planned, possibly
		// by an earlier run); only a fresh pass may say "before this
		// run".
		if plan.SnapshotRestricted {
			if plan.Resumed {
				d.phase("History replay covers this device only, limited to the job's original snapshot; account history and quarantined records are excluded.")
			} else {
				d.phase("History replay covers this device only, and only the batches already synced before this run; batches synced during this run, account history and quarantined records are excluded.")
			}
		} else {
			d.phase("History replay covers this device only; account history and quarantined records are excluded.")
		}
	}
	d.detail("%s", plan.CoverageNote)
	d.detail("De-duplication applies to the current device only; this phase never creates a device or clears progress.")
	d.detail("plan detail: batches=%d records=%d resumed=%t alreadyDone=%d excludedPending=%d reorganizedParents=%d localGrantBatches=%d afterSnapshotBatches=%d quarantineRecords=%d",
		len(plan.Batches), plan.PlannedRecords, plan.Resumed, plan.DoneInJob,
		plan.ExcludedPending, plan.ExcludedReorganized, len(plan.ExcludedLocalGrant), plan.ExcludedAfterSnapshot, plan.QuarantinedRecords)
}

// summarizeResync maps a resync.Result onto the connect summary.
func summarizeResync(res resync.Result, ran bool) ResyncSummary {
	return ResyncSummary{
		Ran:                      ran,
		DryRun:                   res.DryRun,
		JobID:                    res.Plan.JobID,
		Resumed:                  res.Plan.Resumed,
		Completed:                res.Completed,
		ConsentRevision:          res.Self.ConsentRevision,
		Uploads:                  res.Uploads,
		UploadedRecords:          res.UploadedRecords,
		AcceptedRecords:          res.AcceptedRecords,
		RejectedRecords:          res.RejectedRecords,
		ReplayReceipts:           res.ReplayReceipts,
		Blocked:                  res.Blocked,
		SkippedOutOfScopeRecords: res.SkippedOutOfScopeRecords,
		Remaining:                res.Remaining,
		ExcludedPending:          res.Plan.ExcludedPending,
		ExcludedReorganized:      res.Plan.ExcludedReorganized,
		ExcludedLocalGrant:       len(res.Plan.ExcludedLocalGrant),
		ExcludedAfterSnapshot:    res.Plan.ExcludedAfterSnapshot,
		QuarantinedRecords:       res.Plan.QuarantinedRecords,
		Stopped:                  res.Stopped,
	}
}

// printResyncSummary prints the round's outcome; it mirrors the resync
// CLI's report, including the explicit statements about withheld
// history, so partial coverage is never presented as a full restore.
func printResyncSummary(d *display, summary ResyncSummary) {
	d.detail("history retransmission: stop=%s completed=%t uploads=%d submitted=%d accepted=%d rejected=%d blocked=%d skipped=%d remaining=%d",
		summary.Stop, summary.Completed, summary.Uploads, summary.UploadedRecords, summary.AcceptedRecords, summary.RejectedRecords,
		summary.Blocked, summary.SkippedOutOfScopeRecords, summary.Remaining)
	if summary.Remaining > 0 {
		d.detail("history retransmission: the job is unfinished; resume it explicitly with toktrail resync --all when intended (the scheduled task does not continue a resync job).")
	}
	if summary.Blocked > 0 || summary.SkippedOutOfScopeRecords > 0 {
		d.phase("history retransmission: some history was not retransmitted because it is outside the current authorization; original archives remain unchanged.")
	}
	if summary.ExcludedAfterSnapshot > 0 {
		d.phase("history retransmission: %d batch(es) synced during this run were not re-sent (they were just uploaded by this run's collection).", summary.ExcludedAfterSnapshot)
	}
}

// printCollectionRound prints one collection round's summary with the
// label the phase reports under. A no-grants round that actually drained
// the sendable queue (§6.1) reports the no-grants fact AND its counts —
// never a bare "skipped" that hides uploaded or still-pending batches.
func printCollectionRound(d *display, label string, res collection.Result) {
	if res.NoGrants {
		if res.SyncedBatches == 0 && res.PendingRemaining == 0 {
			d.phase("%s: no enabled source grants; skipped", label)
			return
		}
		d.phase("%s: no enabled source grants; drained the device outbox only", label)
	}
	// A pause is a server state worth naming in the default; the
	// healthy outcome is carried by the final result summary, and the
	// counters are verbose detail.
	if res.GrantSync.Paused {
		d.phase("%s: skipped (the device is paused server-side)", label)
	} else {
		d.detail("%s: finished", label)
	}
	d.detail("%s: exportedBatches=%d exportedRecords=%d syncedBatches=%d syncedRecords=%d",
		label, res.ExportedBatches, res.ExportedRecords, res.SyncedBatches, res.SyncedRecords)
	if res.Cursor.Ran {
		// The account-level cursor round is independent of the local
		// grant counts above; surface it so a cursor-only device never
		// looks like an all-zero run.
		d.detail("%s: cursor pulledEvents=%d newRecords=%d replacedRecords=%d reemittedRecords=%d uploadedRecords=%d pendingBatches=%d",
			label, res.Cursor.PulledEvents, res.Cursor.NewRecords,
			res.Cursor.ReplacedRecords, res.Cursor.ReemittedRecords, res.Cursor.SyncedRecords,
			res.Cursor.PendingRemaining)
	}
}

// accumulateCollection folds one drain pass into the backlog totals.
// Counters add up; state-like fields (pending counts, skip reasons,
// DrainStopped) reflect the latest pass.
func accumulateCollection(dst *collection.Result, pass collection.Result) {
	dst.ExportedBatches += pass.ExportedBatches
	dst.ExportedRecords += pass.ExportedRecords
	dst.SyncedBatches += pass.SyncedBatches
	dst.SyncedRecords += pass.SyncedRecords
	dst.AttemptedBatches += pass.AttemptedBatches
	dst.Recovered += pass.Recovered
	dst.Quarantined = pass.Quarantined
	dst.PendingRemaining = pass.PendingRemaining
	dst.PendingCounted = pass.PendingCounted
	dst.DrainStopped = pass.DrainStopped
	dst.DrainStop = pass.DrainStop
	dst.NoGrants = dst.NoGrants || pass.NoGrants
	if pass.Skipped != "" {
		dst.Skipped = pass.Skipped
	}
	dst.GrantOutcomes = append(dst.GrantOutcomes, pass.GrantOutcomes...)
	dst.GrantSync = pass.GrantSync
	dst.Grants = pass.Grants

	dst.Cursor.PulledEvents += pass.Cursor.PulledEvents
	dst.Cursor.NewRecords += pass.Cursor.NewRecords
	dst.Cursor.ReplacedRecords += pass.Cursor.ReplacedRecords
	dst.Cursor.ReemittedRecords += pass.Cursor.ReemittedRecords
	dst.Cursor.SkippedUnchanged += pass.Cursor.SkippedUnchanged
	dst.Cursor.SkippedNoStableID += pass.Cursor.SkippedNoStableID
	dst.Cursor.ExportedBatches += pass.Cursor.ExportedBatches
	dst.Cursor.SyncedBatches += pass.Cursor.SyncedBatches
	dst.Cursor.SyncedRecords += pass.Cursor.SyncedRecords
	dst.Cursor.Ran = dst.Cursor.Ran || pass.Cursor.Ran
	if pass.Cursor.Ran || pass.Cursor.Skipped != "" || pass.Cursor.Status != "" {
		dst.Cursor.Skipped = pass.Cursor.Skipped
		dst.Cursor.Status = pass.Cursor.Status
		dst.Cursor.Note = pass.Cursor.Note
	}
	if pass.Cursor.Ran || pass.Cursor.Skipped != "" || pass.Cursor.Status != "" || pass.Cursor.PendingRemaining > 0 {
		// A pass that skipped the cursor sub-phase (its queue's own
		// budget cap is spent) carries a zeroed cursor result; it must
		// not erase the accumulated pending count of the skipped queue.
		dst.Cursor.PendingRemaining = pass.Cursor.PendingRemaining
		dst.Cursor.PendingCounted = pass.Cursor.PendingCounted
	}
	dst.Cursor.FirstSyncCompleted = dst.Cursor.FirstSyncCompleted || pass.Cursor.FirstSyncCompleted
}
