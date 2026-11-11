package collection

import (
	"context"
	"errors"
	"sort"

	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncbudget"
	synccmd "toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

// ResultSchema is the version of the stable §6.5 JSON contract. It
// changes only when a field is added, renamed or removed; consumers
// key their compatibility on it.
const ResultSchema = 1

// ErrIncompleteRun is the honest incompleteness envelope the command
// layer wraps its non-zero incomplete exits in (a granted source that
// failed to read, an authorized source not covered, an incomplete
// account round). It is never a hard failure: Summarize classifies it
// from the structured result (partial, paused, scope_changed, ...) —
// the same walk a nil-error run gets — instead of defaulting to
// fatal_error.
var ErrIncompleteRun = errors.New("incomplete run")

// Structured, low-cardinality stop codes for the §6.5 contract. Every
// code is a closed enum assigned at the same site as the historical
// human-readable message (Result.DrainStopped, GrantOutcome.Skipped);
// the messages keep flowing to the human output unchanged, while the
// codes carry the machine classification. The verdicts built on them
// (Summarize, SummarizePhases) read ONLY these codes — never message
// text.

// DrainStopCode classifies why a device-queue drain stopped. The empty
// value means no stop was recorded (a clean drain, or a caller that has
// not run the drain at all — disambiguated by the pending count).
type DrainStopCode string

const (
	// DrainStopBounded: an explicit per-queue batch bound stopped the
	// drain with batches still pending (the legacy exit-zero bounded
	// stop; never a budget decline).
	DrainStopBounded DrainStopCode = "bounded"
	// DrainStopBudget: the run's shared upload budget declined the next
	// attempt before its POST; the batch stays pending.
	DrainStopBudget DrainStopCode = "budget"
	// DrainStopPaused: the server paused the device mid-drain; batches
	// stay queued.
	DrainStopPaused DrainStopCode = "paused"
	// DrainStopScope: the server authorization changed during the drain
	// (revision or active-state drift); a new collection is required.
	DrainStopScope DrainStopCode = "scope"
	// DrainStopFailed: an upload or its bookkeeping failed.
	DrainStopFailed DrainStopCode = "failed"
	// DrainStopNotRun: the drain was deliberately not attempted (a
	// count-only pass).
	DrainStopNotRun DrainStopCode = "not_run"
)

// GrantSkipCode classifies what one granted source produced. It is
// assigned next to GrantOutcome.Skipped (and to the exported case),
// mirroring the message vocabulary the human output keeps.
type GrantSkipCode string

const (
	// GrantExported: the grant produced at least one committed batch.
	GrantExported GrantSkipCode = "exported"
	// GrantNoNewRecords: a healthy empty scan (nothing since the last
	// confirmed baselines).
	GrantNoNewRecords GrantSkipCode = "no_new_records"
	// GrantNotAllowed: the server grant scope excludes this source.
	GrantNotAllowed GrantSkipCode = "not_allowed"
	// GrantInputInaccessible: the granted input path no longer reads.
	GrantInputInaccessible GrantSkipCode = "input_inaccessible"
	// GrantExportFailed: preparing the export failed.
	GrantExportFailed GrantSkipCode = "export_failed"
	// GrantSplitFailed: splitting the prepared export failed.
	GrantSplitFailed GrantSkipCode = "split_failed"
)

// knownGrantSkipCodes is the closed set of codes a Result can carry.
// SummarizePhases maps any other value to the summary fallback rather
// than forwarding an unvetted string into the stable JSON contract.
var knownGrantSkipCodes = map[GrantSkipCode]bool{
	GrantExported:          true,
	GrantNoNewRecords:      true,
	GrantNotAllowed:        true,
	GrantInputInaccessible: true,
	GrantExportFailed:      true,
	GrantSplitFailed:       true,
}

// knownDrainStopCodes is the closed set of drain stop codes a Result
// can carry (the empty value is handled separately: it means "no stop
// recorded" and is resolved against the pending count).
var knownDrainStopCodes = map[DrainStopCode]bool{
	DrainStopBounded: true,
	DrainStopBudget:  true,
	DrainStopPaused:  true,
	DrainStopScope:   true,
	DrainStopFailed:  true,
	DrainStopNotRun:  true,
}

// StopReason is the closed, low-cardinality verdict of one run (plan
// §6.5). It is derived ONLY from structured facts — error sentinels,
// the DrainStop/GrantSkip codes and the cursor round outcome — never
// from human-readable message text.
type StopReason string

const (
	// StopComplete: nothing the current authorization allows remains
	// owed — the device queue drained, the account round is clean (or
	// nothing was owed for it), and no records were rejected.
	StopComplete StopReason = "complete"
	// StopBudgetExhausted: the run's shared POST budget (total or
	// deadline), the run window, or a retry that could not fit its wait
	// inside the deadline stopped the run with work left; nothing was
	// lost and the next run resumes.
	StopBudgetExhausted StopReason = "budget_exhausted"
	// StopPaused: the server paused the device or the account source.
	// A paused run with nothing pending keeps the historical exit zero
	// but never claims completion.
	StopPaused StopReason = "paused"
	// StopScopeChanged: the authorization drifted mid-run (a fence
	// stop, a consent revision move, an unconfirmed or changed scope
	// around the history phase); a new collection is required.
	StopScopeChanged StopReason = "scope_changed"
	// StopRetryExhausted: the bounded retry policy stopped a send —
	// retries were spent on real transient failures
	// (syncretry.ErrRetryExhausted) or the next wait could not fit the
	// run deadline (syncretry.ErrRetryPastDeadline).
	StopRetryExhausted StopReason = "retry_exhausted"
	// StopBusy: the state directory was held by another collector
	// process; no work was performed.
	StopBusy StopReason = "busy"
	// StopFatalError: any other hard failure, including settled
	// receipts that rejected records (the rejected counts carry the
	// detail).
	StopFatalError StopReason = "fatal_error"
	// StopBounded: an explicit per-queue batch bound stopped the drain
	// with batches still pending — the historical exit-zero bounded
	// stop, never a budget decline and never a claimed completion.
	StopBounded StopReason = "bounded_stop"
	// StopCancelled: the run was cancelled externally (a signal or a
	// parent context), as opposed to its own deadline elapsing.
	StopCancelled StopReason = "cancelled"
	// StopPartial: the run's coverage is not global — a deliberately
	// partial command mode (periodic --drain-only covers the device
	// queue only), an authorized source the grant sync could not cover,
	// or an ambiguous not-run. It never claims global completion and
	// never claims a failure; the explicit partial modes keep their
	// historical exit-zero contract.
	StopPartial StopReason = "partial"
	// StopEpochStale: the device's locally locked data epoch no longer
	// matches the server's (syncclient.ErrEpochStale — a usage reset
	// happened that this device has not been force-recollected
	// through). Terminal by design: nothing is read, exported or
	// uploaded, the collector never re-binds or auto-advances the local
	// epoch, and only the force-recollect flow resolves it.
	StopEpochStale StopReason = "epoch_stale"
	// StopResetInProgress: an unfinished force-recollect journal blocks
	// ordinary collection (syncclient.ErrResetInProgress). Terminal for
	// this run: the reset must finish (or be resumed through its own
	// entrypoint) before periodic collection, connect or sync proceed.
	StopResetInProgress StopReason = "reset_in_progress"
)

// Summary-only drain stop codes: derived by SummarizePhases, never
// assigned on a Result.
const (
	// DrainStopDrained: the queue emptied (no stop was recorded).
	DrainStopDrained DrainStopCode = "drained"
	// DrainStopUnknown: batches remain pending but no stop was
	// recorded — the honest defensive verdict, never a guess.
	DrainStopUnknown DrainStopCode = "unknown"
)

// GrantSkipUnknown is the summary-only fallback for a grant outcome
// whose code was never set (a zero-valued or future outcome shape).
const GrantSkipUnknown GrantSkipCode = "unknown"

// Fault reports whether this outcome's skip is a fault — the granted
// source was not collected because its input no longer reads or its
// export failed — as opposed to the healthy empty scan
// (GrantNoNewRecords) and the server-scope authorization verdict
// (GrantNotAllowed), neither of which is a run failure. A fault means
// the run is incomplete: never a complete verdict, and the periodic
// CLI turns it into a non-zero exit.
func (o GrantOutcome) Fault() bool {
	switch o.Code {
	case GrantInputInaccessible, GrantExportFailed, GrantSplitFailed:
		return true
	default:
		return false
	}
}

// PendingConcernTools returns the set of allowed tools whose pending
// restriction is a coverage concern, merged by UNIQUE tool name across
// every round's pending map: a tool restricted in both the initial
// collection and a backlog pass counts once, and a tool restricted in
// EITHER round is never dropped (a real stage failure survives the
// merge). The concern vocabulary is deliberately conservative:
//
//   - a reason OUTSIDE the closed wire vocabulary is a concern — an
//     unclassifiable restriction is held as an uncovered source, never
//     guessed away;
//   - a default input that was never detected (missing_input) is NOT a
//     concern: the server's allowed-tools list is an allowance, and a
//     tool this device never installed is not executable work here.
//     Its absence stays observable — the grant-ack pending state with
//     the missing_input code, the not_detected tool status and the
//     summary's pendingMissingInput counter — without failing the
//     round. A tool whose directory existed and was granted, then
//     vanished, is NOT in this map either: that case is an enabled
//     grant whose input no longer reads, reported by the scan as the
//     GrantInputInaccessible fault;
//   - unsupported tools and user-disabled managed grants are
//     no-concern states.
//
// A nil result means no round reported a concern.
func PendingConcernTools(pending ...map[string]string) map[string]struct{} {
	var out map[string]struct{}
	for _, p := range pending {
		if len(p) == 0 {
			continue
		}
		_, unmapped := ackPendingReasons(p)
		for _, tool := range unmapped {
			if out == nil {
				out = make(map[string]struct{}, len(unmapped))
			}
			out[tool] = struct{}{}
		}
	}
	return out
}

// PendingCoverageConcerns counts the authorized sources the grant
// sync's pending map shows as a coverage concern (see
// PendingConcernTools for the vocabulary). It is exactly the §6.5
// incompleteness signal the periodic CLI turns into a non-zero exit
// and connect's completeness evaluation reports.
func PendingCoverageConcerns(pending map[string]string) int {
	return len(PendingConcernTools(pending))
}

// ---------------------------------------------------------------------------
// Stable JSON contract (schema 1)
//
// Every field is an enum from a closed vocabulary, a registry-known
// source/tool name, an integer counter or a boolean. URLs, tickets,
// tokens, device/subject identifiers, file paths, batch/job ids and
// raw server or error text NEVER enter this contract: server-provided
// tool names are filtered against the compiled-in registry (unknown
// ones are only counted), and every message the library keeps for the
// human output is dropped rather than classified by text.
// ---------------------------------------------------------------------------

// ScopeSummary reports the server-driven grant authorization sync.
type ScopeSummary struct {
	Active          bool  `json:"active"`
	Paused          bool  `json:"paused"`
	Refreshed       bool  `json:"refreshed"`
	Acked           bool  `json:"acked"`
	ConsentRevision int64 `json:"consentRevision"`
	// AllowedTools lists the applied server tool scope as CANONICAL
	// registry names (spec.Tool, deduplicated and sorted). The registry
	// matches case-, space- and hyphen-insensitively, so the raw
	// server-supplied spelling never enters the contract — variants
	// collapse onto the canonical name, and unknown names are only
	// counted in UnknownAllowedTools.
	AllowedTools []string `json:"allowedTools"`
	// UnknownAllowedTools counts allowed-tool names the registry does
	// not know (name withheld by design).
	UnknownAllowedTools int `json:"unknownAllowedTools"`
	// PendingTools counts tools whose grant could not be fully applied,
	// split by the closed reason vocabulary below (reasons themselves
	// are free text and never enter the contract).
	PendingTools int `json:"pendingTools"`
	// PendingUnsupported counts allowed tools this collector cannot
	// collect — a no-concern state, not a fault.
	PendingUnsupported int `json:"pendingUnsupported"`
	// PendingDisabled counts managed grants the user manually disabled
	// — a user choice, not a fault.
	PendingDisabled int `json:"pendingDisabled"`
	// PendingMissingInput counts allowed tools whose default input
	// directory is absent — an observable never-installed state (the
	// grant-ack stays pending with the missing_input code and the tool
	// status reports not_detected), not a run fault: a tool this
	// device never installed is not executable work here, so the
	// verdict may still be complete.
	PendingMissingInput int `json:"pendingMissingInput"`
	// PendingUnmapped counts pending reasons outside the closed
	// vocabulary — treated as an uncovered source (conservative).
	PendingUnmapped int `json:"pendingUnmapped"`
}

// GrantSourceStatus is one granted source's scan outcome. Source is
// the registry-known adapter name only; the granted input path never
// enters the contract.
type GrantSourceStatus struct {
	Source string        `json:"source"`
	Status GrantSkipCode `json:"status"`
}

// AccountScanSummary reports the account-level source's upstream pull.
type AccountScanSummary struct {
	Ran              bool `json:"ran"`
	PulledEvents     int  `json:"pulledEvents"`
	NewRecords       int  `json:"newRecords"`
	ReplacedRecords  int  `json:"replacedRecords"`
	ReemittedRecords int  `json:"reemittedRecords"`
	SkippedUnchanged int  `json:"skippedUnchanged"`
	// SkippedNoStableId counts usage events dropped for lack of a
	// stable upstream id — a data gap, never a success.
	SkippedNoStableId int `json:"skippedNoStableId"`
}

// ScanSummary reports the local source scan (and the account source's
// pull phase).
type ScanSummary struct {
	Grants          int                 `json:"grants"`
	ExportedBatches int                 `json:"exportedBatches"`
	ExportedRecords int                 `json:"exportedRecords"`
	Sources         []GrantSourceStatus `json:"sources"`
	// UnknownSources counts grants whose source name the registry does
	// not know (name withheld by design).
	UnknownSources int                `json:"unknownSources"`
	Account        AccountScanSummary `json:"account"`
}

// AccountDrainSummary reports the account-level source's queue drain.
// Outcome reuses cursorsync's closed RoundOutcome vocabulary.
type AccountDrainSummary struct {
	SyncedBatches    int `json:"syncedBatches"`
	SyncedRecords    int `json:"syncedRecords"`
	PendingRemaining int `json:"pendingRemaining"`
	// PendingObserved reports whether PendingRemaining is a real
	// measurement of the durable account queue. Rounds that never read
	// the queue — no permit, an authorization withheld before any
	// preflight, a failed preflight, or a command mode that skips the
	// account source entirely (drain-only) — report false: a zero
	// count is then unmeasured, never a claim that the queue is empty.
	PendingObserved bool                    `json:"pendingObserved"`
	Outcome         cursorsync.RoundOutcome `json:"outcome"`
}

// DrainSummary reports the device outbox drain (and the account
// source's queue). Stop uses the closed DrainStopCode vocabulary plus
// the summary-only "drained" and "unknown".
type DrainSummary struct {
	SyncedBatches    int `json:"syncedBatches"`
	SyncedRecords    int `json:"syncedRecords"`
	AttemptedBatches int `json:"attemptedBatches"`
	RejectedBatches  int `json:"rejectedBatches"`
	RejectedRecords  int `json:"rejectedRecords"`
	Recovered        int `json:"recovered"`
	Quarantined      int `json:"quarantined"`
	PendingRemaining int `json:"pendingRemaining"`
	// PendingObserved reports whether PendingRemaining is a real
	// measurement of the device outbox (a successful count). Rounds
	// that ended before counting — an authorization pause, a scan
	// failure, a failed count — report false: a zero count is then
	// unmeasured, never a claim that the queue is empty.
	PendingObserved bool                `json:"pendingObserved"`
	Stop            DrainStopCode       `json:"stop"`
	Account         AccountDrainSummary `json:"account"`
}

// CountSummary is the run-wide totals mirror for dashboards.
type CountSummary struct {
	ExportedBatches int `json:"exportedBatches"`
	ExportedRecords int `json:"exportedRecords"`
	SyncedBatches   int `json:"syncedBatches"`
	SyncedRecords   int `json:"syncedRecords"`
	// PendingBatches sums the device and account queues.
	PendingBatches int `json:"pendingBatches"`
	// PendingObserved reports whether BOTH queues' pending counts are
	// real measurements; false means at least one queue was never
	// counted (a partial mode, an early exit or a failed count).
	PendingObserved bool `json:"pendingObserved"`
	RejectedRecords int  `json:"rejectedRecords"`
	Recovered       int  `json:"recovered"`
	Quarantined     int  `json:"quarantined"`
}

// Phases is the per-phase core both commands share (plan §6.5's
// scan/drain/scope blocks and the counters).
type Phases struct {
	Scope  ScopeSummary `json:"scope"`
	Scan   ScanSummary  `json:"scan"`
	Drain  DrainSummary `json:"drain"`
	Counts CountSummary `json:"counts"`
}

// RunSummary is the periodic command's stable §6.5 result contract.
type RunSummary struct {
	Schema     int        `json:"schema"`
	Command    string     `json:"command"`
	StopReason StopReason `json:"stop_reason"`
	DurationMS int64      `json:"durationMs"`
	Phases
}

// SummarizePhases builds the redacted per-phase core of one run. It is
// pure: it reads only the Result's structured fields, canonicalizes
// every name through the compiled-in registry (raw server spellings
// and unknown names never enter), and drops all free text.
func SummarizePhases(res Result) Phases {
	scope := ScopeSummary{
		Active:          res.GrantSync.Active,
		Paused:          res.GrantSync.Paused,
		Refreshed:       res.GrantSync.Refreshed,
		Acked:           res.GrantSync.Acked,
		ConsentRevision: res.GrantSync.ConsentRevision,
		PendingTools:    len(res.GrantSync.Pending),
	}
	for _, tool := range res.GrantSync.AllowedTools {
		if spec, known := registry.LookupTool(tool); known {
			// Canonical name: the registry matches aliases
			// case/space/hyphen-insensitively, so the raw server
			// spelling is dropped and variants collapse onto spec.Tool.
			if !containsString(scope.AllowedTools, spec.Tool) {
				scope.AllowedTools = append(scope.AllowedTools, spec.Tool)
			}
		} else {
			scope.UnknownAllowedTools++
		}
	}
	sort.Strings(scope.AllowedTools)
	// Pending reasons use the closed wire vocabulary
	// (unsupported/disabled/missing_input); reasons outside it are the
	// conservative unmapped bucket (counted as uncovered tools).
	reasons := pendingReasonCodes(res.GrantSync.Pending)
	for _, code := range reasons {
		switch code {
		case synccmd.PendingReasonUnsupportedTool:
			scope.PendingUnsupported++
		case synccmd.PendingReasonDisabled:
			scope.PendingDisabled++
		case synccmd.PendingReasonMissingInput:
			scope.PendingMissingInput++
		}
	}
	scope.PendingUnmapped = len(res.GrantSync.Pending) - len(reasons)

	scan := ScanSummary{
		Grants:          res.Grants,
		ExportedBatches: res.ExportedBatches,
		ExportedRecords: res.ExportedRecords,
		Sources:         make([]GrantSourceStatus, 0, len(res.GrantOutcomes)),
		Account: AccountScanSummary{
			Ran:               res.Cursor.Ran,
			PulledEvents:      res.Cursor.PulledEvents,
			NewRecords:        res.Cursor.NewRecords,
			ReplacedRecords:   res.Cursor.ReplacedRecords,
			ReemittedRecords:  res.Cursor.ReemittedRecords,
			SkippedUnchanged:  res.Cursor.SkippedUnchanged,
			SkippedNoStableId: res.Cursor.SkippedNoStableID,
		},
	}
	for _, outcome := range res.GrantOutcomes {
		code := outcome.Code
		if !knownGrantSkipCodes[code] {
			code = GrantSkipUnknown
		}
		if adapter, known := registry.Lookup(outcome.Source); known {
			// Canonical adapter source name (trimmed); the raw stored
			// spelling never enters the contract.
			scan.Sources = append(scan.Sources, GrantSourceStatus{Source: adapter.Source, Status: code})
		} else {
			scan.UnknownSources++
		}
	}

	drain := DrainSummary{
		SyncedBatches:    res.SyncedBatches,
		SyncedRecords:    res.SyncedRecords,
		AttemptedBatches: res.AttemptedBatches,
		RejectedBatches:  res.RejectedBatches,
		RejectedRecords:  res.RejectedRecords,
		Recovered:        res.Recovered,
		Quarantined:      res.Quarantined,
		PendingRemaining: res.PendingRemaining,
		PendingObserved:  res.PendingCounted,
		Stop:             summarizeDrainStop(res),
		Account: AccountDrainSummary{
			SyncedBatches:    res.Cursor.SyncedBatches,
			SyncedRecords:    res.Cursor.SyncedRecords,
			PendingRemaining: res.Cursor.PendingRemaining,
			PendingObserved:  res.Cursor.PendingCounted,
			Outcome:          res.Cursor.Outcome,
		},
	}

	counts := CountSummary{
		ExportedBatches: res.ExportedBatches,
		ExportedRecords: res.ExportedRecords,
		SyncedBatches:   res.SyncedBatches + res.Cursor.SyncedBatches,
		SyncedRecords:   res.SyncedRecords + res.Cursor.SyncedRecords,
		PendingBatches:  res.PendingRemaining + res.Cursor.PendingRemaining,
		PendingObserved: res.PendingCounted && res.Cursor.PendingCounted,
		RejectedRecords: res.RejectedRecords,
		Recovered:       res.Recovered,
		Quarantined:     res.Quarantined,
	}
	return Phases{Scope: scope, Scan: scan, Drain: drain, Counts: counts}
}

// pendingReasonCodes maps the grant sync's pending reasons onto the
// closed wire vocabulary (ackPendingReasons), returning ONLY the
// mapped tools; a pending tool absent from the result carries a reason
// outside the vocabulary (the caller counts those as unmapped). Raw
// reason text never leaves this function.
func pendingReasonCodes(pending map[string]string) map[string]string {
	if len(pending) == 0 {
		return nil
	}
	reasons, _ := ackPendingReasons(pending)
	return reasons
}

// containsString is the tiny membership helper the canonical-name
// dedup needs (no slices import for one call).
func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// summarizeDrainStop resolves the drain stop code: a recorded code wins
// (unknown-to-this-build values fall back honestly); without one, only
// a REAL measurement may report the queue drained — an uncounted
// queue is the honest "unknown", never a claimed empty.
func summarizeDrainStop(res Result) DrainStopCode {
	if knownDrainStopCodes[res.DrainStop] {
		return res.DrainStop
	}
	if !res.PendingCounted {
		return DrainStopUnknown
	}
	if res.PendingRemaining == 0 {
		return DrainStopDrained
	}
	return DrainStopUnknown
}

// ClassifyRunError maps a run error (and the run context's own state,
// nil when the context is still live) to the closed StopReason
// vocabulary. ok is false only for a nil error.
//
// Deadline semantics (the client-timeout distinction): a bare
// context.DeadlineExceeded in the ERROR CHAIN is NOT a run-budget stop
// — an HTTP client timeout wraps exactly that sentinel. The run's own
// window counts as budget only when the run CONTEXT itself reports
// DeadlineExceeded (ctxErr), or through the precise sentinels: the
// syncbudget declines and syncretry's deadline stop. A retry policy
// that spent its retries on real transient failures classifies as
// retry_exhausted even when the last failure was a client timeout;
// precedence keeps contention and the budget's own sentinels above it.
func ClassifyRunError(err, ctxErr error) (StopReason, bool) {
	if err == nil {
		return "", false
	}
	switch {
	case errors.Is(err, runlock.ErrBusy):
		return StopBusy, true
	case errors.Is(err, synccmd.ErrEpochStale):
		// Terminal data-epoch fence: a usage reset happened that this
		// device has not been force-recollected through. Never retried,
		// never auto-rebound — the stable log names the state so an
		// operator knows to run the force-recollect flow.
		return StopEpochStale, true
	case errors.Is(err, synccmd.ErrResetInProgress):
		// Terminal for this run: an unfinished force-recollect journal
		// owns the state directory.
		return StopResetInProgress, true
	case errors.Is(err, syncbudget.ErrTotalExhausted),
		errors.Is(err, syncbudget.ErrDeadlineExceeded):
		return StopBudgetExhausted, true
	case errors.Is(err, syncretry.ErrRetryExhausted):
		return StopRetryExhausted, true
	case errors.Is(ctxErr, context.DeadlineExceeded),
		errors.Is(err, syncretry.ErrRetryPastDeadline):
		return StopBudgetExhausted, true
	case errors.Is(err, context.Canceled),
		errors.Is(ctxErr, context.Canceled):
		return StopCancelled, true
	default:
		return StopFatalError, true
	}
}

// Summarize builds the periodic command's full §6.5 verdict: the
// redacted phases plus the single StopReason. An error verdict is
// classified from sentinels only; a nil-error verdict is classified
// from the structured codes and the cursor round outcome — never from
// message text. command is echoed into the contract verbatim, so
// callers pass one of the fixed command names ("periodic").
func Summarize(res Result, err, ctxErr error, command string, durationMS int64) RunSummary {
	summary := RunSummary{
		Schema:     ResultSchema,
		Command:    command,
		DurationMS: durationMS,
		Phases:     SummarizePhases(res),
	}
	if reason, classified := ClassifyRunError(err, ctxErr); classified {
		if reason == StopFatalError && errors.Is(err, ErrIncompleteRun) {
			// The honest incompleteness envelope: classify from the
			// structured result — the same walk a nil-error run gets —
			// instead of defaulting the wrapped exit to a hard failure.
			summary.StopReason = classifyCompletedRun(res)
			return summary
		}
		summary.StopReason = reason
		if reason == StopBusy {
			// The lock stopped the round before any work: the drain
			// section must not claim a drained queue over the zeroed
			// counts.
			summary.Drain.Stop = DrainStopNotRun
		}
		return summary
	}
	summary.StopReason = classifyCompletedRun(res)
	return summary
}

// SummarizePartialMode is Summarize for a command that deliberately
// ran a partial scope (periodic --drain-only covers the device queue
// only and never reads the account source): every classification
// (errors, pauses, budget stops) stays identical, but a verdict that
// would otherwise read complete becomes StopPartial — a partial mode
// never claims global completion. The command's own exit contract is
// unchanged (a clean drain-only run keeps its historical exit zero).
func SummarizePartialMode(res Result, err, ctxErr error, command string, durationMS int64) RunSummary {
	summary := Summarize(res, err, ctxErr, command, durationMS)
	if summary.StopReason == StopComplete {
		summary.StopReason = StopPartial
	}
	return summary
}

// SummarizeNotRun classifies a command that failed before its
// collection round could start (flag validation, state directory
// resolution, wiring): the phases stay zeroed, the drain section
// reports not_run instead of a drained queue, and the error's own
// verdict drives stop_reason. A nil error never reads as complete —
// an unexplained not-run is the ambiguous partial verdict, never a
// fabricated success. It never fabricates a drain state.
func SummarizeNotRun(err error, command string, durationMS int64) RunSummary {
	summary := Summarize(Result{}, err, nil, command, durationMS)
	summary.Drain.Stop = DrainStopNotRun
	if summary.StopReason == StopComplete {
		summary.StopReason = StopPartial
	}
	return summary
}

// classifyCompletedRun is the nil-error verdict. It mirrors the
// periodic CLI's existing incomplete judgment (periodicCursorIncomplete
// and the DrainStopped shapes), reading only structure:
//
//   - a paused device or account round is paused (even with nothing
//     pending — a paused round never claims completion);
//   - an authorization drift (cursor fence stop, a scope drain stop) is
//     scope_changed;
//   - a failed account round, dropped no-stable-id events, or a
//     granted source that failed to read or export are fatal_error
//     (the historical non-zero exits; the periodic CLI fails the run
//     on the grant faults);
//   - an authorized source the grant sync could not classify (an
//     unmapped pending reason) is partial — never a claimed
//     completion. A never-detected default input is not a concern:
//     the tool was never installed on this device, so no executable
//     work is owed (see PendingConcernTools);
//   - pending batches with an explicit bound (device or account) are
//     the exit-zero bounded stop;
//   - anything else with nothing pending is complete.
func classifyCompletedRun(res Result) StopReason {
	if res.GrantSync.Paused || res.DrainStop == DrainStopPaused {
		return StopPaused
	}
	switch res.Cursor.Outcome {
	case cursorsync.RoundFenceStop:
		return StopScopeChanged
	case cursorsync.RoundError:
		return StopFatalError
	case cursorsync.RoundPaused:
		return StopPaused
	}
	if res.Cursor.SkippedNoStableID > 0 {
		return StopFatalError
	}
	for _, outcome := range res.GrantOutcomes {
		if outcome.Fault() {
			return StopFatalError
		}
	}
	if PendingCoverageConcerns(res.GrantSync.Pending) > 0 {
		return StopPartial
	}
	if res.DrainStop == DrainStopScope {
		return StopScopeChanged
	}
	if res.DrainStop == DrainStopFailed {
		return StopFatalError
	}
	if res.DrainStop == DrainStopBudget {
		return StopBudgetExhausted
	}
	if res.PendingRemaining > 0 || res.Cursor.PendingRemaining > 0 {
		// The historical exit-zero-with-pending shape is the bounded
		// stop: an explicit per-queue bound on either queue (the device
		// DrainStopBounded code, the cursor RoundBounded outcome) or —
		// defensively — remaining batches with no recorded stop.
		return StopBounded
	}
	return StopComplete
}
