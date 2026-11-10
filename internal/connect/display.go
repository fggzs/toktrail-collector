package connect

// The connect/resync human display layer. Two rules shape it:
//
//   - Concise by default: the default output shows phase transitions,
//     phase outcomes and the honest incompleteness boundaries - never
//     per-batch lines, and never the values the section 6.5 contract keeps out
//     (URLs, tickets, device/subject identifiers, paths, batch and job
//     ids). --verbose adds the per-tool, per-batch and per-pass detail,
//     plus the closed-set diagnostic codes, but never re-adds a secret:
//     the connect/server URL stays unprinted in every mode (a stripped
//     URL can still carry ticket material in its path, and a hostile
//     server can reflect it), and neither does any server-controlled
//     free text (unknown tool names, raw errors): only
//     registry-canonical tool names and closed-set reason phrases are
//     ever printed.
//   - Honest progress and results: a long phase shows a heartbeat line
//     roughly every DefaultHumanHeartbeat on every stream (TTY and
//     redirect alike - plain newline-terminated lines), from observed
//     counters only. The final result renders the SAME closed-set
//     verdict the --json contract carries (SummarizeRun / SyncStopReason)
//     in natural language - never a self-invented judgment, never
//     err == nil as success, never an unobserved value printed as zero,
//     and never a receipt count described as newly-stored or
//     deduplicated-unique records.

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/resync"
)

// sealedOutcome whitelists the retransmission layers' sealed outcome
// vocabulary for display: the known constants pass through verbatim,
// anything else - unvetted text a future or hostile producer could
// place in the field - degrades to the fixed "unknown".
func sealedOutcome(outcome string) string {
	switch outcome {
	case "done", "blocked", "failed", "planned":
		return outcome
	default:
		return "unknown"
	}
}

// schedulerNotes isolates the scheduler package's own human output.
// Its best-effort failure notes quote raw command errors and its dry-
// run plan prints full local paths, so the raw text is swallowed here
// and never forwarded to any display mode - only the FACT that a note
// occurred survives, and connect renders it as one fixed safe English
// line. The installation, its error propagation and its rollback are
// untouched (the hard errors still return through the error chain).
type schedulerNotes struct {
	seen bool
}

func (s *schedulerNotes) Write(p []byte) (int, error) {
	s.seen = true
	return len(p), nil
}

// display routes the connect/resync human output through the two
// verbosity levels. It is a display layer only: no state machine, error
// or wire behavior ever reads it back.
type display struct {
	out     io.Writer
	verbose bool
}

func newDisplay(out io.Writer, verbose bool) *display {
	return &display{out: out, verbose: verbose}
}

// phase prints a line every mode shows: phase transitions, outcomes
// and the honest pending/rejected/resume boundaries.
func (d *display) phase(format string, args ...any) {
	fmt.Fprintf(d.out, format+"\n", args...)
}

// detail prints a line only --verbose shows.
func (d *display) detail(format string, args ...any) {
	if !d.verbose {
		return
	}
	fmt.Fprintf(d.out, format+"\n", args...)
}

// DefaultHumanHeartbeat is the minimum spacing between human heartbeat
// lines: a long phase stays visibly alive roughly every thirty seconds
// on every stream, from observed counters only.
const DefaultHumanHeartbeat = 30 * time.Second

// HeartbeatFallbackTick is the recommended fallback ticker period: it
// must fire much faster than DefaultHumanHeartbeat so a phase whose
// events stop is still named within one threshold of their
// disappearance (events gone at t=10 show the fallback around t=40).
const HeartbeatFallbackTick = 5 * time.Second

// heartbeatSink is a writer that can refuse a heartbeat line while an
// interactive prompt holds the stream open (a write without a trailing
// newline means the command is waiting on stdin).
type heartbeatSink interface {
	WriteHeartbeatLine(p []byte) (int, error)
}

// heartbeatStagePhrase maps the closed stage vocabulary onto readable
// English. The stages are locally assigned constants, but the mapping
// is closed anyway: an unknown value degrades to the generic "sync"
// wording and is never echoed verbatim (a future or foreign stage
// string is unvetted display input).
func heartbeatStagePhrase(stage string) string {
	switch stage {
	case "prepare":
		return "preparing"
	case "grant_sync":
		return "refreshing the authorization"
	case "cursor_sync":
		return "syncing the account source"
	case "source_scan":
		return "scanning local sources"
	case "drain":
		// Reader-facing wording: the queue upload, not the internal
		// drain vocabulary.
		return "uploading queued batches"
	case "tool_status":
		return "reporting tool status"
	case "history":
		return "retransmitting history"
	case "backlog":
		return "uploading queued batches"
	case "complete":
		return "finishing"
	default:
		return "sync"
	}
}

// HumanHeartbeat adapts the unified progress event stream into
// throttled human heartbeat lines. Only heartbeat events print; the
// line carries the readable stage, the elapsed time when one was
// actually measured, and the pending batch count when the event's own
// Counted gate backs it - never totals, percentages, rates,
// confirmation claims or an uncounted queue as an observed zero.
// minInterval <= 0 selects DefaultHumanHeartbeat; now is the throttle
// clock (production: time.Now; tests inject a synthetic one, so no
// test waits real seconds). The machine event callback is untouched:
// this adapter is an ADDITIONAL consumer, never a replacement for the
// JSONL progress writer.
//
// The returned function may be invoked from a heartbeat goroutine;
// calls are serialized internally, and a sink implementing
// heartbeatSink additionally gets prompt-aware gating (heartbeat lines
// are dropped while an interactive prompt waits on stdin).
func HumanHeartbeat(sink io.Writer, minInterval time.Duration, now func() time.Time) func(collection.ProgressEvent) {
	events, _ := StartHeartbeat(sink, minInterval, now, nil)
	return events
}

// StartHeartbeat couples the two human progress sources into one
// stoppable runner and returns the event consumer and the stop
// function:
//
//   - the event-driven lines (the unified progress stream) carry the
//     live stage, the measured elapsed time and the observed pending
//     counts;
//   - a fallback tick channel covers the phases NO internal emitter
//     exists for - the connect config fetch and bind, the resync
//     offline plan scan: when no progress event at all arrived for the
//     whole minInterval, the fixed, claim-free "Still working." line
//     prints. The fallback never fabricates a stage, a count or a
//     confirmation; it states only that the command is running.
//
// Both sources share ONE output throttle (a single lastOutput stamp
// read, checked and updated under the same lock hold), so a fallback
// line is never immediately followed by an event line or vice versa,
// and no decision races a concurrent print. The caller's tick channel
// should fire much faster than minInterval (about five seconds against
// the thirty-second threshold): a phase whose events stop at t=10 then
// shows the fallback around t=40, not a full interval later.
//
// Both lines go through the sink's prompt-aware WriteHeartbeatLine when
// it implements heartbeatSink, so progress pauses while an interactive
// prompt waits on stdin and resumes within one interval after the
// confirmation returns. The machine JSONL event callback is untouched:
// this runner is an additional consumer only (the CLI never starts it
// under --progress-json). tick may be nil (no fallback); a closed tick
// channel ends the fallback goroutine. The stop function is idempotent
// and joins the goroutine.
func StartHeartbeat(sink io.Writer, minInterval time.Duration, now func() time.Time, tick <-chan time.Time) (func(collection.ProgressEvent), func()) {
	if minInterval <= 0 {
		minInterval = DefaultHumanHeartbeat
	}
	if now == nil {
		now = time.Now
	}
	var mu sync.Mutex
	lastEvent := now()  // the last progress event of ANY kind
	lastOutput := now() // the last heartbeat line DELIVERED by EITHER source
	// printLine reports whether the line was actually delivered: a
	// prompt-gated sink returns (0, nil) for a dropped line, and a drop
	// must never count as output - otherwise the shared stamp would
	// starve the post-confirmation heartbeat for a whole extra
	// interval.
	printLine := func(line string) bool {
		p := []byte(line)
		if hs, ok := sink.(heartbeatSink); ok {
			n, _ := hs.WriteHeartbeatLine(p)
			return n > 0
		}
		_, _ = sink.Write(p)
		return true
	}
	events := func(ev collection.ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		lastEvent = now()
		if ev.Kind != collection.ProgressHeartbeat {
			return
		}
		if now().Sub(lastOutput) < minInterval {
			return
		}
		var b strings.Builder
		b.WriteString(sentence(heartbeatStagePhrase(ev.Stage)))
		b.WriteString(": still working")
		var obs []string
		if ev.Duration > 0 {
			// The stage's measured elapsed time; a zero duration was
			// never measured and is omitted, never shown as zero.
			obs = append(obs, fmt.Sprintf("%s elapsed", ev.Duration.Truncate(time.Second)))
		}
		if ev.Counted {
			// Only a really counted queue may state a pending count -
			// an uncounted one is never presented as an observed zero.
			obs = append(obs, fmt.Sprintf("%d batch(es) pending", ev.PendingBatches))
		}
		if len(obs) > 0 {
			b.WriteString(" (" + strings.Join(obs, "; ") + ")")
		}
		b.WriteString(".\n")
		if printLine(b.String()) {
			lastOutput = now()
		}
	}
	stopCh := make(chan struct{})
	stopDone := make(chan struct{})
	var stopOnce sync.Once
	go func() {
		defer close(stopDone)
		if tick == nil {
			return
		}
		for {
			select {
			case <-stopCh:
				return
			case _, ok := <-tick:
				if !ok {
					return
				}
				mu.Lock()
				// The whole decision under one lock hold: a concurrent
				// event line cannot slip between the check and the
				// update, and the shared lastOutput throttles both
				// sources against each other.
				if now().Sub(lastEvent) >= minInterval && now().Sub(lastOutput) >= minInterval {
					if printLine("Still working.\n") {
						lastOutput = now()
					}
				}
				mu.Unlock()
			}
		}
	}()
	stop := func() {
		stopOnce.Do(func() { close(stopCh) })
		<-stopDone
	}
	return events, stop
}

// stopReasonStatus is the verdict line's BRIEF status: the full
// actionable phrase (StopReasonPhrase) is printed exactly once - by the
// command layer's error wrapper, on the failure line main renders - so
// the summary's own verdict line stays short and never repeats the
// reason. The structured lines below the verdict (sources, pending,
// history) carry the detail instead.
func stopReasonStatus(reason collection.StopReason) string {
	switch reason {
	case collection.StopComplete:
		return "completed for the current authorization"
	case collection.StopCancelled:
		return "cancelled"
	case collection.StopFatalError:
		return "failed"
	case collection.StopEpochStale, collection.StopResetInProgress:
		return "blocked"
	default:
		return "incomplete"
	}
}

// StopReasonPhrase maps the closed section 6.5 StopReason onto its fixed
// natural-language phrase. The mapping is display-only; unknown values
// degrade to the honest unclassified wording, never a guess. Exported
// so the command layer wraps its returned error with the same closed-
// set verdict instead of the raw error text.
func StopReasonPhrase(reason collection.StopReason) string {
	switch reason {
	case collection.StopComplete:
		// Scoped: out-of-scope history is a normal authorization
		// verdict on a complete run, so the title never implies that
		// ALL history was covered (the withheld reminders below stay
		// explicit).
		return "completed for the current authorization"
	case collection.StopBudgetExhausted:
		// Never "nothing was sent": the pending queues can include
		// retry batches whose earlier send lost its receipt; only the
		// attempts this budget declined are provably unsent.
		return "incomplete: the upload budget was reached; remaining work stays pending"
	case collection.StopPaused:
		return "incomplete: the server paused collection"
	case collection.StopScopeChanged:
		return "incomplete: the authorization scope changed during the run"
	case collection.StopRetryExhausted:
		return "incomplete: upload retries were exhausted"
	case collection.StopBusy:
		return "incomplete: the state directory stayed busy (another collector process holds the lock)"
	case collection.StopFatalError:
		// The reason only: main's unified line already carries the
		// "connect failed:"/"resync failed:" prefix, so the phrase
		// never repeats the failure word, and the raw error text is
		// never included.
		return "an unexpected error occurred"
	case collection.StopBounded:
		return "incomplete: the drain stopped at its explicit batch bound"
	case collection.StopCancelled:
		return "cancelled"
	case collection.StopPartial:
		return "incomplete: some authorized sources were not covered on this device"
	case collection.StopEpochStale:
		// Terminal fence: only the force-recollect flow resolves it, so
		// the phrase names the action without suggesting a retry or a
		// re-bind (the collector never re-binds automatically).
		return "blocked: the device's data epoch no longer matches the server (a usage reset happened); run the force-recollect flow before collecting again"
	case collection.StopResetInProgress:
		return "blocked: a force-recollect is in progress; finish or resume it before collecting again"
	default:
		return "ended with an unclassified outcome"
	}
}

// RenderRunSummary renders the section 6.5 closed-set run summary as the
// concise human final result of a connect command: two or three lines
// at most. It reads ONLY the summary's closed enums and counters - the
// same SummarizeRun verdict the --json contract carries, never message
// text and never err == nil as success. Unobserved values (a pending
// count no queue read backed, an installation nothing confirmed) are
// omitted, never printed as zero or as a negative claim; the history
// retransmission and this run's collection uploads are reported as
// SEPARATE facts (they are different queues, and summing them would
// double-count replay confirmations as new uploads); receipt counts are
// phrased as records the server confirmed - never a claim of
// newly-stored or deduplicated-unique records. Only a history section
// that actually needs attention (a real retransmission, a failure, a
// resume boundary) gets its own line.
func RenderRunSummary(w io.Writer, s RunSummary, verbose bool) {
	// The verdict line carries the run's own outcome facts in ONE line:
	// the binding and scheduler states were already stated once by the
	// setup phases above (repeating them would duplicate the log), and
	// the internal consent revision is verbose-only.
	verdict := fmt.Sprintf("Connect result: %s", qualifiedStatus(s.StopReason, runRejectedRecords(s)))
	if s.Binding.Status == BindFailed {
		verdict += "; device binding failed"
	}
	c := s.Collection.Counts
	switch {
	case c.SyncedBatches > 0:
		verdict += fmt.Sprintf("; the server confirmed %d batch(es) (%d record(s))", c.SyncedBatches, c.SyncedRecords)
	case c.ExportedBatches > 0:
		verdict += fmt.Sprintf("; %d batch(es) (%d record(s)) prepared from local sources", c.ExportedBatches, c.ExportedRecords)
	}
	fmt.Fprintf(w, "%s.\n", verdict)
	// The pending state, PER QUEUE: each queue states its known positive
	// count only behind its OWN observation gate (the merged Counts gate
	// is true only when BOTH queues were measured - a known device count
	// must never be swallowed by an unmeasured account queue), and an
	// unmeasured queue this incomplete run needed to report is stated as
	// unknown. An account source whose round never ran and was never
	// counted is out of scope: it is never forced into an unknown.
	drain := s.Collection.Drain
	if drain.PendingObserved && drain.PendingRemaining > 0 {
		fmt.Fprintf(w, "Device: %s\n", pendingAttentionLine(drain.PendingRemaining, s.StopReason))
	}
	if drain.Account.PendingObserved && drain.Account.PendingRemaining > 0 {
		fmt.Fprintf(w, "Account: %s\n", pendingAttentionLine(drain.Account.PendingRemaining, s.StopReason))
	}
	if !drain.PendingObserved && s.StopReason != collection.StopComplete {
		fmt.Fprintln(w, "Pending batches: unknown (not measured this run).")
	}
	if !drain.Account.PendingObserved && s.Collection.Scan.Account.Ran && s.StopReason != collection.StopComplete {
		fmt.Fprintln(w, "Account-source batches pending: unknown (not measured this run).")
	}
	if c.RejectedRecords > 0 {
		fmt.Fprintf(w, "The server rejected %d record(s).\n", c.RejectedRecords)
	}
	if c.Recovered > 0 {
		fmt.Fprintf(w, "%d quarantined record(s) were recovered and re-queued.\n", c.Recovered)
	}
	if c.Quarantined > 0 {
		fmt.Fprintf(w, "%d record(s) were quarantined and are not counted.\n", c.Quarantined)
	}
	if h := s.History; historyNeedsAttention(h) {
		fmt.Fprintf(w, "%s\n", historyAttentionLine(h))
	}
	if s.StopReason != collection.StopComplete {
		renderFailureAttention(w, s)
	}
	if verbose {
		renderRunDiagnostics(w, s)
	}
}

// renderFailureAttention names the phase and the determinable closed-set
// reason behind a non-complete verdict: at most three registry-canonical
// source names with their fixed failure phrase (the rest folded into a
// count), plus the account round's closed outcome when it failed.
// Never a path, a raw error or an unvetted name - the summary's source
// statuses are already canonicalized and text-free. When nothing
// determinable exists, nothing extra is printed and the verdict line's
// generic failure stands on its own.
func renderFailureAttention(w io.Writer, s RunSummary) {
	const maxNamed = 3
	named := 0
	failed := 0
	for _, src := range s.Collection.Scan.Sources {
		reason, isFailure := grantFailurePhrase(src.Status)
		if !isFailure {
			continue
		}
		failed++
		if named < maxNamed {
			fmt.Fprintf(w, "Source %s: %s.\n", src.Source, reason)
			named++
		}
	}
	if failed > named {
		fmt.Fprintf(w, "%d more source(s) failed the same way.\n", failed-named)
	}
	switch s.Collection.Drain.Account.Outcome {
	case cursorsync.RoundError:
		fmt.Fprintln(w, "The account source failed this round; its queue keeps its state.")
	case cursorsync.RoundFenceStop:
		fmt.Fprintln(w, "The account source stopped on an authorization or source-state change.")
	}
}

// grantFailurePhrase maps the closed grant skip codes that are hard
// local failures onto their fixed English phrase. Codes that are not
// failures (a healthy export, an empty scan, an authorization verdict)
// report false.
func grantFailurePhrase(code collection.GrantSkipCode) (phrase string, isFailure bool) {
	switch code {
	case collection.GrantInputInaccessible:
		return "is unavailable (its input can no longer be read)", true
	case collection.GrantExportFailed:
		return "failed to export its records", true
	case collection.GrantSplitFailed:
		return "failed to split its export", true
	default:
		return "", false
	}
}

// renderRunDiagnostics prints the verbose-only closed-set view: the raw
// stop reason, the binding/scheduler state and the closed incompleteness
// codes. Closed enums and counters only - no free text.
func renderRunDiagnostics(w io.Writer, s RunSummary) {
	line := fmt.Sprintf("Diagnostics: stop_reason=%s binding=%s", s.StopReason, s.Binding.Status)
	if s.Binding.ConsentRevision > 0 {
		line += fmt.Sprintf(" consentRevision=%d", s.Binding.ConsentRevision)
	}
	if s.Scheduler.Installed {
		line += " scheduler=installed"
	}
	fmt.Fprintln(w, line)
	if len(s.IncompleteCodes) > 0 {
		fmt.Fprintf(w, "Diagnostics: incomplete codes=[%s]\n", strings.Join(s.IncompleteCodes, " "))
	}
}

// historyNeedsAttention reports whether the history retransmission
// block deserves a line in the concise final result: it really
// retransmitted something, left something behind, was rejected, or
// ended anywhere but the two clean steady states (a completed pass and
// an authorization-driven nothing-eligible verdict). A first install's
// empty pass and a nothing-eligible authorization verdict are normal
// states, not reminders.
func historyNeedsAttention(h HistorySummary) bool {
	if !h.Ran || h.DryRun {
		return false
	}
	if h.Uploads > 0 || h.Remaining > 0 || h.RejectedRecords > 0 {
		return true
	}
	switch h.Stop {
	case ResyncStopCompleted, ResyncStopNothingEligible:
		return false
	default:
		return true
	}
}

// historyAttentionLine renders the history block's attention line from
// its closed stop code and observed counters. The scheduled task does
// NOT continue a resync job - that boundary is part of every resumable
// wording.
func historyAttentionLine(h HistorySummary) string {
	var line string
	switch h.Stop {
	case ResyncStopCompleted:
		line = fmt.Sprintf("History retransmission: %d batch(es) re-sent (%d record(s) accepted by the server).", h.Uploads, h.AcceptedRecords)
	case ResyncStopBudget:
		line = "History retransmission: stopped at the shared upload budget; resume it explicitly with toktrail resync --all when intended (the scheduled task does not continue a resync job)."
	case ResyncStopStopped:
		line = "History retransmission: stopped early; resume it explicitly with toktrail resync --all when intended (the scheduled task does not continue a resync job)."
	case ResyncStopBusy:
		line = "History retransmission: not run (the state directory stayed busy)."
	case ResyncStopPaused:
		line = "History retransmission: skipped (the device is paused server-side)."
	case ResyncStopFailed:
		line = "History retransmission: failed."
	case ResyncStopNothingEligible:
		line = "History retransmission: nothing eligible under the current authorization."
	default:
		line = "History retransmission: ended without a recorded outcome."
	}
	if h.Stop != ResyncStopCompleted && h.Remaining > 0 {
		line += fmt.Sprintf(" %d batch(es) remain un-retransmitted.", h.Remaining)
	}
	if h.RejectedRecords > 0 {
		// Rejections show whatever the stop code: a completed job can
		// still carry rejected records in its receipts, and hiding them
		// behind "completed" would dress a partial acceptance up as
		// full success.
		line += fmt.Sprintf(" The server rejected %d record(s).", h.RejectedRecords)
	}
	return line
}

// pendingAttentionLine states the observed pending count and adds a
// follow-up hint ONLY where the stop reason actually guarantees it: a
// paused device or a moved scope must not promise an automatic
// continuation, and a busy run performed no work at all.
func pendingAttentionLine(pending int, reason collection.StopReason) string {
	line := fmt.Sprintf("%d batch(es) remain pending", pending)
	switch reason {
	case collection.StopScopeChanged:
		// Factual coverage statement only: never a command suggestion,
		// never an unproven scheduled-continuation claim.
		line += "; a new collection is required under the current authorization"
	}
	return line + "."
}

// qualifiedStatus renders the verdict line's status, qualifying a
// COMPLETED run whose receipts still carry rejected records (the
// history job can complete with rejections in its receipts): the title
// then explicitly says some records were rejected, so a partial
// acceptance never reads as unqualified success. Exit codes and the
// JSON contract are untouched by this display-only qualification.
func qualifiedStatus(reason collection.StopReason, rejectedRecords int) string {
	if reason == collection.StopComplete && rejectedRecords > 0 {
		return "processing completed for the current authorization; some records were rejected"
	}
	return stopReasonStatus(reason)
}

// runRejectedRecords totals the run's observed record rejections: the
// collection drain's and the history retransmission's receipt counts.
func runRejectedRecords(s RunSummary) int {
	n := s.Collection.Counts.RejectedRecords
	if s.History.Ran {
		n += s.History.RejectedRecords
	}
	return n
}

// syncRejectedRecords totals one sync orchestration's observed record
// rejections across its collection rounds and the history phase.
func syncRejectedRecords(sync SyncResult) int {
	n := sync.Collection.RejectedRecords + sync.Backlog.Result.RejectedRecords
	if sync.Resync.Ran {
		n += sync.Resync.RejectedRecords
	}
	return n
}

// RenderSyncResult renders the resync command's human final result from
// the existing closed sets: the verdict is SyncStopReason's (the same
// classification SummarizeRun applies to a connect run - sentinels and
// structured state, never err == nil and never message text), the
// history block maps its closed stop code, and the pending counts print
// only behind their own observation gates. dryRun renders the
// planned-only verdict. The run error's text is never repeated here -
// the command's error channel owns it.
func RenderSyncResult(w io.Writer, sync SyncResult, err, ctxErr error, dryRun, verbose bool) {
	if dryRun {
		// A dry run never reaches the verdict classification: planning
		// only, no network, and the remote consent scope unverified -
		// never a "complete" claim over work that was only listed.
		fmt.Fprintln(w, "Resync result: dry run - planned only; nothing was uploaded or changed, and the remote consent scope was not verified.")
		return
	}
	reason := SyncStopReason(sync, err, ctxErr)
	fmt.Fprintf(w, "Resync result: %s.\n", qualifiedStatus(reason, syncRejectedRecords(sync)))
	if line := historyAttentionLine(syncHistoryView(sync)); historyNeedsAttention(syncHistoryView(sync)) {
		fmt.Fprintln(w, line)
	}
	final := sync.Collection
	if sync.Backlog.Passes > 0 {
		final = sync.Backlog.Result
	}
	// The pending counts read from the SAME source as their observation
	// gates: an initial-collection hard error returns before any backlog
	// pass exists, and the initial round's own counted queues must never
	// be hidden behind the never-populated backlog fields.
	if final.PendingCounted {
		if final.PendingRemaining > 0 {
			fmt.Fprintf(w, "Device: %s\n", pendingAttentionLine(final.PendingRemaining, reason))
		}
	} else if reason != collection.StopComplete {
		// The device queue this run needed to report was never measured:
		// unknown, never a silent zero.
		fmt.Fprintln(w, "Device batches pending: unknown (not measured this run).")
	}
	// The account queue: a counted queue states its pending count
	// WHATEVER Ran says - cursorsync's fail-closed pause path counts the
	// durable queue BEFORE the upstream pull and returns with Ran=false
	// and a real count, which a Ran gate would swallow. Only an
	// uncounted queue decides its scope by Ran: an inapplicable account
	// source (no round, never counted) is never forced into an unknown.
	if final.Cursor.PendingCounted {
		if final.Cursor.PendingRemaining > 0 {
			fmt.Fprintf(w, "Account: %s\n", pendingAttentionLine(final.Cursor.PendingRemaining, reason))
		}
	} else if final.Cursor.Ran && reason != collection.StopComplete {
		fmt.Fprintln(w, "Account-source batches pending: unknown (not measured this run).")
	}
	if verbose {
		fmt.Fprintf(w, "Diagnostics: history stop=%s.\n", sync.Resync.Stop)
	}
}

// SummarizeResyncForCLI maps a resync.Result onto the sync-level
// summary the resync command's human rendering reads (the same mapper
// SummarizeRun applies internally). ran mirrors the internal contract:
// true for a dry run that produced a plan.
func SummarizeResyncForCLI(res resync.Result, ran bool) SyncResult {
	return SyncResult{Resync: summarizeResync(res, ran)}
}

// SummarizeOverrideForCLI is SummarizeResyncForCLI's override-pass
// twin.
func SummarizeOverrideForCLI(res resync.OverrideResult, ran bool) SyncResult {
	return SyncResult{Resync: summarizeOverride(res, ran)}
}

// syncHistoryView maps a SyncResult's retransmission summary onto the
// summary-level HistorySummary so the resync renderer reads the same
// closed view RenderRunSummary does.
func syncHistoryView(sync SyncResult) HistorySummary {
	return summarizeHistory(sync.Resync)
}

// sentence upper-cases the first rune of a rendered fact line.
func sentence(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	up := strings.ToUpper(string(r[0]))
	return up + string(r[1:])
}

// toolCountSet accumulates the connect setup's per-category tool
// counts for the merged sources line. Tool names are deduplicated (the
// server's tool list may repeat one), and every category stays
// distinct: an unsupported name is never counted as "not installed",
// and a declined or failed account-source confirmation is never counted
// as detected either.
type toolCountSet struct {
	seen          map[string]bool
	detected      int
	notDetected   int
	unsupported   int
	accountActive int
	// accountNotEnabled counts an account source whose first-time
	// enable failed before any permit existed (a declined or
	// unavailable local confirmation, or a pre-enable failure): it owes
	// a local confirmation gesture, it is not "not installed".
	accountNotEnabled int
	// accountFirstSyncIncomplete counts an account source whose enable
	// wrote the permit but whose first sync did not complete.
	accountFirstSyncIncomplete int
}

// counted deduplicates the per-tool counting by name.
func (t *toolCountSet) counted(name string) bool {
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	if t.seen[name] {
		return false
	}
	t.seen[name] = true
	return true
}

// summary renders the merged sources line: only non-zero segments, in a
// fixed order, with fixed closed-set labels (no tool names - an
// unknown server spelling is never echoed).
func (t *toolCountSet) summary() string {
	var parts []string
	if t.detected > 0 {
		parts = append(parts, fmt.Sprintf("%d detected", t.detected))
	}
	if t.notDetected > 0 {
		parts = append(parts, fmt.Sprintf("%d not detected (skipped)", t.notDetected))
	}
	if t.unsupported > 0 {
		// Counted only: the raw server spelling is unvetted text and is
		// never echoed in any mode.
		parts = append(parts, fmt.Sprintf("%d unsupported (skipped)", t.unsupported))
	}
	if t.accountActive > 0 {
		parts = append(parts, fmt.Sprintf("%d account source(s) active", t.accountActive))
	}
	if t.accountNotEnabled > 0 {
		parts = append(parts, fmt.Sprintf("%d account source(s) not enabled (local confirmation or setup incomplete)", t.accountNotEnabled))
	}
	if t.accountFirstSyncIncomplete > 0 {
		parts = append(parts, fmt.Sprintf("%d account source(s) enabled with first sync incomplete", t.accountFirstSyncIncomplete))
	}
	return strings.Join(parts, ", ")
}
