package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	resynccmd "toktrail-collector/internal/app/resync"
	"toktrail-collector/internal/connect"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/registry"
)

// resyncUsage is the resync command's static usage text, printed
// verbatim instead of the flag package's own usage: the flag package
// renders DEFAULT VALUES (including environment-derived server URLs)
// and error details that quote raw argument values, none of which may
// reach the output stream.
const resyncUsage = `usage: toktrail resync [flags]

flags:
  --all                resynchronize usage within the current authorization
  --dry-run            offline read-only plan; remote scope is not verified
  --yes                confirm retransmission without an interactive prompt
  --replace-existing   override mode: scan the CURRENT Codex and DeepSeek Harness sources and replace same-key server records with the current scanned record (explicit confirmation required)
  --force-recollect    clear this device's ordinary history and rebuild ALL authorized local tools from current source data; Cursor is excluded (explicit confirmation required)
  --expected-device    refuse to run unless this is the intended bound device ID
  --state-dir string   local TokTrail state directory (also TOKTRAIL_HOME)
  --server string      server base URL; defaults to the bound server (also TOKTRAIL_SERVER_URL)
  --max-batches int    upload budget; 0 processes the entire frozen plan
  --verbose            show detailed per-batch, per-source-directory and per-pass output (never secrets: no URLs, tickets or credentials)
`

// errResyncFlagValue is the fixed, value-free error a failed resync
// flag parse returns: the flag package's own error quotes the raw
// argument value verbatim (a pasted value may carry a ticket, a URL or
// an absolute path), so it is never surfaced. The failure semantics -
// a non-nil error (exit code 1) - are unchanged.
var errResyncFlagValue = errors.New("invalid flag or flag value; run 'toktrail help' for usage")

func runResync(args []string) error {
	return runResyncWithIO(args, os.Stdin, os.Stdout)
}

// runResyncWithIO runs the resync command with explicit IO. The human
// output is concise English by default - the plan counts and their
// fixed coverage notes, the phase summaries and the honest pending/
// rejected/resume boundaries - with a heartbeat line roughly every
// thirty seconds while a long phase runs. --verbose adds the per-batch
// and per-source-directory detail. The two interactive confirmations
// (the plain retransmission and the replace-existing override) keep
// their exact prompts, their timing (before any collection, scan or
// upload) and their [y/N] default; heartbeat lines are dropped while a
// prompt waits on stdin. The returned error's display text is the
// closed-set verdict phrase (never the raw error text); errors.Is/As
// and the exit code are untouched.
func runResyncWithIO(args []string, input io.Reader, output io.Writer) error {
	fs := flag.NewFlagSet("resync", flag.ContinueOnError)
	// The flag package's own output (usage with environment-derived
	// defaults, errors quoting raw values) is discarded; the static
	// usage above and fixed safe errors replace it.
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "resynchronize usage within the current authorization")
	dryRun := fs.Bool("dry-run", false, "offline read-only plan; remote scope is not verified")
	yes := fs.Bool("yes", false, "confirm retransmission without an interactive prompt")
	replaceExisting := fs.Bool("replace-existing", false, "override mode: scan the CURRENT Codex and DeepSeek Harness sources and replace same-key server records with the current scanned record (explicit confirmation required)")
	forceRecollect := fs.Bool("force-recollect", false, "clear ordinary device history and recollect all authorized local tools; Cursor excluded")
	expectedDevice := fs.String("expected-device", "", "guard against clearing the wrong bound device")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "server base URL; defaults to bound server")
	maxBatches := fs.Int("max-batches", 0, "upload budget; 0 processes the entire frozen plan")
	verbose := fs.Bool("verbose", false, "show detailed per-batch, per-source-directory and per-pass output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(output, resyncUsage)
			// The help request keeps its chain (errors.Is works) and
			// its exit semantics; the wrapper only gives main's unified
			// failure line a fixed safe text.
			return safeDisplayError(err, "help requested")
		}
		// The original parse error stays on the chain (errors.Is/As,
		// the exit code); only its display text is replaced, because it
		// quotes the raw argument value verbatim.
		return safeDisplayError(err, errResyncFlagValue.Error())
	}
	// The human stream: serialized against the heartbeat goroutine, and
	// prompt-gated (heartbeat lines are dropped while a confirmation
	// waits on stdin; the prompt line is closed - a newline only, the
	// answer never echoed - once the confirmation returns).
	hs := newHumanStream(output)
	hs.quiet = !isTerminalWriter(output)
	out := io.Writer(hs)
	// The coupled heartbeat: event-driven lines from the progress
	// stream plus a fast fallback ticker for the phases no internal
	// emitter covers (the offline plan scan, the lock waits). Stopped
	// (and joined) before the final result renders. The machine event
	// callback is untouched (resync has no JSONL mode).
	heartbeatTicker := time.NewTicker(connect.HeartbeatFallbackTick)
	defer heartbeatTicker.Stop()
	progress, stopHeartbeat := connect.StartHeartbeat(hs, 0, nil, heartbeatTicker.C)
	defer stopHeartbeat()
	// The command's own fixed-literal validation errors keep their text
	// (they echo no argument values); everything else is wrapped with a
	// fixed generic display, preserving errors.Is/As.
	known := func(err error) error { return safeDisplayError(err, err.Error()) }
	unknown := func(err error) error {
		// The advice deliberately avoids suggesting a re-run: the
		// history retransmission has side effects, so the user reviews
		// the state first.
		return safeDisplayError(err, "resync did not run (details withheld; review the configuration and the run status before taking any further action)")
	}
	if !*all {
		return known(errors.New("resync requires --all; use --all --dry-run to inspect the plan first"))
	}
	if fs.NArg() != 0 {
		return known(errors.New("resync accepts flags only, no positional arguments"))
	}
	if *forceRecollect && *replaceExisting {
		return known(errors.New("--force-recollect and --replace-existing cannot be combined"))
	}
	if *expectedDevice != "" && !*forceRecollect {
		return known(errors.New("--expected-device requires --force-recollect"))
	}
	if *maxBatches < 0 {
		return known(errors.New("--max-batches must be zero or a positive integer"))
	}
	if *dryRun && *yes {
		return known(errors.New("--dry-run and --yes cannot be combined: dry-run never uploads"))
	}
	dir := strings.TrimSpace(*stateDir)
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return unknown(err)
		}
	}
	if *forceRecollect {
		return runForceRecollectWithIO(dir, *serverURL, *expectedDevice, *dryRun, *yes, *maxBatches, *verbose, input, out)
	}
	if !*dryRun {
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return unknown(err)
		}
		if err := lock.Close(); err != nil {
			return unknown(err)
		}
	}
	// printPlan shows the plan the user is about to confirm: the
	// counts, the exclusions and the fixed coverage notes. The target
	// line (server URL, device id) is never printed in any mode - both
	// are unvetted reflection surfaces; verbose adds nothing there.
	printPlan := func(plan resynccmd.Plan) {
		if plan.Resumed {
			// A resumed journal may not carry a records total; only the
			// provable batch count is stated - never an unknown record
			// total shown as zero.
			fmt.Fprintf(out, "plan: resuming an unfinished retransmission job; %d batch(es) remain in the plan.\n", len(plan.Batches))
		} else {
			fmt.Fprintf(out, "plan: %d batch(es) (%d record(s)) to retransmit.\n", len(plan.Batches), plan.PlannedRecords)
		}
		// The coverage limitation in ONE short fixed line (the long
		// local note stays verbose); the key confirmation facts stay.
		// The PLAN's SnapshotRestricted marker decides: a resumed job
		// restricted by its journal-frozen universe names the ORIGINAL
		// snapshot; only a fresh restricted pass says "before this
		// run".
		if plan.SnapshotRestricted {
			if plan.Resumed {
				fmt.Fprintln(out, "History replay covers this device only, limited to the job's original snapshot; account history and quarantined records are excluded.")
			} else {
				fmt.Fprintln(out, "History replay covers this device only, and only the batches already synced before this run; batches synced during this run, account history and quarantined records are excluded.")
			}
		} else {
			fmt.Fprintln(out, "History replay covers this device only; account history and quarantined records are excluded.")
		}
		fmt.Fprintln(out, "De-duplication applies to the current device only; this command never creates a device or clears progress.")
		if *verbose {
			fmt.Fprintln(out, plan.CoverageNote)
			fmt.Fprintf(out, "plan detail: batches=%d records=%d resumed=%t alreadyDone=%d excludedPending=%d reorganizedParents=%d localGrantBatches=%d quarantineRecords=%d\n",
				len(plan.Batches), plan.PlannedRecords, plan.Resumed, plan.DoneInJob,
				plan.ExcludedPending, plan.ExcludedReorganized, len(plan.ExcludedLocalGrant), plan.QuarantinedRecords)
		}
	}
	// printOverridePlan shows the override plan: per-source counts under
	// registry-canonical source names only. The input directories (local
	// paths), the invalid record keys and any unvetted source spelling
	// are NEVER echoed in any mode - an unknown name degrades to the
	// fixed closed label; the target line (server URL, device id) is
	// never printed either. The risk warning and the confirmation below
	// it are unchanged.
	printOverridePlan := func(plan resynccmd.OverridePlan) {
		fmt.Fprintf(out, "override plan (current source scans only):\n")
		for _, sp := range plan.Sources {
			label := sp.Source
			if _, known := registry.Lookup(sp.Source); !known {
				// An unvetted source spelling is never echoed; the
				// counts stay under the fixed closed label.
				label = "unknown source"
			}
			fmt.Fprintf(out, "  %s: scanned=%d drifted=%d new=%d frozenAttempts=%d alreadyCurrent=%d invalid=%d scanIssues=%d scanQuarantined=%d\n",
				label, sp.Scanned, sp.Drifted, sp.NewRecords, sp.FrozenAttempts, sp.AlreadyCurrent, sp.InvalidRecords, sp.ScanIssues, sp.ScanQuarantined)
		}
		if len(plan.ExcludedSources) > 0 {
			// The excluded entries carry grant paths; only their count
			// is shown.
			fmt.Fprintf(out, "excluded sources (not part of the override): %d\n", len(plan.ExcludedSources))
		}
		if plan.WithheldNoGrant > 0 {
			fmt.Fprintf(out, "pending override attempts with no enabled grant (stay pending): %d\n", plan.WithheldNoGrant)
		}
		fmt.Fprintf(out, "totals: replace=%d insert=%d\n", plan.TotalReplace, plan.TotalNew)
		fmt.Fprintln(out, plan.Warning)
		fmt.Fprintln(out, "De-duplication applies to the current device only; this command never creates a device or clears progress.")
	}
	// The two interactive confirmations keep their exact prompts, their
	// timing and their [y/N] default. The prompt line is closed (a
	// newline only - the answer is never echoed) once the confirmation
	// returns, so the heartbeat gating resumes for the long phases that
	// follow. A refusal returns the private sentinel (never free text),
	// so the abort recognition below answers errors.Is, not message
	// matching - an untrusted error merely containing "cancelled" can
	// never masquerade as the user's own refusal.
	confirm := func(plan resynccmd.Plan) error {
		printPlan(plan)
		if *yes {
			return nil
		}
		err := promptYesNo(input, out, "Resynchronize usage under the live server consent?")
		hs.CompletePromptLine()
		return err
	}
	confirmOverride := func(plan resynccmd.OverridePlan) error {
		printOverridePlan(plan)
		if plan.TotalReplace == 0 && plan.TotalNew == 0 {
			fmt.Fprintln(out, "nothing to override: the current scans already match the effective baselines")
		}
		if *yes {
			return nil
		}
		err := promptYesNo(input, out, "Replace server records that conflict with the CURRENT scan of the granted Codex/DeepSeek Harness sources?")
		hs.CompletePromptLine()
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *replaceExisting {
		if *dryRun {
			result, err := resynccmd.RunOverride(ctx, resynccmd.OverrideOptions{StateDir: dir, ServerURL: *serverURL, DryRun: true})
			if err == nil {
				printOverridePlan(result.Plan)
				fmt.Fprintln(out, "dry-run: offline plan only; the remote consent scope, the server's replace-existing capability, and scope withholding are not evaluated")
				connect.RenderSyncResult(out, connect.SummarizeOverrideForCLI(result, true), nil, nil, true, *verbose)
			}
			if err != nil {
				return unknown(err)
			}
			return nil
		}
		lock, err := runlock.Acquire(dir)
		if err != nil {
			return unknown(err)
		}
		if err := lock.Close(); err != nil {
			return unknown(err)
		}
		cursorOpts, err := cursorSyncOptions(dir, *serverURL, nil)
		if err != nil {
			return unknown(err)
		}
		cursorOpts.Out = out
		result, err := connect.Sync(ctx, connect.SyncOptions{
			StateDir: dir, ServerURL: *serverURL, Cursor: cursorOpts, Out: out,
			Verbose:               *verbose,
			Progress:              progress,
			ResyncReplaceExisting: true,
			ResyncMaxBatches:      *maxBatches,
			ResyncOverrideConfirm: confirmOverride,
		})
		if err != nil {
			// The confirmation abort keeps its own text; every other
			// failure wraps the closed-set verdict phrase.
			if isResyncConfirmAbort(err) {
				return safeDisplayError(err, confirmAbortDisplayText(err))
			}
			stopHeartbeat()
			connect.RenderSyncResult(out, result, err, ctx.Err(), false, *verbose)
			return safeDisplayError(err, runFailureDisplayText(err, connect.StopReasonPhrase(connect.SyncStopReason(result, err, ctx.Err()))))
		}
		stopHeartbeat()
		connect.RenderSyncResult(out, result, nil, ctx.Err(), false, *verbose)
		if !result.Resync.Completed {
			fmt.Fprintln(out, "Run the same resync --all --replace-existing command again to resume the override pass.")
		}
		return nil
	}
	if *dryRun {
		result, err := resynccmd.Run(ctx, resynccmd.Options{StateDir: dir, ServerURL: *serverURL, DryRun: true})
		if err == nil {
			printPlan(result.Plan)
			fmt.Fprintln(out, "dry-run: archive plan only; source scanning, quarantine recovery and remote consent are not evaluated")
			connect.RenderSyncResult(out, connect.SummarizeResyncForCLI(result, true), nil, nil, true, *verbose)
		}
		if err != nil {
			return unknown(err)
		}
		return nil
	}
	cursorOpts, err := cursorSyncOptions(dir, *serverURL, nil)
	if err != nil {
		return unknown(err)
	}
	cursorOpts.Out = out
	result, err := connect.Sync(ctx, connect.SyncOptions{
		StateDir: dir, ServerURL: *serverURL, Cursor: cursorOpts, Out: out,
		Verbose:      *verbose,
		Progress:     progress,
		ResyncDryRun: *dryRun, ResyncMaxBatches: *maxBatches, ResyncConfirm: confirm,
	})
	if err != nil {
		if isResyncConfirmAbort(err) {
			return safeDisplayError(err, confirmAbortDisplayText(err))
		}
		stopHeartbeat()
		connect.RenderSyncResult(out, result, err, ctx.Err(), false, *verbose)
		return safeDisplayError(err, runFailureDisplayText(err, connect.StopReasonPhrase(connect.SyncStopReason(result, err, ctx.Err()))))
	}
	stopHeartbeat()
	connect.RenderSyncResult(out, result, nil, ctx.Err(), false, *verbose)
	if result.Resync.Remaining > 0 {
		fmt.Fprintln(out, "Run the same resync --all command again to resume.")
	}
	return nil
}

// errResyncDeclined is the private sentinel for the user's explicit
// refusal at an interactive confirmation. It is identified ONLY through
// errors.Is on the wrapping chain, never by message text.
var errResyncDeclined = errors.New("cancelled")

// errResyncConfirmUnavailable is the private sentinel for a
// confirmation that could not be read (no interactive input).
var errResyncConfirmUnavailable = errors.New("confirmation not provided; use --yes only after reviewing the plan")

// promptYesNo prints the exact interactive prompt and reads one bounded
// line: only an explicit y/yes confirms. A refusal returns the private
// sentinel; a closed or unreadable stdin returns the unavailable
// sentinel - never an implicit yes. A scanner I/O failure keeps its
// chain but displays the fixed generic text (the raw I/O message may
// quote paths).
func promptYesNo(input io.Reader, out io.Writer, question string) error {
	fmt.Fprintf(out, "%s [y/N] ", question)
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return safeDisplayError(fmt.Errorf("read confirmation: %w", err), "the confirmation could not be read; use --yes only after reviewing the plan")
		}
		return errResyncConfirmUnavailable
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if answer != "y" && answer != "yes" {
		return errResyncDeclined
	}
	return nil
}

// isResyncConfirmAbort reports whether err carries one of the user's OWN
// confirmation refusals (the private sentinel, anywhere in the wrapping
// chain the sync/override layers built around it). Strictly errors.Is -
// an untrusted error merely CONTAINING "cancelled" never matches here,
// so it can never reach the raw-text display path.
func isResyncConfirmAbort(err error) bool {
	return errors.Is(err, errResyncDeclined) || errors.Is(err, errResyncConfirmUnavailable)
}

// confirmAbortDisplayText renders the refusal's fixed safe text from
// the sentinel it carries - never the wrapped chain's raw text.
func confirmAbortDisplayText(err error) string {
	if errors.Is(err, errResyncDeclined) {
		return "cancelled at the confirmation prompt; nothing was collected or uploaded"
	}
	return "the confirmation was not provided; use --yes only after reviewing the plan"
}
