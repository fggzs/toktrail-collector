package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/app/cursorsync"
	"toktrail-collector/internal/app/diagnostic"
	statuscmd "toktrail-collector/internal/app/status"
	bindcmd "toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/scheduler"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncbudget"
	synccmd "toktrail-collector/internal/syncclient"
	"toktrail-collector/internal/syncretry"
)

var version = "dev"

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "version":
		fmt.Println("toktrail", version)
	case "connect":
		if err := runConnect(os.Args[2:]); err != nil {
			// The same safe display contract as periodic: the curated
			// text when the runner attached one, the fixed fallback
			// otherwise — raw error text (paths, URLs, tokens) is never
			// echoed. Exit code unchanged.
			fmt.Fprintf(os.Stderr, "connect failed: %s\n", displayErrorText(err))
			os.Exit(1)
		}
	case "bind":
		if err := runBind(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "bind failed: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := runStatus(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "status failed: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(1)
		}
	case "preview":
		if err := runPreview(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "preview failed: %v\n", err)
			os.Exit(1)
		}
	case "export":
		if err := runExport(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "export failed: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := runSync(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sync failed: %v\n", err)
			os.Exit(1)
		}
	case "resync":
		if err := runResync(os.Args[2:]); err != nil {
			// Same safe display contract as periodic/connect.
			fmt.Fprintf(os.Stderr, "resync failed: %s\n", displayErrorText(err))
			os.Exit(1)
		}
	case "periodic":
		if err := runPeriodic(os.Args[2:]); err != nil {
			// The unified failure line: displayErrorText renders the
			// curated safe summary when the runner attached one and a
			// fixed fallback otherwise — a raw error text may embed
			// local paths, endpoint URLs or secret-bearing values, so
			// it is never echoed here. The full date-time prefix keeps
			// long-lived appended error logs (periodic.err.log)
			// locatable across days. The error value, its chain and
			// the exit code are untouched (see displayErrorText).
			fmt.Fprintf(os.Stderr, "[%s] periodic failed: %s\n", time.Now().Format("2006-01-02 15:04:05"), displayErrorText(err))
			os.Exit(1)
		}
	case "cursor":
		if err := runCursor(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "cursor failed: %v\n", err)
			os.Exit(1)
		}
	case "sources":
		if err := runSources(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sources failed: %v\n", err)
			os.Exit(1)
		}
	case "plugins":
		if err := runPlugins(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "plugins failed: %v\n", err)
			os.Exit(1)
		}
	case "service":
		if err := runService(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "service failed: %v\n", err)
			os.Exit(1)
		}
	case "privacy":
		if err := runPrivacy(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "privacy failed: %v\n", err)
			os.Exit(1)
		}
	case "upgrade":
		if err := runUpgrade(os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade failed: %v\n", err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "doctor failed: %v\n", err)
			os.Exit(1)
		}
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; try help\n", cmd)
		os.Exit(2)
	}
}

func runBind(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", "http://127.0.0.1:3211"), "toktrail-server base URL")
	ticket := fs.String("ticket", env("TOKTRAIL_BIND_TICKET", ""), "one-time bind ticket")
	applicationID := fs.String("application", env("TOKTRAIL_APPLICATION_ID", "leaderboard-local"), "server application id")
	subjectID := fs.String("subject", env("TOKTRAIL_SUBJECT_ID", ""), "external subject id from leaderboard/account flow")
	deviceName := fs.String("device-name", env("TOKTRAIL_DEVICE_NAME", "toktrail-collector"), "local device name")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := bindcmd.Run(ctx, statedir.New(dir), bindcmd.Options{
		ServerURL:         *serverURL,
		Ticket:            *ticket,
		ApplicationID:     *applicationID,
		ExternalSubjectID: *subjectID,
		DeviceName:        *deviceName,
	})
	if err != nil {
		return err
	}
	replay := "new"
	if result.Replay {
		replay = "replay"
	}
	fmt.Printf("bound device %s (%s), consentRevision=%d, state=%s\n", result.State.DeviceID, replay, result.State.ConsentRevision, statedir.New(dir).Path())
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := statuscmd.Run(ctx, statedir.New(dir), statuscmd.Options{ServerURL: *serverURL})
	if err != nil {
		return err
	}
	fmt.Printf("device %s\n", result.State.DeviceID)
	fmt.Printf("uploadAuthorized=%t publicAuthorized=%t revoked=%t consentRevision=%d\n", result.State.UploadAuthorized, result.State.PublicAuthorized, result.State.Revoked, result.State.ConsentRevision)
	fmt.Printf("checkedAt=%s state=%s\n", result.State.LastCheckedAt.Format(time.RFC3339), statedir.New(dir).Path())
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory; interval sources use it to load confirmed baselines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	// Finish any pending export transaction first so interval baselines
	// are consistent before the claude-code-jsonl progress state is read.
	if err := synccmd.CheckResetJournal(dir); err != nil {
		return err
	}
	if _, err := exportcommit.Recover(dir); err != nil {
		return err
	}
	res, err := pipeline.Scan(adapter.Options{Source: *source, Input: *input, StateDir: dir})
	if err != nil {
		return err
	}
	fmt.Printf("source=%s records=%d valid=%d invalid=%d\n", res.Source, res.RecordCount, res.ValidRecords, res.InvalidRecords)
	fmt.Printf("knownIncludeRecords=%d tokensInclude=%s knownExcludeRecords=%d tokensExclude=%s\n", res.KnownIncludeRecords, formatOptionalUint(res.TokensInclude), res.KnownExcludeRecords, formatOptionalUint(res.TokensExclude))
	if res.EarliestOccurredAt != nil && res.LatestOccurredAt != nil {
		fmt.Printf("range=%s..%s\n", res.EarliestOccurredAt.Format(time.RFC3339), res.LatestOccurredAt.Format(time.RFC3339))
	}
	for _, tool := range adapter.SortedTools(res.Tools) {
		fmt.Printf("tool[%s]=%d\n", tool, res.Tools[tool])
	}
	if res.Quarantined > 0 {
		fmt.Printf("quarantined=%d\n", res.Quarantined)
		if remaining := res.Quarantined - len(res.Issues); remaining > 0 {
			fmt.Printf("quarantineNote=%d more quarantined lines not listed\n", remaining)
		}
	}
	if len(res.Issues) > 0 {
		// Line quarantines and message-level interval diagnostics share the
		// issue list; report even when nothing was quarantined.
		for _, issue := range res.Issues {
			fmt.Printf("issue[%s:%d]=%s\n", issue.File, issue.Line, issue.Reason)
		}
	}
	return nil
}

func runPreview(args []string) error {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	limit := fs.Int("limit", 10, "max records to preview")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory; interval sources use it to load confirmed baselines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	if err := synccmd.CheckResetJournal(dir); err != nil {
		return err
	}
	if _, err := exportcommit.Recover(dir); err != nil {
		return err
	}
	rows, err := pipeline.Preview(adapter.Options{Source: *source, Input: *input, Limit: *limit, StateDir: dir})
	if err != nil {
		return err
	}
	for _, row := range rows {
		status := "ok"
		if !row.Valid {
			status = "invalid:" + row.Error
		}
		fmt.Printf("%d %s tool=%s kind=%s occurredAt=%s include=%s exclude=%s %s\n", row.Index, row.RecordKey, row.Tool, row.Kind, row.Occurred, formatOptionalUint(row.Include), formatOptionalUint(row.Exclude), status)
	}
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", adapter.UsageJSONSource, "local adapter source")
	input := fs.String("input", "", "local usage input path")
	output := fs.String("out", "", "output batch JSON file")
	batchID := fs.String("batch", "", "batch id; generated when omitted")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory for outbox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	if err := synccmd.CheckResetJournal(dir); err != nil {
		return err
	}
	prepared, err := pipeline.PrepareExport(adapter.Options{Source: *source, Input: *input, Output: *output, BatchID: *batchID, StateDir: dir})
	if err != nil {
		return err
	}
	if prepared.Records == 0 {
		// Nothing new since the last confirmed baselines (e.g. all messages
		// frozen or unchanged); committing an empty batch would only churn
		// the outbox and cursor.
		fmt.Printf("no new records for source=%s\n", *source)
		return nil
	}
	chunks, err := pipeline.SplitPreparedExport(prepared)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		res, err := exportcommit.CommitExport(exportcommit.ExportOptions{
			StateDir: dir,
			Prepared: chunk,
			Source:   *source,
			Input:    *input,
		})
		if err != nil {
			return err
		}
		fmt.Printf("exported batch %s records=%d file=%s\n", res.BatchID, res.Records, res.Output)
		fmt.Printf("outbox=%s status=pending\n", res.OutboxPath)
		fmt.Printf("cursor=%s batch=%s\n", res.CursorPath, res.BatchID)
	}
	return nil
}

func runSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	batchFile := fs.String("file", "", "usage batch JSON file to upload")
	batchID := fs.String("batch", "", "override or provide batch id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := synccmd.Run(ctx, statedir.New(dir), synccmd.Options{
		ServerURL: *serverURL,
		StateDir:  dir,
		BatchFile: *batchFile,
		BatchID:   *batchID,
	})
	if err != nil {
		return err
	}
	replay := "new"
	if result.Receipt.Replay {
		replay = "replay"
	}
	if result.Receipt.BatchID == "" {
		// Recovery-only run: no batch was uploaded, quarantined records were
		// re-pended under the live consent scope. The recovered/quarantined
		// line below carries the outcome.
	} else {
		fmt.Printf("synced batch %s (%s), status=%s accepted=%d rejected=%d\n", result.Receipt.BatchID, replay, result.Receipt.Status, result.Receipt.AcceptedRecords, result.Receipt.RejectedRecords)
	}
	fmt.Printf("device=%s consentRevision=%d uploadAuthorized=%t\n", result.Self.DeviceID, result.Self.ConsentRevision, result.Self.UploadAuthorized)
	fmt.Printf("recovered=%d quarantined=%d\n", result.Recovered, result.Quarantined)
	if result.Receipt.BatchID == "" {
		fmt.Printf("state=%s\n", statedir.New(dir).Path())
		return nil
	}
	fmt.Printf("receivedAt=%s state=%s\n", result.Receipt.ReceivedAt.Format(time.RFC3339), statedir.New(dir).Path())
	return nil
}

func formatOptionalUint(v *uint64) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%d", *v)
}

// ---------------------------------------------------------------------------
// periodic: the complete-exit scheduled entry. It collects only the
// explicitly granted sources (grants.json), exports with the existing
// exportcommit WAL, and drains pending batches with the existing
// syncclient (server fresh-consent preflight preserved). One process
// lock covers the entire run; overlapping runs fail fast.
//
// §6.2 drain shape: with neither an explicit --max-batches nor a positive
// --max-total-batches, one run scans each granted source exactly once,
// pulls the account upstream exactly once, and then keeps the lock and
// drains the device outbox and the account cursor queue in fair rotation
// (one batch per queue per turn) until both queues are exhausted, a turn
// makes no progress, the run is cancelled, or the shared budget of 100
// POSTs within the --sync-timeout window (20 minutes by default) declines
// — a decline with work left exits non-zero as an incomplete run.
// ---------------------------------------------------------------------------

func runPeriodic(args []string) error {
	return runPeriodicIO(args, os.Stdout, os.Stderr)
}

// runPeriodicIO runs the periodic command with explicit output
// writers. By default (no --json, no --verbose) stdout carries exactly
// ONE concise English status line — timestamp, this run's
// server-confirmed counts, observable pending, and an idle marker when
// nothing new was collected — rendered from the SAME closed-set
// collection.Summarize classification the --json verdict uses (never
// from err==nil). Real errors are stated exactly once through main's
// unified "periodic failed:" line; the round itself never duplicates
// the reason. --verbose replaces the concise line with the detailed
// per-phase log (counts and closed status codes only; never
// credentials, URLs, tickets, raw records, local paths or untrusted
// free text). With --json, stdout carries EXACTLY one JSON object —
// the stable §6.5 result, printed on every exit path including
// errors — while all human text (the concise line, the verbose log,
// incomplete reasons) moves to stderr, so the machine stream stays
// parseable. The returned error, and therefore the process exit code,
// is identical with and without --json: partial completion still
// exits non-zero and the historical zero-exit shapes (a paused run
// with nothing pending, an explicitly bounded drain) still exit zero
// — the JSON verdict never dresses partial completion up as success
// (stop_reason differs from "complete" on those shapes).
//
// Human heartbeat: while --progress-json is off, a long run prints
// nothing between its start and its final line, so a filtering
// progress callback (reusing the collection round's existing
// ProgressEmitter) renders one human heartbeat line roughly every 30
// seconds on the human stream. The callback shares the existing
// progress-callback I/O contract: the emitter dispatches it
// synchronously under its own mutex — exactly like the JSON event
// writer — so a blocked writer delays subsequent progress events the
// same way the --progress-json writer already does; the throttle
// rejects every intervening event before any I/O, so the cost is at
// most one small line per ~30 seconds, and the emitter's deferred
// Stop joins its ticker goroutine on every exit path (cancellation
// included). When --progress-json is on, the machine events already
// provide the periodic output, so no human heartbeat is added and the
// event writer stays byte-identical to the historical one.
func runPeriodicIO(args []string, stdout, stderr io.Writer) error {
	started := time.Now()
	fs := flag.NewFlagSet("periodic", flag.ContinueOnError)
	// The flag package echoes raw argument VALUES in its own
	// parse-error output ("invalid value \"...\" for flag
	// --sync-timeout") and prints them to the flag set's output BEFORE
	// Parse returns, so a value that carries a token, URL or path would
	// leak through fs.SetOutput(stderr). The flag set therefore writes
	// into a capture buffer that is discarded on parse failure; only the
	// -h usage (static help text, no argument values) is re-emitted to
	// keep the help convention. The raw parse error stays in the
	// returned chain (errors.Is, the --json usage-error object); only
	// its display is the fixed safe text.
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	maxBatches := fs.Int("max-batches", collection.DefaultMaxSyncBatches, "max pending batches to upload per active queue per run (an explicit legacy bound; the default run instead drains until the shared upload budget stops it)")
	maxTotalBatches := fs.Int("max-total-batches", 0, "max total ingest batch uploads shared across the device and cursor queues this run; when the budget is exhausted with work left, the run reports incomplete and exits non-zero (0=unset)")
	syncTimeout := fs.Duration("sync-timeout", collection.DefaultSharedPOSTWindow, "overall periodic run timeout, covering the source scan and the uploads; the default shared upload budget's deadline follows this value (§6.2 default: 20 minutes)")
	drainOnly := fs.Bool("drain-only", false, "only drain existing device outbox batches; do not refresh grants, scan sources, or run account sources")
	parallelScans := fs.Int("max-parallel-scans", collection.DefaultMaxParallelScans, "how many granted sources are read and parsed at the same time (filtering and uploads stay serialized; 1 = one at a time)")
	progressJSON := fs.Bool("progress-json", false, "emit collection progress events as JSON Lines on stderr")
	verbose := fs.Bool("verbose", false, "print the detailed per-phase run log (counts and closed status codes only; never credentials, URLs, tickets or raw records) instead of the default one-line status summary")
	jsonOut := fs.Bool("json", false, "print the run's stable §6.5 result (stop_reason and phase counts) as a single JSON object on stdout; human output moves to stderr")
	// The automatic -h help prints every flag's DefValue, and two of
	// them come from the environment (TOKTRAIL_SERVER_URL may carry an
	// endpoint with credentials; TOKTRAIL_HOME a local path), so their
	// recorded defaults are scrubbed to the empty string AFTER
	// registration — PrintDefaults then omits the "(default ...)"
	// suffix entirely while the usage text still documents the
	// behavior. The live flag values are untouched.
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == "server" || f.Name == "state-dir" {
			f.DefValue = ""
		}
	})
	if err := fs.Parse(args); err != nil {
		// Flag parsing failed before the flags were readable; a literal
		// --json in the raw arguments is the best-effort signal to still
		// emit the result object for the usage error.
		if jsonWantsEmission(fs, *jsonOut, args) {
			emitResultJSON(stdout, collection.SummarizeNotRun(err, "periodic", elapsedMS(started)))
		}
		if errors.Is(err, flag.ErrHelp) {
			// -h: the captured usage is static flag help (no argument
			// values); re-emit it verbatim to keep the help convention.
			_, _ = io.WriteString(stderr, flagOutput.String())
			return safeDisplayError(err, err.Error())
		}
		// Any other parse failure: the flag package's own output (and
		// the raw error text) may echo the user's argument value, which
		// can carry a token, URL or path — it is never displayed. The
		// chain keeps the original error for errors.Is and the JSON
		// usage-error object; the display is the fixed safe text.
		return safeDisplayError(err, "invalid flag or flag value (raw text withheld; run \"toktrail help\" for usage)")
	}
	// The human stream: stdout by default (the historical behavior);
	// stderr under --json, keeping stdout to exactly one JSON object.
	// The serialized stderr sink: when progress events share the stream
	// with human text (always stderr for events; human moves there under
	// --json), one mutex serializes every write so lines never interleave
	// and no ticker/run-goroutine pair races on the writer. With progress
	// off the plain writer is kept for the machine-event stream.
	stderrSink := io.Writer(stderr)
	if *progressJSON {
		stderrSink = newSerializedWriter(stderr)
	}
	human := io.Writer(stdout)
	if *jsonOut {
		human = stderrSink
	}
	if !*progressJSON {
		// The human heartbeat is armed (machine events are off): its
		// lines arrive from the emitter's ticker goroutine while the run
		// goroutine keeps writing prompts and verbose detail, so the
		// human stream gets the same per-line serialization the event
		// sink has. Sequential writes stay byte-identical to the plain
		// writer; only concurrent heartbeat writes gain ordering.
		if *jsonOut {
			human = newSerializedWriter(stderr)
		} else {
			human = newSerializedWriter(stdout)
		}
	}
	// The progress wiring, distinguishing the machine and human modes:
	//   - --progress-json: the historical JSONL event writer, unchanged
	//     and byte-identical (never the heartbeat);
	//   - otherwise: the ~30s human heartbeat filter over the same
	//     collection ProgressEmitter (batch/queue events are dropped —
	//     they are machine events and the default output stays one
	//     line; only heartbeat events render, throttled).
	var progress func(collection.ProgressEvent)
	var heartbeat *periodicHumanHeartbeat
	if *progressJSON {
		progress = writeCollectionProgressJSON(stderrSink)
	} else {
		// A terminal gets a single in-place status line; a redirected
		// stream (the scheduled task's log, CI, a pipe) gets no periodic
		// chatter at all beyond one low-frequency stall notice, so logs
		// stay readable instead of filling with repeated "Still running"
		// lines every thirty seconds.
		heartbeat = newPeriodicHumanHeartbeatFor(human, started, time.Now, isTerminalWriter(stdout))
		progress = heartbeat.handle
	}
	result, runErr, ctxErr, ran := runPeriodicRound(fs, human, progress, *serverURL, *stateDir, *maxBatches, *maxTotalBatches, *parallelScans, *syncTimeout, *drainOnly, *verbose)
	if heartbeat != nil {
		// Close the in-place status line before the summary is rendered:
		// the summary must start on its own line, never appended to a
		// half-finished progress line.
		heartbeat.Close()
	}
	// One summary feeds both surfaces, so the concise human line and
	// the --json verdict can never disagree: the classification is the
	// closed-set walk (stop_reason, observation bits), never err==nil.
	var summary collection.RunSummary
	switch {
	case !ran:
		// The round never started (validation, state directory or
		// wiring failure): report not_run phases, never a fabricated
		// drained queue.
		summary = collection.SummarizeNotRun(runErr, "periodic", elapsedMS(started))
	case *drainOnly:
		// The explicit partial mode: the device queue only, the
		// account source never read. A clean run keeps its historical
		// exit zero but the verdict never claims global completion.
		summary = collection.SummarizePartialMode(result, runErr, ctxErr, "periodic", elapsedMS(started))
	default:
		summary = collection.Summarize(result, runErr, ctxErr, "periodic", elapsedMS(started))
	}
	if !*verbose && ran {
		// The default one-line summary. Pre-run failures (ran=false)
		// print no status line: nothing ran, and main's unified error
		// line is the single, clear reason surface.
		periodicConciseResult(human, summary, *drainOnly, time.Now())
	}
	if *jsonOut {
		emitResultJSON(stdout, summary)
	}
	// runErr is already wrapped with its safe display text at every
	// construction site inside the round (chain, err.Error() and every
	// errors.Is/As match preserved verbatim); the summary above read
	// the same error value, so the JSON verdict is unchanged too.
	return runErr
}

// runPeriodicRound is the periodic body after flag parsing. In the
// default (concise) mode it prints NO run summary or reason lines at
// all: the one-line status summary is rendered by runPeriodicIO from
// the shared closed-set classification, and a real error is stated
// exactly once by main's unified "periodic failed:" line. In --verbose
// mode the historical detail lines print to human (and the progress
// events flow through the caller's progress callback). It returns the
// collection result, the run error (nil on the historical zero-exit
// shapes; every non-nil error is wrapped with its curated SafeDisplay
// text while the chain and err.Error() stay verbatim), the run
// context's cancellation/deadline state for §6.5 classification (including
// a proven elapsed deadline before the context timer fires), and whether
// the collection round actually started (false for the pre-run
// failures, so the summary reports not_run instead of a drained
// queue).
func runPeriodicRound(fs *flag.FlagSet, human io.Writer, progress func(collection.ProgressEvent), serverURL, stateDir string, maxBatches, maxTotalBatches, maxParallelScans int, syncTimeout time.Duration, drainOnly, verbose bool) (collection.Result, error, error, bool) {
	if syncTimeout <= 0 {
		err := fmt.Errorf("--sync-timeout must be positive")
		return collection.Result{}, safeDisplayError(err, err.Error()), nil, false
	}
	if maxTotalBatches < 0 {
		err := fmt.Errorf("--max-total-batches must be non-negative")
		return collection.Result{}, safeDisplayError(err, err.Error()), nil, false
	}
	// flag.Visit reports only the flags the user actually passed, so it
	// is the explicit-ness signal for the legacy --max-batches bound:
	// only an explicitly given bound keeps the historical per-queue cap
	// (never truncated by the default shared total), while an unset one
	// hands the run to the §6.2 shared-budget drain.
	maxBatchesExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-batches" {
			maxBatchesExplicit = true
		}
	})
	dir := stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return collection.Result{}, safeDisplayError(err, "cannot determine the local TokTrail state directory"), nil, false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	// Shared POST budget and drain shape (§6.2):
	//   - an explicit --max-batches WITHOUT a total keeps the historical
	//     unbudgeted behavior — no shared budget exists, so the per-queue
	//     bound is never truncated by a default total;
	//   - an explicit --max-total-batches (with or without --max-batches)
	//     arms the shared total; with --max-batches the fair rotation
	//     still respects each queue's own bound;
	//   - with neither bound given, the default profile arms 100 shared
	//     POSTs within the effective --sync-timeout window (2 minutes by
	//     default, exactly the value the user passes when explicit).
	// When the pool declines an attempt, the batch was never POSTed and
	// stays pending: the run reports itself incomplete and exits
	// non-zero instead of a quiet bounded stop.
	budget, fair := periodicUploadPlan(time.Now, maxBatchesExplicit, maxTotalBatches, syncTimeout)
	// The run's single bounded retry policy for transient send
	// failures: full jitter (never deterministic), with the run
	// deadline pinned to THIS run's ctx deadline — the --sync-timeout
	// window every periodic run carries — so every queue of the run
	// (device outbox, account source) retries under the same bound and
	// no retry wait can outlive the run. A defensive real-time cap
	// covers a ctx that somehow carries no deadline.
	retryDeadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		retryDeadline = time.Now().Add(syncTimeout)
	}
	retry := syncretry.New(
		syncretry.WithJitter(syncretry.FullJitter),
		syncretry.WithRunDeadline(retryDeadline),
	)
	options := collection.Options{
		StateDir:         dir,
		ServerURL:        serverURL,
		MaxBatches:       0,
		FairDrain:        fair,
		Budget:           budget,
		Retry:            retry,
		CollectorVersion: version,
		Progress:         progress,
		MaxParallelScans: maxParallelScans,
	}
	// Only an explicitly passed legacy bound reaches the collection: the
	// flag's default value must not cap the fair drain.
	if maxBatchesExplicit {
		options.MaxBatches = maxBatches
		if options.MaxBatches <= 0 {
			options.MaxBatches = collection.DefaultMaxSyncBatches
		}
	}
	drainLimit := options.MaxBatches
	var result collection.Result
	var err error
	if drainOnly {
		result, err = collection.DrainPending(ctx, options)
	} else {
		// Account-level cursor source wiring (desktop credential reader +
		// pinned-host Cursor API client). Construction reads no credential
		// and touches no network; the periodic cursor branch runs only when
		// a local permit exists.
		cursorOpts, cursorErr := periodicCursorOptions(dir, serverURL, nil)
		if cursorErr != nil {
			return collection.Result{}, safeDisplayError(cursorErr, "cannot initialize the account source (cursor) wiring"), nil, false
		}
		cursorOpts.MaxBatches = options.MaxBatches
		cursorOpts.Budget = budget
		// One run, one retry policy: the account-source queue retries
		// transient failures under the same run deadline as the device
		// queue (nil Retry would silently keep it single-shot).
		cursorOpts.Retry = retry
		// The cursor round's own human lines (and, on a first-time
		// enable, its interactive confirmation) belong on the human
		// stream, never on the JSON machine stream.
		cursorOpts.Out = human
		options.Cursor = cursorOpts
		result, err = collection.Run(ctx, options)
	}
	if err != nil {
		if periodicRunTimedOut(err, ctx.Err(), retryDeadline, time.Now()) {
			if verbose {
				printPeriodicResult(human, result)
				fmt.Fprintf(human, "incomplete: the periodic run timeout (%s) elapsed; remaining work stays pending\n", syncTimeout)
			}
			msg := fmt.Sprintf("periodic incomplete: run timeout (%s) elapsed", syncTimeout)
			return result, safeDisplayError(fmt.Errorf("%s: %w", msg, err), msg+"; remaining work stays pending"), context.DeadlineExceeded, true
		}
		if isSyncBudgetDecline(err) {
			// The shared upload budget stopped the run before some of its
			// work (pending device batches, pending account batches,
			// not-yet-uploaded exports): report the partial result as
			// incomplete and exit non-zero. The declined batches were
			// never POSTed and stay pending; remaining work stays pending
			// under its own fresh budget.
			if verbose {
				printPeriodicResult(human, result)
				if result.PendingRemaining > 0 {
					fmt.Fprintf(human, "pendingRemaining=%d (stopped by the shared upload budget; remaining work stays pending)\n", result.PendingRemaining)
				}
				switch {
				case maxTotalBatches > 0:
					fmt.Fprintf(human, "incomplete: the --max-total-batches %d shared upload budget is exhausted (devicePending=%d cursorPending=%d); remaining work stays pending\n",
						maxTotalBatches, result.PendingRemaining, result.Cursor.PendingRemaining)
				case errors.Is(err, syncbudget.ErrDeadlineExceeded):
					fmt.Fprintf(human, "incomplete: the periodic upload window (--sync-timeout %s) elapsed with work remaining (devicePending=%d cursorPending=%d); remaining work stays pending\n",
						syncTimeout, result.PendingRemaining, result.Cursor.PendingRemaining)
				default:
					fmt.Fprintf(human, "incomplete: the default shared upload budget (%d POSTs / %s) is exhausted (devicePending=%d cursorPending=%d); remaining work stays pending\n",
						collection.DefaultSharedPOSTBudget, syncTimeout, result.PendingRemaining, result.Cursor.PendingRemaining)
				}
			}
			var msg string
			switch {
			case maxTotalBatches > 0:
				msg = fmt.Sprintf("periodic incomplete: the shared upload budget (--max-total-batches %d) is exhausted with work remaining", maxTotalBatches)
			case errors.Is(err, syncbudget.ErrDeadlineExceeded):
				msg = fmt.Sprintf("periodic incomplete: the periodic upload window (--sync-timeout %s) elapsed with work remaining", syncTimeout)
			default:
				msg = fmt.Sprintf("periodic incomplete: the default shared upload budget (%d POSTs / %s) is exhausted with work remaining",
					collection.DefaultSharedPOSTBudget, syncTimeout)
			}
			return result, safeDisplayError(fmt.Errorf("%s: %w", msg, err), msg+"; remaining work stays pending"), ctx.Err(), true
		}
		return result, safeDisplayError(err, periodicRunErrorSafeText(err, ctx.Err())), ctx.Err(), true
	}
	if verbose {
		printPeriodicResult(human, result)
		if result.PendingRemaining > 0 {
			if fair {
				if maxBatchesExplicit {
					fmt.Fprintf(human, "pendingRemaining=%d (drain stops at %d batch(es) per queue per run; remaining work stays pending)\n", result.PendingRemaining, drainLimit)
				} else {
					fmt.Fprintf(human, "pendingRemaining=%d (the run stopped before the queues were empty; remaining work stays pending)\n", result.PendingRemaining)
				}
			} else {
				fmt.Fprintf(human, "pendingRemaining=%d (drain stops at %d batch(es) per run; remaining work stays pending)\n", result.PendingRemaining, drainLimit)
			}
		}
	}
	// §6.5/F1: a granted source that failed to read or export is an
	// incomplete run — never a quiet exit zero. The judgment reads only
	// the structured GrantSkipCode (GrantOutcome.Fault); not_allowed
	// (the server scope excludes the source) is an authorization
	// verdict and stays a complete exit.
	if faults := grantFaultCount(result); faults > 0 {
		if verbose {
			fmt.Fprintf(human, "incomplete: %d granted source(s) did not complete this run (input inaccessible or export failed); their remaining work stays pending\n", faults)
		}
		msg := fmt.Sprintf("periodic incomplete: %d granted source(s) did not complete", faults)
		return result, safeDisplayError(fmt.Errorf("%w: %s", collection.ErrIncompleteRun, msg), msg+"; their remaining work stays pending"), ctx.Err(), true
	}
	// §6.5: an authorized source whose pending restriction could not be
	// classified (a reason outside the closed wire vocabulary) is an
	// incomplete run — the historical exit zero would dress an uncovered
	// authorization up as success. User-disabled and unsupported tools
	// are no-concern states and never trigger this, and a default input
	// that was never detected is the normal skip of a tool this device
	// never installed (still observable in the grantSync pending lines
	// and the scope summary). The count is the only detail reported: no
	// tool names, paths or reason text.
	if concerns := collection.PendingCoverageConcerns(result.GrantSync.Pending); concerns > 0 {
		if verbose {
			fmt.Fprintf(human, "incomplete: %d authorized source(s) are not covered on this device (unclassified restriction); their remaining work stays pending\n", concerns)
		}
		msg := fmt.Sprintf("periodic incomplete: %d authorized source(s) are not covered", concerns)
		return result, safeDisplayError(fmt.Errorf("%w: %s", collection.ErrIncompleteRun, msg), msg+"; their remaining work stays pending"), ctx.Err(), true
	}
	// §6.5: a successful (nil-error) run still owes the truth about its
	// account queue — a round that failed, drifted or paused with work
	// queued is an incomplete run, never a quiet exit zero. The judgment
	// reads only the structured cursorsync outcome, never Skipped/Note
	// text; the device-queue report above stays exactly as it was.
	if reason, incomplete := periodicCursorIncomplete(result.Cursor); incomplete {
		if verbose {
			// The verbose reason is the structured phrase (the closed
			// vocabulary derived from the round outcome), never the
			// free-text Skipped/Note diagnostic that may embed raw
			// error text.
			fmt.Fprintf(human, "incomplete: the account cursor source %s; remaining work stays pending\n", cursorIncompleteStructuredText(result.Cursor))
		}
		return result, safeDisplayError(fmt.Errorf("%w: periodic incomplete: the account cursor source %s", collection.ErrIncompleteRun, reason),
			"periodic incomplete: the account cursor source "+cursorIncompleteStructuredText(result.Cursor)+"; remaining work stays pending"), ctx.Err(), true
	}
	return result, nil, ctx.Err(), true
}

// periodicRunTimedOut recognizes the run's own deadline independently of when
// the context timer goroutine updates Err. On Windows that update can lag the
// wall-clock check in syncretry. A retry that cannot fit a future deadline, or
// a client timeout while the run still has time, must not claim time elapsed.
func periodicRunTimedOut(err, ctxErr error, deadline, now time.Time) bool {
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, syncretry.ErrRetryPastDeadline) {
		return false
	}
	if errors.Is(ctxErr, context.Canceled) {
		return false
	}
	return errors.Is(ctxErr, context.DeadlineExceeded) || (!deadline.IsZero() && !now.Before(deadline))
}

// periodicRunErrorSafeText maps a non-budget, non-timeout run error to
// its closed English rendering for main's unified failure line. The
// mapping keys only off error sentinels — never message text — and the
// residual default is a fixed fallback: a raw collection error may
// embed local paths, endpoint URLs or secret-bearing values, so its
// text is never displayed. The run-context deadline keeps its earlier
// budget wording (stop_reason and the JSON verdict are untouched by
// this display mapping); the deadline case here is the bare in-chain
// sentinel (a client or network timeout).
func periodicRunErrorSafeText(err, ctxErr error) string {
	switch {
	case errors.Is(err, runlock.ErrBusy):
		return "another collector process holds the collector state lock; no work was performed"
	case errors.Is(err, syncretry.ErrRetryExhausted):
		return "periodic incomplete: the bounded retry policy spent its retries before the run deadline; remaining work stays pending"
	case errors.Is(err, syncretry.ErrRetryPastDeadline):
		return "periodic incomplete: the next retry cannot fit within the run deadline; remaining work stays pending"
	case errors.Is(err, context.Canceled), errors.Is(ctxErr, context.Canceled):
		return "the run was cancelled before it finished"
	case errors.Is(err, os.ErrPermission):
		return "local access denied; check permissions"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "operation timed out"
	case errors.Is(err, collection.ErrToolStatusReport):
		return "the usage upload was confirmed, but its source status report failed; remaining work stays pending"
	default:
		return "the collection round failed (details withheld; review the configuration before another run)"
	}
}

// ---------------------------------------------------------------------------
// periodic display surfaces: the safe error wrapper, the default
// one-line summary and the human heartbeat. Everything here renders
// ONLY closed vocabularies and counts — never credentials, URLs,
// tickets, raw records, local paths or untrusted free text.
// ---------------------------------------------------------------------------

// displaySafeError couples a returned error with its curated safe
// rendering for main's unified failure line. Error() and Unwrap()
// delegate verbatim, so the wrapped error keeps its exact text, chain
// and every errors.Is/As match — only the display changes.
type displaySafeError struct {
	err  error
	safe string
}

func (e *displaySafeError) Error() string       { return e.err.Error() }
func (e *displaySafeError) Unwrap() error       { return e.err }
func (e *displaySafeError) SafeDisplay() string { return e.safe }

// safeDisplayError wraps err (a nil err stays nil) with the safe human
// rendering used by main's unified failure line.
func safeDisplayError(err error, safe string) error {
	if err == nil {
		return nil
	}
	return &displaySafeError{err: err, safe: safe}
}

// displayErrorText renders a command failure for main's unified error
// line: the curated safe text of a *displaySafeError constructed in
// THIS package (never a SafeDisplay method on an arbitrary external
// error type, whose string is untrusted), and a fixed fallback for
// everything else — a raw error text may embed local paths, endpoint
// URLs or secret-bearing values, so it is never echoed. The error
// value, its chain and the exit code are untouched.
func displayErrorText(err error) string {
	var safe *displaySafeError
	if errors.As(err, &safe) {
		return safe.safe
	}
	return "the run failed (unclassified; details withheld; review the configuration before another run)"
}

// cursorIncompleteStructuredText renders the account cursor round's
// incompleteness phrase from the closed RoundOutcome vocabulary and
// its counts — never the free-text Skipped/Note diagnostic, which may
// embed raw error text. The phrases mirror the historical wording so
// the verbose line stays recognizable.
func cursorIncompleteStructuredText(cursor cursorsync.Result) string {
	switch cursor.Outcome {
	case cursorsync.RoundError:
		return "failed this run"
	case cursorsync.RoundFenceStop:
		return "stopped by an authorization or source-state change"
	case cursorsync.RoundPaused:
		if cursor.PendingRemaining > 0 {
			return fmt.Sprintf("is paused with %d batch(es) still pending", cursor.PendingRemaining)
		}
	}
	if cursor.SkippedNoStableID > 0 {
		return fmt.Sprintf("skipped %d usage event(s) without a stable upstream id (those events are not counted)", cursor.SkippedNoStableID)
	}
	return "did not complete"
}

// periodicStatusPhrase maps the closed §6.5 stop_reason onto the
// natural English status word of the default one-line summary. The
// mapping is total (an unknown value reads as incomplete, never as
// success), and the machine vocabulary stays available through --json
// and the verbose log.
func periodicStatusPhrase(reason collection.StopReason) string {
	switch reason {
	case collection.StopComplete:
		return "Complete"
	case collection.StopPartial:
		return "Partial"
	case collection.StopPaused:
		return "Paused"
	case collection.StopBounded:
		return "Stopped at the requested batch limit"
	case collection.StopBusy:
		return "Busy"
	case collection.StopCancelled:
		return "Cancelled"
	case collection.StopScopeChanged:
		return "Authorization changed"
	case collection.StopBudgetExhausted, collection.StopRetryExhausted, collection.StopFatalError:
		return "Incomplete"
	default:
		return "Incomplete"
	}
}

// pluralRecords/pluralBatches render simple English plurals for the
// natural-language summary line.
func pluralRecords(n int) string {
	if n == 1 {
		return "1 record"
	}
	return fmt.Sprintf("%d records", n)
}

func pluralBatches(n int) string {
	if n == 1 {
		return "1 batch"
	}
	return fmt.Sprintf("%d batches", n)
}

// periodicConciseResult renders the DEFAULT one-line English run
// summary: timestamp, this run's server-confirmed record count, the
// observable pending state, and an idle marker when the scan provably
// ran to completion over every granted source and found nothing new.
// Every value comes from the same closed-set summary the --json
// verdict uses; pending appears only where its queue was actually
// observed (an unobserved queue never reads as zero), and "confirmed"
// means server-receipt-confirmed this run — never a claim about new
// unique records. "no new records" is stated ONLY for a globally
// complete run whose scan demonstrably ran (a partial verdict, a
// drain-only run, a no-grants run or a paused run never claims it —
// unexamined scope stays neutral); any confirmed count always shows,
// so a backlog drain never reads as idleness.
func periodicConciseResult(w io.Writer, summary collection.RunSummary, drainOnly bool, now time.Time) {
	phases := summary.Phases
	drain, account, counts := phases.Drain, phases.Drain.Account, phases.Counts

	// Only a globally COMPLETE run may claim "no new records": a
	// partial verdict (drain-only, an uncovered authorized source)
	// leaves scope unexamined, so it keeps the neutral wording.
	// scanProvedRan: the scan phase demonstrably ran — at least one
	// granted source returned a real scan verdict (the healthy
	// empty-scan code or an export) or the account round pulled. A run
	// whose grants are all not-allowed, disabled or otherwise never
	// scanned proves nothing, and drain-only / no-grants runs scan
	// nothing at all; those keep the neutral wording.
	scanProvedRan := phases.Scan.Account.Ran
	for _, src := range phases.Scan.Sources {
		if src.Status == collection.GrantNoNewRecords || src.Status == collection.GrantExported {
			scanProvedRan = true
			break
		}
	}
	// nothingNew: no source exported and no account pull produced new,
	// replaced or re-emitted records.
	nothingNew := counts.ExportedRecords == 0 &&
		(!phases.Scan.Account.Ran ||
			(phases.Scan.Account.NewRecords == 0 && phases.Scan.Account.ReplacedRecords == 0 && phases.Scan.Account.ReemittedRecords == 0))
	for _, src := range phases.Scan.Sources {
		if src.Status == collection.GrantExported {
			nothingNew = false
			break
		}
	}
	// scanProvedEmpty: the only state in which "no new records" is a
	// provable claim rather than a guess — complete status AND a
	// demonstrably-run scan AND nothing new anywhere.
	scanProvedEmpty := summary.StopReason == collection.StopComplete && scanProvedRan && nothingNew

	var clauses []string
	confirmed := counts.SyncedRecords > 0 || counts.SyncedBatches > 0
	switch {
	case confirmed:
		text := fmt.Sprintf("%s confirmed in %s", pluralRecords(counts.SyncedRecords), pluralBatches(counts.SyncedBatches))
		if counts.ExportedRecords > 0 {
			text += fmt.Sprintf(", %s newly exported", pluralRecords(counts.ExportedRecords))
		}
		if scanProvedEmpty {
			text += ", no new records this scan"
		}
		clauses = append(clauses, text)
	case scanProvedEmpty:
		clauses = append(clauses, "no new records")
	case counts.ExportedRecords > 0:
		clauses = append(clauses, fmt.Sprintf("no records confirmed yet, %s exported", pluralRecords(counts.ExportedRecords)))
	default:
		// Nothing was confirmed and nothing new is provable (a
		// drain-only run, a no-grants run, a paused or incomplete one):
		// the honest neutral wording, never a "no new records" claim.
		clauses = append(clauses, "no records confirmed")
	}
	if clause := conciseFaultedSourcesClause(phases.Scan.Sources); clause != "" {
		clauses = append(clauses, clause)
	}
	if counts.RejectedRecords > 0 {
		clauses = append(clauses, fmt.Sprintf("%s rejected by the server", pluralRecords(counts.RejectedRecords)))
	}
	if counts.Recovered > 0 {
		clauses = append(clauses, fmt.Sprintf("%d quarantined records recovered", counts.Recovered))
	}
	if counts.Quarantined > 0 {
		clauses = append(clauses, fmt.Sprintf("%d records quarantined", counts.Quarantined))
	}
	clauses = append(clauses, periodicPendingClause(drain, account, drainOnly))

	fmt.Fprintf(w, "[%s] %s: %s.\n", now.Format("2006-01-02 15:04:05"), periodicStatusPhrase(summary.StopReason), strings.Join(clauses, "; "))
}

// conciseFaultedSourcesClause renders the granted sources whose closed
// scan status is a fault (the input no longer reads, or the export
// failed): at most three canonical registry names with their closed
// fault phrase, the remainder summarized as a count. Input paths and
// free text never appear — only the structured GrantSkipCode — and the
// canonicalization defends against a contaminated summary so a hostile
// source name never echoes. The main error line stays count-only, so
// the detail lives exactly here.
func conciseFaultedSourcesClause(sources []collection.GrantSourceStatus) string {
	const maxNamed = 3
	var named []string
	total := 0
	for _, src := range sources {
		switch src.Status {
		case collection.GrantInputInaccessible, collection.GrantExportFailed, collection.GrantSplitFailed:
			total++
			if len(named) < maxNamed {
				named = append(named, fmt.Sprintf("%s (%s)", canonicalToolDisplay(src.Source), grantFaultPhrase(src.Status)))
			}
		}
	}
	if total == 0 {
		return ""
	}
	clause := fmt.Sprintf("%d source(s) did not complete: %s", total, strings.Join(named, ", "))
	if rest := total - len(named); rest > 0 {
		clause += fmt.Sprintf(", and %d more", rest)
	}
	return clause
}

// grantFaultPhrase maps a closed fault GrantSkipCode onto its fixed
// English phrase for the concise faulted-sources clause.
func grantFaultPhrase(status collection.GrantSkipCode) string {
	switch status {
	case collection.GrantInputInaccessible:
		return "input not accessible"
	case collection.GrantExportFailed:
		return "export preparation failed"
	case collection.GrantSplitFailed:
		return "export split failed"
	default:
		return "unclassified fault"
	}
}

// periodicPendingClause renders the observable pending state in
// natural English. A queue's count appears only when it was actually
// measured (PendingObserved); an unobserved queue never reads as zero
// and the global "nothing pending" is reserved for runs where BOTH
// queues were measured. The account queue distinguishes "not read"
// (an absent round) from "unknown" (a round that ended before
// measuring) — and the absent-round wording never infers the command
// mode from the outcome alone: only the caller's explicit drain-only
// flag may name the mode, every other absent round stays neutral.
func periodicPendingClause(drain collection.DrainSummary, account collection.AccountDrainSummary, drainOnly bool) string {
	if drain.PendingObserved && account.PendingObserved {
		if total := drain.PendingRemaining + account.PendingRemaining; total > 0 {
			return fmt.Sprintf("%s pending", pluralBatches(total))
		}
		return "nothing pending"
	}
	if drain.PendingObserved && !account.PendingObserved {
		if account.Outcome == cursorsync.RoundAbsent {
			if drainOnly {
				// A drain-only run never refreshes grants or scans the
				// granted sources, so an empty device queue says nothing
				// about whether new local records exist. The wording must
				// not let "nothing pending" read as "collection is up to
				// date".
				if drain.PendingRemaining == 0 {
					return "device queue empty, nothing was scanned and the account queue was not read (drain-only)"
				}
				return fmt.Sprintf("%s pending (drain-only; nothing was scanned and the account queue was not read)", pluralBatches(drain.PendingRemaining))
			}
			// An absent account round WITHOUT the drain-only flag: the
			// mode is not inferable from the outcome, so the wording
			// stays neutral about why the queue was not read.
			if drain.PendingRemaining == 0 {
				return "device queue empty; account queue not read"
			}
			return fmt.Sprintf("%s pending on the device queue; account queue not read", pluralBatches(drain.PendingRemaining))
		}
		if drain.PendingRemaining == 0 {
			return "nothing pending on the device queue; cursor pending unknown"
		}
		return fmt.Sprintf("%s pending on the device queue; cursor pending unknown", pluralBatches(drain.PendingRemaining))
	}
	if !drain.PendingObserved && account.PendingObserved {
		// The account queue was measured but the device queue was not:
		// the measured count always shows — a known positive queue is
		// never swallowed by the unknown — and the unmeasured side is
		// named as unknown, never as zero.
		if account.PendingRemaining > 0 {
			batches := "batches"
			if account.PendingRemaining == 1 {
				batches = "batch"
			}
			return fmt.Sprintf("%d account %s pending; device pending unknown", account.PendingRemaining, batches)
		}
		return "account queue empty; device pending unknown"
	}
	return "pending unknown"
}

// periodicHumanHeartbeatInterval is the nominal cadence of the default
// human heartbeat during long runs (plan §10 keeps the machine
// heartbeat at ~5s; the human line is deliberately quieter).
const periodicHumanHeartbeatInterval = 30 * time.Second

// periodicHumanHeartbeat renders the ~30s human heartbeat line for a
// run whose machine events are off. It wraps the collection round's
// existing progress callback: the emitter dispatches every event
// synchronously under its own mutex, so handle is never invoked
// concurrently with itself — but it MAY be invoked from the emitter's
// ticker goroutine, which is why the heartbeat writes only through the
// caller's serialized human stream.
//
// I/O contract (the same one the --progress-json event writer already
// has): the callback runs under the emitter's dispatch mutex, so a
// blocked writer delays subsequent progress events exactly like the
// JSON event writer does; the throttle below rejects every event
// before any I/O, so the cost is at most one small line per
// ~30 seconds. The emitter's deferred Stop joins the ticker goroutine
// on every exit path, so cancellation unwinds cleanly and no heartbeat
// outlives the run.
type periodicHumanHeartbeat struct {
	out      io.Writer
	started  time.Time
	last     time.Time
	now      func() time.Time
	interval time.Duration
	// inPlace renders the status on one terminal line (carriage return +
	// clear-to-end-of-line) instead of appending a new line per update.
	inPlace  bool
	lineOpen bool
	lineLen  int
}

func newPeriodicHumanHeartbeat(out io.Writer, started time.Time, now func() time.Time) *periodicHumanHeartbeat {
	return &periodicHumanHeartbeat{out: out, started: started, now: now, interval: periodicHumanHeartbeatInterval}
}

// newPeriodicHumanHeartbeatFor wires the heartbeat for the real output
// stream. A terminal refreshes one in-place line every few seconds; a
// redirected stream (scheduled-task log, CI, pipe) prints only a
// low-frequency stall notice, because a log gains nothing from a
// repeated "still running" line every thirty seconds.
func newPeriodicHumanHeartbeatFor(out io.Writer, started time.Time, now func() time.Time, tty bool) *periodicHumanHeartbeat {
	if tty {
		return &periodicHumanHeartbeat{out: out, started: started, now: now, interval: 5 * time.Second, inPlace: true}
	}
	return &periodicHumanHeartbeat{out: out, started: started, now: now, interval: 10 * time.Minute}
}

// Close finishes an in-place status line so the caller's next output
// starts on a fresh line. It is safe to call when nothing was rendered.
func (h *periodicHumanHeartbeat) Close() {
	if h == nil || !h.lineOpen {
		return
	}
	fmt.Fprint(h.out, "\n")
	h.lineOpen = false
}

// handle is the progress callback: every non-heartbeat event is
// dropped (they are machine events; the default output stays one
// line), and heartbeat events render at most once per interval. It
// performs no I/O until the throttle passes.
func (h *periodicHumanHeartbeat) handle(event collection.ProgressEvent) {
	if event.Kind != collection.ProgressHeartbeat {
		return
	}
	now := h.now()
	if now.Sub(h.started) < h.interval {
		return
	}
	if !h.last.IsZero() && now.Sub(h.last) < h.interval {
		return
	}
	h.last = now
	h.render(event, now)
}

// render writes one heartbeat line from the event's closed fields,
// honoring every observation gate (an uncounted queue never reads as a
// zero pending). The write goes through WriteProgressLine when the
// stream supports it, so an interactive prompt left open on the line
// is completed first and the heartbeat never shares a line.
func (h *periodicHumanHeartbeat) render(event collection.ProgressEvent, now time.Time) {
	var b strings.Builder
	if h.inPlace {
		fmt.Fprintf(&b, "Still running: %s elapsed", formatDurationWords(now.Sub(h.started)))
	} else {
		fmt.Fprintf(&b, "[%s] Still running: %s elapsed", now.Format("2006-01-02 15:04:05"), formatDurationWords(now.Sub(h.started)))
	}
	if event.Stage != "" {
		fmt.Fprintf(&b, ", %s", heartbeatStagePhrase(event.Stage))
	}
	if event.AttemptInFlightKnown {
		if event.AttemptInFlight {
			b.WriteString(", uploading a batch")
		} else {
			b.WriteString(", between uploads")
		}
	}
	if event.Counted {
		fmt.Fprintf(&b, ", %s pending", pluralBatches(event.PendingBatches))
		if event.RecordsCounted {
			fmt.Fprintf(&b, " (%s)", pluralRecords(event.PendingRecords))
		}
	} else {
		b.WriteString(", pending unknown")
	}
	if h.inPlace {
		// One terminal line: rewrite it in place. The timestamp is
		// omitted (the line is continuously visible) and the previous
		// longer line is cleared so no stale tail remains.
		text := b.String()
		fmt.Fprintf(h.out, "\r\x1b[K%s", text)
		h.lineOpen = true
		h.lineLen = len(text)
		return
	}
	b.WriteString(".\n")
	line := []byte(b.String())
	if lp, ok := h.out.(interface {
		WriteProgressLine([]byte) (int, error)
	}); ok {
		_, _ = lp.WriteProgressLine(line)
		return
	}
	_, _ = h.out.Write(line)
}

// heartbeatStagePhrase maps the closed progress-stage vocabulary onto
// natural English for the human heartbeat line. A value outside the
// known set (contaminated state, a future stage) collapses to the
// fixed "working" and is never echoed raw.
func heartbeatStagePhrase(stage string) string {
	switch stage {
	case "grant_sync":
		return "syncing the server grant scope"
	case "source_scan":
		return "scanning the granted sources"
	case "cursor_sync":
		return "collecting the account source"
	case "drain":
		return "uploading pending batches"
	case "history":
		return "retransmitting history"
	case "complete":
		return "finishing"
	default:
		return "working"
	}
}

// formatDurationWords renders a duration for the human heartbeat line.
func formatDurationWords(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	mins := secs / 60
	secs %= 60
	return fmt.Sprintf("%dm%02ds", mins, secs)
}

// grantFaultCount counts the granted sources whose structured skip
// code is a fault (the input no longer reads, or the export failed) —
// the §6.5/F1 incompleteness signal. It reads only GrantOutcome.Fault,
// never the skip message text.
func grantFaultCount(result collection.Result) int {
	count := 0
	for _, outcome := range result.GrantOutcomes {
		if outcome.Fault() {
			count++
		}
	}
	return count
}

// periodicCursorIncomplete judges the account cursor round of a
// successful (nil-error) periodic run against plan §6.5 — partial
// completion must never read as success — using ONLY the structured
// cursorsync round outcome (never the human-readable Skipped/Note text,
// which stays a display surface):
//
//   - RoundError (an actual failure: pull, upload/retry exhaustion,
//     credential, hard license/server errors, a rejected receipt) and
//     RoundFenceStop (an authorization or fence drift, with or without
//     partial uploads) are incomplete;
//   - RoundPaused is incomplete only while batches remain queued: paused
//     with nothing pending keeps the historical exit zero (a state, not
//     a partial run);
//   - RoundRan, RoundBounded (an explicit per-run batch bound — the
//     legacy --max-batches bounded-pending compatibility), RoundNoPermit
//     and RoundAuthWithheld (the authorization withholds the account
//     source before any work ran) are complete exits;
//   - a round that skipped usage events without a stable upstream id
//     dropped data and is incomplete whatever its outcome.
func periodicCursorIncomplete(cursor cursorsync.Result) (reason string, incomplete bool) {
	switch cursor.Outcome {
	case cursorsync.RoundError:
		return "failed: " + cursorDiagnostic(cursor), true
	case cursorsync.RoundFenceStop:
		return "stopped by an authorization or source-state change: " + cursorDiagnostic(cursor), true
	case cursorsync.RoundPaused:
		if cursor.PendingRemaining > 0 {
			return fmt.Sprintf("is paused with %d batch(es) still pending", cursor.PendingRemaining), true
		}
	}
	if cursor.SkippedNoStableID > 0 {
		return fmt.Sprintf("skipped %d usage event(s) without a stable upstream id (those events are not counted)", cursor.SkippedNoStableID), true
	}
	return "", false
}

// cursorDiagnostic renders the cursor round's own diagnostic — the skip
// reason, else the first note segment — for the incomplete reason line.
// It is display only: the classification in periodicCursorIncomplete
// never reads it.
func cursorDiagnostic(cursor cursorsync.Result) string {
	if cursor.Skipped != "" {
		return cursor.Skipped
	}
	if note := cursor.Note; note != "" {
		if idx := strings.Index(note, "; "); idx >= 0 {
			return note[:idx]
		}
		return note
	}
	return "the round did not complete"
}

// periodicCursorOptions is the production wiring of the periodic cursor
// phase (desktop credential reader + pinned-host Cursor API client). It
// is a variable solely so the CLI integration tests can inject synthetic
// auth/verify/pull providers; production always uses cursorSyncOptions
// and never reads a real credential during flag wiring.
var periodicCursorOptions = cursorSyncOptions

// periodicUploadPlan decides the §6.2 shared POST budget and the drain
// shape from the explicitly passed periodic flags. now is the budget's
// clock (production: time.Now; tests inject a controllable one) and
// fixes the default profile's deadline origin. The rules:
//
//   - an explicit --max-batches WITHOUT a positive --max-total-batches
//     keeps the historical unbudgeted behavior: no shared budget exists,
//     so the per-queue bound is never truncated by a default total, and
//     the drain keeps the historical bounded shape (fair=false);
//   - an explicit positive --max-total-batches arms the shared total and
//     the fair rotation in both shapes (with --max-batches each queue
//     additionally keeps its own bound, enforced by the rotation's
//     steppers rather than by a budget queue cap so a per-queue bound
//     stays a normal exit-zero bounded stop, never a budget decline);
//   - with neither bound given (the default profile) the run gets
//     collection.DefaultSharedPOSTBudget shared POSTs inside a deadline
//     of exactly the effective --sync-timeout window — 2 minutes by
//     default, and the user's explicit value (5m, 30s, ...) whenever
//     --sync-timeout is passed, so the window is never stuck at the
//     default when the user asked for a different run length.
func periodicUploadPlan(now func() time.Time, maxBatchesExplicit bool, maxTotalBatches int, syncTimeout time.Duration) (budget *syncbudget.Budget, fair bool) {
	if maxBatchesExplicit && maxTotalBatches <= 0 {
		return nil, false
	}
	if maxTotalBatches > 0 {
		return syncbudget.New(syncbudget.WithTotal(maxTotalBatches)), true
	}
	return syncbudget.New(
		syncbudget.WithTotal(collection.DefaultSharedPOSTBudget),
		syncbudget.WithDeadline(now().Add(syncTimeout)),
		syncbudget.WithNow(now),
	), true
}

// isSyncBudgetDecline reports whether a periodic failure is a shared
// upload-budget decline (internal/syncbudget): the attempt was stopped
// before its ingest POST, so the batch stays pending and the next run
// resumes it. A run-context timeout is deliberately NOT a budget decline.
func isSyncBudgetDecline(err error) bool {
	return err != nil && (errors.Is(err, syncbudget.ErrTotalExhausted) ||
		errors.Is(err, syncbudget.ErrQueueExhausted) ||
		errors.Is(err, syncbudget.ErrDeadlineExceeded))
}

// printPeriodicResult renders the periodic run's DETAILED summary for
// --verbose through the synced counters and closed status codes. It is
// the sanitized successor of the historical log: input paths, the
// grantSync free-text note, the cursor round's free-text note and
// untrusted skip diagnostics are never printed (an unclassified
// diagnostic is named as withheld, never guessed); the closed
// GrantSkipCode / RoundOutcome vocabularies and the observation gates
// carry the same information without raw fields. A run whose Skipped
// reason means nothing was attempted (no grants, server pause) prints
// only that state's fixed wording.
func printPeriodicResult(human io.Writer, result collection.Result) {
	if result.GrantSync.Active {
		fmt.Fprintf(human, "grantSync: revision=%d paused=%t refreshed=%t acked=%t allowedTools=%s\n",
			result.GrantSync.ConsentRevision, result.GrantSync.Paused, result.GrantSync.Refreshed, result.GrantSync.Acked, toolListDisplaySafe(result.GrantSync.AllowedTools))
		for _, added := range result.GrantSync.AddedGrants {
			// The added-grant entry is "source input": the input is a
			// local path, so only the registry-shaped source name is
			// shown.
			source := strings.Fields(added)
			name := "unknown"
			if len(source) > 0 {
				name = canonicalToolDisplay(source[0])
			}
			fmt.Fprintf(human, "grantSync: added managed grant %s (input path withheld)\n", name)
		}
		// The pending restrictions: per tool only the canonical
		// registry name plus a withheld marker (the raw reason is free
		// text that may embed local paths); the closed reason counts
		// come from the same redaction walk the §6.5 JSON uses.
		for _, tool := range sortedPendingTools(result.GrantSync.Pending) {
			fmt.Fprintf(human, "grantSync: pending %s (restriction details withheld)\n", tool)
		}
		if scope := collection.SummarizePhases(result).Scope; scope.PendingTools > 0 {
			fmt.Fprintf(human, "grantSync: pendingRestrictions unsupported=%d disabled=%d missingInput=%d unclassified=%d\n",
				scope.PendingUnsupported, scope.PendingDisabled, scope.PendingMissingInput, scope.PendingUnmapped)
		}
		if result.GrantSync.Note != "" {
			fmt.Fprintf(human, "grantSync: note present (details withheld)\n")
		}
	}
	if result.Cursor.Ran {
		printCursorSyncVerbose(human, result.Cursor)
	}
	if result.Cursor.Skipped != "" {
		// Triggered by the skip FACT alone (a no-permit round never
		// loaded the permit, so Status stays empty): the closed-set
		// phrase keyed off the outcome prints, never the raw text.
		fmt.Fprintf(human, "cursor sync: %s\n", cursorSkippedDisplay(result.Cursor))
	}
	// §6.5: name the account round's structured outcome explicitly so a
	// non-clean round — notably a paused one that keeps the historical
	// exit zero with nothing pending — never reads as a silent success.
	// Only the closed RoundOutcome vocabulary prints; a value outside it
	// (persisted-state contamination) reads as unknown, never raw.
	if o := result.Cursor.Outcome; o != cursorsync.RoundAbsent && o != cursorsync.RoundRan {
		if !knownCursorRoundOutcome(o) {
			o = "unknown"
		}
		cursorPending := "unknown"
		if result.Cursor.PendingCounted {
			cursorPending = strconv.Itoa(result.Cursor.PendingRemaining)
		}
		fmt.Fprintf(human, "cursor sync: outcome=%s pending=%s\n", o, cursorPending)
	}
	if result.Skipped != "" && result.NoGrants {
		fmt.Fprintf(human, "%s\n", periodicRunSkippedDisplay(result))
		return
	}
	if result.Skipped != "" && !result.NoGrants && len(result.GrantOutcomes) == 0 {
		fmt.Fprintf(human, "%s\n", periodicRunSkippedDisplay(result))
		return
	}
	for i, outcome := range result.GrantOutcomes {
		source := canonicalToolDisplay(outcome.Source)
		switch {
		case outcome.Skipped != "":
			fmt.Fprintf(human, "grant %s: skipped (%s)\n", source, grantSkipDisplay(outcome))
		case !outcome.Exported:
			fmt.Fprintf(human, "grant %s: no new records\n", source)
		default:
			// The batch id read from persisted state could carry
			// arbitrary text (a ticket, a token — even a plain
			// alphanumeric one defeats charset checks), so no mode
			// echoes it: the per-run ORDINAL identifies the line
			// without identifying the stored id.
			fmt.Fprintf(human, "grant %s: exported batch #%d records=%d\n", source, i+1, outcome.Records)
		}
	}
	fmt.Fprintf(human, "exportedBatches=%d exportedRecords=%d\n", result.ExportedBatches, result.ExportedRecords)
	fmt.Fprintf(human, "syncedBatches=%d syncedRecords=%d\n", result.SyncedBatches, result.SyncedRecords)
}

// printCursorSyncVerbose renders the account round's detailed lines
// from closed counts only — the successor of the shared
// printCursorSyncResult with the free-text note withheld (the note may
// embed raw upload error text). pendingRemaining prints its raw
// historical number; the observation gate is carried by the outcome
// line and the §6.5 summary.
func printCursorSyncVerbose(w io.Writer, res cursorsync.Result) {
	fmt.Fprintf(w, "cursor sync: pulledEvents=%d new=%d replaced=%d unchanged=%d noStableId=%d\n",
		res.PulledEvents, res.NewRecords, res.ReplacedRecords, res.SkippedUnchanged, res.SkippedNoStableID)
	// pendingRemaining honors its observation gate: an uncounted queue
	// never reads as a zero.
	pending := "unknown"
	if res.PendingCounted {
		pending = strconv.Itoa(res.PendingRemaining)
	}
	fmt.Fprintf(w, "cursor sync: exportedBatches=%d syncedBatches=%d syncedRecords=%d pendingRemaining=%s\n",
		res.ExportedBatches, res.SyncedBatches, res.SyncedRecords, pending)
	if res.FirstSyncCompleted {
		fmt.Fprintf(w, "cursor sync: first usage pull persisted; local permit active (upload confirmation is shown in syncedRecords/pendingRemaining)\n")
	}
	if res.Note != "" {
		fmt.Fprintf(w, "cursor sync: note present (details withheld)\n")
	}
}

// cursorSkippedDisplay renders the cursor round's skip state as a
// fixed short English phrase keyed ONLY off the closed RoundOutcome
// vocabulary — never the free-text Skipped diagnostic (which may echo
// an arbitrary persisted string through the permit-status fallback, or
// raw error text), and never with reconnect/resync guidance: the line
// states what happened, not what the operator should re-run.
func cursorSkippedDisplay(res cursorsync.Result) string {
	switch res.Outcome {
	case cursorsync.RoundError:
		return "failed (raw diagnostics withheld)"
	case cursorsync.RoundFenceStop:
		return "stopped by an authorization or source-state change"
	case cursorsync.RoundPaused:
		return "paused"
	case cursorsync.RoundBounded:
		return "stopped at the batch limit"
	case cursorsync.RoundNoPermit:
		return "no local permit"
	case cursorsync.RoundAuthWithheld:
		return "withheld by the current authorization"
	default:
		return "skipped (details withheld)"
	}
}

// knownCursorRoundOutcome reports whether the outcome value belongs to
// the closed RoundOutcome vocabulary this build knows; anything else
// renders as "unknown" rather than echoing the raw string.
func knownCursorRoundOutcome(o cursorsync.RoundOutcome) bool {
	switch o {
	case cursorsync.RoundError, cursorsync.RoundFenceStop, cursorsync.RoundPaused,
		cursorsync.RoundBounded, cursorsync.RoundNoPermit, cursorsync.RoundAuthWithheld:
		return true
	}
	return false
}

// toolListDisplaySafe renders the applied allowed-tools scope as
// canonical registry names only: the raw list is server-provided free
// text, so an unknown or hostile name never echoes (it collapses to
// "unknown"; the §6.5 JSON counts those separately).
func toolListDisplaySafe(tools []string) string {
	if len(tools) == 0 {
		return "(unrestricted)"
	}
	parts := make([]string, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, canonicalToolDisplay(tool))
	}
	return strings.Join(parts, ",")
}

// canonicalToolDisplay renders a grant or tool name as its
// operator-facing canonical TOOL name through the compiled-in
// registry: a tool name (grant-sync pending keys, allowedTools)
// matches directly; a source identifier (grant outcomes, added grants)
// maps onto its tool's display name via the supported-tool list — the
// internal source id (e.g. a "codex-jsonl" style identifier) never
// reaches the display. An unknown or hostile name is never echoed
// (the JSON contract only counts those).
func canonicalToolDisplay(name string) string {
	if spec, known := registry.LookupTool(name); known {
		return spec.Tool
	}
	for _, spec := range registry.SupportedTools() {
		if spec.Source == name {
			return spec.Tool
		}
	}
	return "unknown"
}

// sortedPendingTools lists the pending map's keys as canonical registry
// names (an unknown name renders as "unknown"), sorted for stable
// output. The raw reason values never enter the display.
func sortedPendingTools(pending map[string]string) []string {
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, canonicalToolDisplay(k))
	}
	sort.Strings(keys)
	return keys
}

// grantSkipDisplay renders one granted source's skip reason from its
// closed GrantSkipCode — fixed wording keyed off structure, never the
// free-text Skipped message (which may embed local paths or raw error
// text).
func grantSkipDisplay(outcome collection.GrantOutcome) string {
	switch outcome.Code {
	case collection.GrantNotAllowed:
		return "source not allowed by the server grant scope for this device"
	case collection.GrantInputInaccessible:
		return "input not accessible (details withheld)"
	case collection.GrantExportFailed:
		return "export preparation failed (details withheld)"
	case collection.GrantSplitFailed:
		return "export split failed (details withheld)"
	case collection.GrantNoNewRecords:
		return "no new records since the last confirmed baselines"
	default:
		return "unclassified (details withheld)"
	}
}

// periodicRunSkippedDisplay renders the run-level no-op state from
// structure: the two historical shapes (no enabled grants, a server
// pause) keep their authored wording; any other skipped reason is
// never echoed raw.
func periodicRunSkippedDisplay(result collection.Result) string {
	switch {
	case result.NoGrants:
		return "no enabled source grants; nothing to collect (sources enable requires explicit --source and --input)"
	case result.GrantSync.Paused:
		return fmt.Sprintf("server reports collection paused for this device (consent revision %d); no local reading or uploads this run", result.GrantSync.ConsentRevision)
	default:
		return "run skipped (reason withheld)"
	}
}

// emitResultJSON writes exactly one JSON object (newline-terminated) to
// the machine stream: the --json result contract. It is called on
// EVERY exit path of a --json run, including errors, so a consumer
// always gets one parseable verdict.
func emitResultJSON(w io.Writer, summary any) {
	b, err := json.Marshal(summary)
	if err != nil {
		// The summary types are marshalable by construction; this is the
		// never-happens net so the stream still receives exactly one
		// object.
		fmt.Fprintln(w, `{"schema":1,"command":"unknown","stop_reason":"fatal_error"}`)
		return
	}
	fmt.Fprintln(w, string(b))
}

// jsonWantsEmission decides whether a --json run whose flag parsing
// FAILED still owes the result object:
//
//   - a successfully parsed --json wins outright: fs.Visit reports only
//     the flags the user actually passed before the failure, and the
//     parsed value already reflects the last valid assignment (an
//     explicit --json=false stays disabled);
//   - when parsing stopped before reaching --json (the failing flag
//     came first), the raw arguments are scanned with the flag
//     package's own value semantics below.
//
// No argument text is ever echoed or logged.
func jsonWantsEmission(fs *flag.FlagSet, jsonOut bool, args []string) bool {
	parsed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" {
			parsed = true
		}
	})
	if parsed {
		return jsonOut
	}
	return scanArgsWantsJSON(fs, args)
}

// scanArgsWantsJSON reports whether the raw argument list enables the
// --json switch, mirroring the flag package's own parsing semantics:
//
//   - only the leading flag portion is scanned — parsing stops at the
//     first non-flag argument (a positional URL) and at "--", so an
//     argument that merely contains "json" (a URL, another flag's
//     value) never triggers it;
//   - a bare --json/-json enables it; --json=<v> follows
//     strconv.ParseBool, so --json=false, --json=0 and --json=F stay
//     disabled while --json, --json=1, --json=t and --json=TRUE enable;
//   - a KNOWN value-taking flag (--state-dir /tmp/x) consumes its next
//     argument, which is skipped so it is never mistaken for a
//     positional terminator or for the switch;
//   - with multiple assignments the LAST valid boolean wins; an
//     unparseable value leaves the previous assignment standing.
func scanArgsWantsJSON(fs *flag.FlagSet, args []string) bool {
	enabled := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			// The flag portion ends: a positional argument (or the
			// explicit terminator) ends flag parsing.
			break
		}
		name := arg
		if strings.HasPrefix(name, "--") {
			name = name[2:]
		} else {
			name = name[1:]
		}
		flagName, value, hasValue := strings.Cut(name, "=")
		if flagName == "json" {
			if !hasValue {
				enabled = true
			} else if v, err := strconv.ParseBool(value); err == nil {
				enabled = v
			}
			continue
		}
		if hasValue {
			// A self-contained assignment to another flag.
			continue
		}
		// A known value-taking flag consumes the next argument: skip it
		// so it is never mistaken for the switch or a positional.
		if f := fs.Lookup(flagName); f != nil && !isBoolFlagValue(f) && i+1 < len(args) {
			i++
		}
	}
	return enabled
}

// isBoolFlagValue reports whether the flag's value is a boolean (the
// flag package's own marker: bool flags do not consume a following
// argument).
func isBoolFlagValue(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// elapsedMS measures a command's wall-clock duration for the result
// contract.
func elapsedMS(started time.Time) int64 {
	return time.Since(started).Milliseconds()
}

func writeCollectionProgressJSON(out io.Writer) func(collection.ProgressEvent) {
	return func(event collection.ProgressEvent) {
		payload := map[string]any{
			"type":   "collection_progress",
			"kind":   event.Kind,
			"stage":  event.Stage,
			"source": event.Source,
		}
		switch event.Kind {
		case collection.ProgressBatch, collection.ProgressQueue, collection.ProgressHeartbeat:
			appendProgressEventKeys(payload, event)
		default:
			// The historical stage/count key set, byte-identical to the
			// pre-extension writer.
			payload["input"] = event.Input
			payload["startedAt"] = event.StartedAt.Format(time.RFC3339Nano)
			payload["endedAt"] = event.EndedAt.Format(time.RFC3339Nano)
			payload["durationMs"] = event.Duration.Milliseconds()
			payload["error"] = event.Err
			payload["exportedBatches"] = event.ExportedBatches
			payload["exportedRecords"] = event.ExportedRecords
			payload["syncedBatches"] = event.SyncedBatches
			payload["syncedRecords"] = event.SyncedRecords
			payload["pendingRemaining"] = event.PendingRemaining
		}
		b, err := json.Marshal(payload)
		if err != nil {
			fmt.Fprintf(out, "{\"type\":\"collection_progress\",\"error\":%q}\n", err.Error())
			return
		}
		b = append(b, '\n')
		if lp, ok := out.(interface {
			WriteProgressLine([]byte) (int, error)
		}); ok {
			// The shared stderr sink completes any open human line
			// (an interactive prompt) before the event, keeping every
			// progress line per-line parseable.
			_, _ = lp.WriteProgressLine(b)
			return
		}
		_, _ = out.Write(b)
	}
}

// appendProgressEventKeys adds the batch/queue/heartbeat keys. Every
// gated field is emitted ONLY when its gate is set — an unmeasured
// duration, an unknown payload size or an unseen receipt never appears
// as a zero value.
func appendProgressEventKeys(payload map[string]any, event collection.ProgressEvent) {
	if event.Queue != "" {
		payload["queue"] = event.Queue
	}
	switch event.Kind {
	case collection.ProgressBatch:
		payload["attempt"] = event.Attempt
		if event.Phase != "" {
			payload["phase"] = event.Phase
		}
		if event.AttemptStage != "" {
			payload["attemptStage"] = event.AttemptStage
		}
		if event.Result != "" {
			payload["result"] = event.Result
		}
		if event.PrepareMeasured {
			payload["prepareMs"] = event.Prepare.Milliseconds()
		}
		if event.SelfCheckMeasured {
			payload["selfCheckMs"] = event.SelfCheck.Milliseconds()
		}
		if event.HTTPMeasured {
			payload["httpMs"] = event.HTTP.Milliseconds()
		}
		if event.ACKMeasured {
			payload["ackMs"] = event.ACK.Milliseconds()
		}
		if event.InterAttemptMeasured {
			payload["interAttemptMs"] = event.InterAttempt.Milliseconds()
		}
		if event.DurationKnown {
			payload["durationMs"] = event.Duration.Milliseconds()
		}
		if event.PayloadBytesKnown {
			payload["payloadBytes"] = event.PayloadBytes
		}
		if event.ReceiptObserved {
			payload["acceptedRecords"] = event.AcceptedRecords
			payload["rejectedRecords"] = event.RejectedRecords
			payload["batchReplay"] = event.BatchReplay
		}
		if event.FirstBatchConfirmation != "" {
			payload["firstBatchConfirmation"] = event.FirstBatchConfirmation
		}
		if event.Origin != "" {
			payload["origin"] = event.Origin
		}
	case collection.ProgressQueue:
		payload["counted"] = event.Counted
		if event.Counted {
			// Only a really read ledger may state a batch count — an
			// unread queue is never presented as an observed zero.
			payload["pendingBatches"] = event.PendingBatches
		}
		payload["recordsCounted"] = event.RecordsCounted
		if event.RecordsCounted {
			payload["pendingRecords"] = event.PendingRecords
		}
		if event.BytesCounted {
			payload["pendingBytes"] = event.PendingBytes
		}
		if event.AgeCounted {
			payload["oldestPendingAgeMs"] = event.OldestPendingAge.Milliseconds()
		}
	case collection.ProgressHeartbeat:
		payload["durationMs"] = event.Duration.Milliseconds()
		if event.AttemptInFlightKnown {
			payload["attemptInFlight"] = event.AttemptInFlight
			if event.AttemptInFlight {
				payload["attemptElapsedMs"] = event.AttemptElapsed.Milliseconds()
			}
		}
		payload["counted"] = event.Counted
		if event.Counted {
			// Same honesty rule as the queue events: an uncounted
			// aggregate is never presented as an observed zero.
			payload["pendingBatches"] = event.PendingBatches
		}
		payload["recordsCounted"] = event.RecordsCounted
		if event.RecordsCounted {
			payload["pendingRecords"] = event.PendingRecords
		}
		if event.BytesCounted {
			payload["pendingBytes"] = event.PendingBytes
		}
		if event.AgeCounted {
			payload["oldestPendingAgeMs"] = event.OldestPendingAge.Milliseconds()
		}
		payload["firstBatchConfirmedBatches"] = event.FirstBatchConfirmedBatches
		payload["samples"] = event.Samples
		if event.RateKnown {
			payload["processingRateRecPerSec"] = event.ProcessingRateRecPerSec
		}
		if event.EtaKnown {
			payload["etaMs"] = event.Eta.Milliseconds()
		}
	}
}

// serializedWriter serializes every Write behind one mutex, so human
// text, interactive prompts and progress JSONL lines that share one
// stream (stderr under --json) never interleave mid-line and concurrent
// writers stay race-free. Progress events are ALWAYS written to stderr
// and never to stdout: stdout stays exactly one JSON object under
// --json and human-only otherwise. The stream itself is MIXED when
// --json and --progress-json are combined — consumers filter per line
// by parsing for the top-level "type":"collection_progress"
// discriminator; human and prompt lines never carry it.
type serializedWriter struct {
	mu sync.Mutex
	w  io.Writer
	// lineComplete reports whether the stream currently ends on a line
	// boundary. An interactive prompt like "[y/N] " deliberately writes
	// no trailing newline; a progress event arriving after it must first
	// complete that line, or the event would share the prompt's line and
	// stop being per-line parseable.
	lineComplete bool
}

func newSerializedWriter(w io.Writer) *serializedWriter {
	return &serializedWriter{w: w, lineComplete: true}
}

func (s *serializedWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if len(p) > 0 && p[len(p)-1] == '\n' {
		s.lineComplete = true
	} else if len(p) > 0 {
		s.lineComplete = false
	}
	return n, err
}

// WriteProgressLine writes one complete progress JSONL line atomically:
// when the preceding human write left the line open (an interactive
// prompt without a newline), it first completes that line so the prompt
// stays visible and inputtable on its own line and every event occupies
// its own parseable line. Progress mode only — human output is never
// modified.
func (s *serializedWriter) WriteProgressLine(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lineComplete {
		if _, err := s.w.Write([]byte("\n")); err != nil {
			return 0, err
		}
		s.lineComplete = true
	}
	n, err := s.w.Write(p)
	if len(p) > 0 && p[len(p)-1] == '\n' {
		s.lineComplete = true
	} else if len(p) > 0 {
		s.lineComplete = false
	}
	return n, err
}

func toolListDisplay(tools []string) string {
	if len(tools) == 0 {
		return "(unrestricted)"
	}
	parts := make([]string, 0, len(tools))
	parts = append(parts, tools...)
	return strings.Join(parts, ",")
}

func sortedPendingDisplay(pending map[string]string) []string {
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+": "+pending[k])
	}
	return out
}

// ---------------------------------------------------------------------------
// sources / plugins: adapter visibility and enablement for scheduled
// collection. Manual scan/preview/export keep their explicit
// --source/--input semantics and are unaffected by this config.
// ---------------------------------------------------------------------------

func runSources(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail sources <list|enable|disable>")
		return flag.ErrHelp
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		return runSourcesList(rest)
	case "enable":
		return runSourcesEnable(rest)
	case "disable":
		return runSourcesDisable(rest)
	}
	fmt.Fprintf(os.Stderr, "unknown sources subcommand %q; try help\n", sub)
	os.Exit(2)
	return nil
}

func runSourcesList(args []string) error {
	fs := flag.NewFlagSet("sources list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	store := grants.New(dir)
	config, err := store.Load()
	if err != nil {
		return err
	}
	enabled := make(map[string]bool)
	for _, grant := range config.Grants {
		if grant.Enabled {
			enabled[grant.Source+"\x00"+grant.Input] = true
		}
	}
	for _, source := range grants.KnownSources() {
		fmt.Printf("source %s\n", source)
	}
	for _, grant := range config.Grants {
		status := "disabled"
		if grant.Enabled {
			status = "enabled"
		}
		fmt.Printf("grant %s %s %s\n", grant.Source, grant.Input, status)
	}
	fmt.Printf("state=%s\n", store.Path())
	_ = enabled
	return nil
}

func runSourcesEnable(args []string) error {
	fs := flag.NewFlagSet("sources enable", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "adapter source (usage-json, codex-jsonl, claude-code-jsonl, deepseek-harness, workbuddy-jsonl, qwen-jsonl, kimi-cli-jsonl, kimi-code-jsonl, zcode-sqlite, hermes-sqlite, openclaw-sqlite, pi-jsonl, omp-jsonl, codebuddy-history, opencode-sqlite)")
	input := fs.String("input", "", "absolute local input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *input == "" {
		return fmt.Errorf("sources enable requires explicit --source and --input (no default scanning)")
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	grant, err := grants.New(dir).Enable(*source, *input)
	if err != nil {
		return err
	}
	fmt.Printf("enabled grant %s %s\n", grant.Source, grant.Input)
	fmt.Printf("state=%s\n", grants.New(dir).Path())
	return nil
}

func runSourcesDisable(args []string) error {
	fs := flag.NewFlagSet("sources disable", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "adapter source")
	input := fs.String("input", "", "local input path")
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *input == "" {
		return fmt.Errorf("sources disable requires explicit --source and --input")
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	grant, found, err := grants.New(dir).Disable(*source, *input)
	if err != nil {
		return err
	}
	if !found {
		fmt.Printf("no grant for %s %s\n", *source, *input)
		return nil
	}
	fmt.Printf("disabled grant %s %s\n", grant.Source, grant.Input)
	fmt.Printf("state=%s\n", grants.New(dir).Path())
	return nil
}

func runPlugins(args []string) error {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail plugins")
		return flag.ErrHelp
	}
	// Plugins are compiled into the binary (no runtime plugin loading, no
	// unvetted code paths); this lists the built-in adapters and their
	// inputs so users can see what exists before granting anything.
	for _, plugin := range registry.All() {
		fmt.Printf("plugin %s %s\n", plugin.Source, plugin.Description)
	}
	fmt.Printf("note=plugins are compiled in; enable a grant with: toktrail sources enable --source <s> --input <path>\n")
	return nil
}

// ---------------------------------------------------------------------------
// service: install/uninstall the per-user scheduled collection task.
// Installing never binds a device, never scans, and never runs a
// collection; only the grants given explicitly with --grant are stored.
// ---------------------------------------------------------------------------

func runService(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: toktrail service <install|refresh|uninstall> [flags]")
		return flag.ErrHelp
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "install":
		return runServiceInstall(rest)
	case "refresh":
		return runServiceRefresh(rest)
	case "uninstall":
		return runServiceUninstall(rest)
	}
	fmt.Fprintf(os.Stderr, "unknown service subcommand %q; try help\n", sub)
	os.Exit(2)
	return nil
}

func parseGrant(arg string) (source, input string, err error) {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid grant %q; expected --grant <source>=<absolute-input-path>", arg)
	}
	return parts[0], parts[1], nil
}

func runServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	dryRun := fs.Bool("dry-run", false, "print the rendered scheduler plan without changing anything")
	interval := fs.Duration("interval", scheduler.DefaultInterval, "scheduling interval (minimum 1m)")
	grantSpecs := multiFlag{}
	fs.Var(&grantSpecs, "grant", "explicit source grant for scheduled collection: <source>=<absolute-input-path>; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	if len(grantSpecs) == 0 {
		return fmt.Errorf("service install requires at least one explicit --grant <source>=<input>; scheduled collection never scans by default")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Validate and persist grants BEFORE touching any scheduler file, so
	// a bad grant cannot leave a half-configured task behind. The state
	// process lock serializes this against concurrent commands.
	stateLock, err := runlock.Acquire(dir)
	if err != nil {
		return err
	}
	defer stateLock.Close()
	store := grants.New(dir)
	for _, grantArg := range grantSpecs {
		source, input, err := parseGrant(grantArg)
		if err != nil {
			return err
		}
		if _, err := store.Enable(source, input); err != nil {
			return err
		}
	}
	plan, err := scheduler.Install(scheduler.InstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: dir,
			Binary:   binary,
			Interval: *interval,
			HomeDir:  home,
		},
		DryRun: *dryRun,
		Out:    os.Stdout,
	})
	if err != nil {
		return err
	}
	identity, _ := scheduler.TaskIdentity(dir)
	fmt.Printf("service=%s interval=%s\n", identity, *interval)
	fmt.Printf("scheduled command: %s periodic --state-dir %s\n", binary, plan.Marker)
	fmt.Printf("note=installing the service does not bind, scan, or collect; the first run happens after the first interval elapses\n")
	return nil
}

func runServiceUninstall(args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	dryRun := fs.Bool("dry-run", false, "print the uninstall plan without changing anything")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Uninstall does not execute the binary, but the shared task-config
	// validation requires an absolute path so the rendered identity is
	// unambiguous; resolve the current executable like install does.
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	if _, err := scheduler.Uninstall(scheduler.UninstallOptions{
		Config: scheduler.TaskConfig{
			Platform: runtime.GOOS,
			StateDir: dir,
			Binary:   binary,
			Interval: scheduler.DefaultInterval,
			HomeDir:  home,
		},
		DryRun: *dryRun,
		Out:    os.Stdout,
	}); err != nil {
		return err
	}
	identity, _ := scheduler.TaskIdentity(dir)
	fmt.Printf("service=%s removed\n", identity)
	fmt.Printf("note=source grants and local state are kept; remove them manually if desired\n")
	return nil
}

// multiFlag collects repeatable string flags (--grant a=b --grant c=d).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// ---------------------------------------------------------------------------
// privacy / doctor
// ---------------------------------------------------------------------------

func runPrivacy(args []string) error {
	fs := flag.NewFlagSet("privacy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	source := fs.String("source", "", "narrow the report to one adapter source (with --input)")
	input := fs.String("input", "", "narrow the report to one input path (with --source)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	reports, err := diagnostic.Privacy(diagnostic.PrivacyOptions{
		StateDir: dir,
		Source:   *source,
		Input:    *input,
	})
	if err != nil {
		return err
	}
	if len(reports) == 0 {
		fmt.Printf("no enabled source grants; nothing scanned (privacy performs no network access)\n")
		return nil
	}
	for _, report := range reports {
		fmt.Printf("source=%s input=%s\n", report.Source, report.Input)
		fmt.Printf("records=%d valid=%d invalid=%d quarantined=%d\n", report.RecordCount, report.ValidRecords, report.InvalidRecords, report.Quarantined)
		fmt.Printf("uploadSafeRecords=%d tokensInclude=%s tokensExclude=%s\n", report.UploadSafeRecords, formatOptionalUint(report.TokensInclude), formatOptionalUint(report.TokensExclude))
		if report.Earliest != nil && report.Latest != nil {
			fmt.Printf("range=%s..%s\n", report.Earliest.Format(time.RFC3339), report.Latest.Format(time.RFC3339))
		}
		for _, tool := range adapter.SortedTools(report.Tools) {
			fmt.Printf("tool[%s]=%d\n", tool, report.Tools[tool])
		}
		fmt.Printf("outboxPending=%d outboxPendingRecords=%d\n", report.OutboxPending, report.OutboxPendingRecords)
	}
	fmt.Printf("note=privacy is local-only; no network access was performed\n")
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", env("TOKTRAIL_HOME", ""), "local TokTrail state directory")
	checkServer := fs.Bool("check-server", false, "also check the server device status (the only networked check)")
	serverURL := fs.String("server", env("TOKTRAIL_SERVER_URL", ""), "toktrail-server base URL; defaults to bound server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		var err error
		dir, err = statedir.DefaultDir()
		if err != nil {
			return err
		}
	}
	binary := ""
	if executable, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(executable); err == nil {
			binary = abs
		}
	}
	home := ""
	if h, err := os.UserHomeDir(); err == nil {
		home = h
	}
	report, err := diagnostic.Doctor(diagnostic.DoctorOptions{
		StateDir:    dir,
		CheckServer: *checkServer,
		ServerURL:   *serverURL,
		Binary:      binary,
		HomeDir:     home,
		Version:     version,
	})
	if err != nil {
		return err
	}
	for _, check := range report.Checks {
		fmt.Printf("%s %s %s\n", check.Status, check.Name, check.Detail)
	}
	if report.Failed() {
		return fmt.Errorf("doctor found failing checks (see above)")
	}
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printHelp() {
	fmt.Println(`toktrail collector scaffold

Commands:
  version                    print collector version
  connect '<URL>' [--verbose]    one-step device setup via connect URL/ticket: fetches
                             server configuration, binds device, probes local tools,
                             configures source grants, installs scheduled service,
                             and runs initial collection; --json prints the stable
                             result (stop_reason + phase counts) as one JSON object
                             on stdout, with human output and prompts on stderr;
                             --verbose prints the detailed per-step log (counts and
                             closed status codes only; never credentials, URLs,
                             tickets or raw records)
  bind                       bind this device to toktrail-server using explicit upload authorization
  status                     check bound device authorization from toktrail-server
scan [--source usage-json|codex-jsonl|claude-code-jsonl|deepseek-harness|workbuddy-jsonl|qwen-jsonl|kimi-cli-jsonl|kimi-code-jsonl|zcode-sqlite|hermes-sqlite|openclaw-sqlite|pi-jsonl|omp-jsonl|codebuddy-history|opencode-sqlite] --input <path>
                            locally scan usage records without network/account access
preview [--source usage-json|codex-jsonl|claude-code-jsonl|deepseek-harness|workbuddy-jsonl|qwen-jsonl|kimi-cli-jsonl|kimi-code-jsonl|zcode-sqlite|hermes-sqlite|openclaw-sqlite|pi-jsonl|omp-jsonl|codebuddy-history|opencode-sqlite] --input <path>
                            preview local usage records
export [--source usage-json|codex-jsonl|claude-code-jsonl|deepseek-harness|workbuddy-jsonl|qwen-jsonl|kimi-cli-jsonl|kimi-code-jsonl|zcode-sqlite|hermes-sqlite|openclaw-sqlite|pi-jsonl|omp-jsonl|codebuddy-history|opencode-sqlite] --input <path> --out <batch.json>
                              export local records and add a pending outbox batch
  sync [--file <batch.json>]  preflight device authorization, then upload a local batch
                              (or the oldest pending outbox batch) with the current
                              consent revision; revoked/deleted devices stop sending

  resync --all [--dry-run] [--yes] [--max-batches N] [--verbose]
  resync --all --force-recollect [--expected-device ID] [--dry-run] [--yes]
                               clear ordinary device history, keep device identity,
                               and rebuild ALL authorized local tools; Cursor is
                               excluded. Force dry-run reads the remote plan and
                               local sources but never resets or uploads.
                              retransmit archived synced batches to the bound device;
                              dry-run is offline and read-only; execution confirms
                              live authorization and preserves collection progress;
                              --verbose prints the detailed per-batch log (counts
                              and closed status codes only; never credentials,
                              URLs, tickets or raw records)

Planned by the approved architecture:
  sources / plugins            adapter visibility and enablement
  service install|refresh|uninstall    platform scheduled sync
  privacy / doctor             consent and diagnostics

Scheduling and diagnostics (implemented):
  periodic [--state-dir <dir>] [--max-batches <n>] [--max-total-batches <n>] [--sync-timeout <dur>] [--drain-only] [--progress-json] [--verbose] [--json]
                               complete-exit scheduled run: collect the
                               enabled source grants only (no default
                               scanning), export via the WAL, then drain
                               pending batches with the existing
                               server-consent preflight; one process lock
                               covers the whole run. Default (no explicit
                               bounds): scan/pull once, then drain the
                               device and cursor queues in fair rotation
                               until exhausted, bounded by a shared budget
                               of 100 ingest POSTs within the
                               --sync-timeout window (2 minutes by
                               default; the budget deadline follows an
                               explicit --sync-timeout value). A budget
                               stop with work left exits non-zero
                               (incomplete). --max-batches keeps the
                               historical per-active-queue bound (never
                               truncated by the default total; without
                               --max-total-batches the run keeps the
                               unbudgeted legacy shape); --max-total-batches
                               caps the run's total POSTs across both
                               queues and keeps the fair rotation; both
                               bounds together each take effect;
                               --json prints the stable result
                               (stop_reason + phase counts) as one JSON
                               object on stdout, with human output on
                               stderr. By default the human output is
                               one concise English status line
                               (date-time, this run's server-confirmed
                               counts, observable pending; a provably
                               empty scan reads as "no new records";
                               real errors surface exactly once through
                               the command's dated failure line) and a
                               long run prints a human heartbeat
                               roughly every 30 seconds; --verbose
                               restores the detailed per-phase log
                               (counts and closed status codes only;
                               never credentials, URLs, tickets, raw
                               records, local paths or untrusted free
                               text)
  sources list                 show built-in sources and enabled grants
  sources enable --source <s> --input <path>
                               grant scheduled collection an explicit
                               source+input (manual scan/export semantics
                               are unchanged)
  sources disable --source <s> --input <path>
                               revoke that grant
  plugins                      list the compiled-in adapters
  service install --grant <source>=<input> [--interval 30m] [--dry-run]
  service refresh [--state-dir <dir>] [--dry-run]  (Windows: migrate an existing task without changing grants)
                               install the per-user scheduled task
                               (launchd / user systemd timer / Task
                               Scheduler); user scope only; does NOT bind,
                               scan, or collect
  service uninstall            remove the per-user scheduled task (keeps
                               local state and grants)
  privacy [--source <s> --input <path>]
                               local-only report of what would be uploaded;
                               never touches the network
  upgrade [--check] [--to V]   verify and replace this installation in place
                               (state, grants, outbox and the schedule are untouched)
  doctor [--check-server]      local health checks; the server check is the
                               only networked one and is opt-in

Implementation migrates one tool adapter first, then expands coverage.`)
}
