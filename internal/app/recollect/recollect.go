// Package recollect implements `toktrail resync --all --force-recollect`:
// the deliberate, user-confirmed rebuild of ONE device's ordinary usage
// data from its currently authorized local sources. The server clears the
// device's ordinary history (a usage reset that preserves the device
// identity, credentials, grants, account facts, and every Cursor store),
// and this driver re-uploads a full pre-scan of the local truth under the
// new data epoch.
//
// Shape of one run:
//
//   - The ORIGINAL state directory's runlock is held for the entire run,
//     and a durable journal (force-recollect.json) is written BEFORE the
//     reset is requested. syncclient's reset-journal guard blocks every
//     ordinary entrypoint (collection, connect, sync, resync) while the
//     journal is unfinished, so nothing can mix old-epoch and new-epoch
//     data; only this driver's own sends continue, by naming the
//     journal's request id in syncclient.Options.AllowedResetRequestID
//     (the data-epoch fences are never bypassed).
//
//   - The pre-scan runs the ordinary export pipeline (dynamic source
//     registry, no hardcoded source list) over every enabled local grant
//     of the original state — never the Cursor account source and never
//     implicitly-added sources — inside a NEW, EMPTY temporary state
//     directory. Empty baselines are what make the scan a full rebuild:
//     interval sources export each message's cumulative current usage and
//     file ledgers re-parse everything. Records the live consent scope
//     excludes (a disallowed tool, a record at or after uploadUntil, or a
//     record before historyFrom) are quarantined recoverable in the
//     rebuilt state through the same crash-safe filter transaction the
//     ordinary pipeline uses — never silently dropped, because the scan
//     ledger marks their files as read. The temporary state's batch files
//     are frozen with payload hashes into the journal before the reset,
//     so the confirmed coverage is exactly what uploads.
//
//   - Fail-closed before the reset: an unknown source id, a missing or
//     unreadable granted input, a load failure, a record the consent
//     scope cannot evaluate, or a quarantined usage line the scanner
//     could not parse stops the whole run — a rebuild must never shrink
//     coverage silently, because the server's copy is the only history
//     being replaced. Legitimate diagnostics (tools that do not record a
//     model, duplicate record keys) are counted, never fatal.
//
//   - Dry-run performs the read-only network probes (capabilities, device
//     self, usage-reset plan) and the full local pre-scan, changes
//     nothing in the original state, writes no journal, clears nothing
//     remotely, and removes the temporary artifacts through a
//     verified-absolute-path cleanup.
//
//   - After confirmation: a fresh scope/epoch CAS, the idempotent
//     POST /v1/devices/usage-reset (a crash between the server applying
//     the reset and the journal write resumes by replaying the identical
//     request for its receipt — never a second reset), then the local
//     switch: the code-known ordinary stores are archived (moved, never
//     deleted) and the scanned state is installed with its paths
//     rewritten, per-step journaled, and the preserved device.json's data
//     epoch advanced to the receipt's new epoch. Identity, grants,
//     managed consent, the scheduler, the lock inode, and every Cursor
//     store are preserved in place.
//
//   - Uploads drain the installed batches through the ordinary
//     syncclient.Run (fresh live consent and epoch fences on every POST;
//     the batch stays pending on any stop). The pass stops on the first
//     rejected record, an authorization stop, an epoch fence, a budget
//     bound, or an observed scope drift — the frozen plan is never
//     re-scoped or re-planned by drift — and stays resumable. The
//     completion marker is sent only when every frozen batch settled
//     (done, or blocked with its records quarantined recoverable),
//     nothing was rejected, the installed outbox holds no pending batch,
//     and the recoverable quarantine is settled under the live
//     authorization; the CLI may then state the SERVER accepted the
//     rebuild while the website projection stays asynchronous.
//
// This package deliberately never calls collection.Run, connect, or any
// Cursor orchestration: those read the state this driver is switching or
// drive sources outside a local rebuild.
package recollect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/runlock"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// Options configures one force-recollect run.
type Options struct {
	// StateDir is the collector state directory whose device is rebuilt.
	StateDir string
	// ServerURL optionally overrides the bound server (device.json), then
	// the same local default the sync command uses.
	ServerURL string
	// ExpectedDeviceID guards the destructive half: when set, the run
	// refuses to proceed unless the bound device id matches it exactly.
	ExpectedDeviceID string
	// DryRun plans offline-safe: the read-only network probes and the
	// full local pre-scan run, but no journal is written, nothing in the
	// original state changes, nothing is cleared remotely, and the
	// temporary scan artifacts are removed through a verified-path
	// cleanup.
	DryRun bool
	// MaxBatches is an optional per-run upload budget. Zero (the
	// default) drains the whole frozen plan; a positive value stops the
	// pass after that many uploads, resumable by re-running the command.
	// Negative values are rejected.
	MaxBatches int
	// HTTPClient is injectable for tests; nil uses the syncclient
	// default.
	HTTPClient *http.Client
	// Confirm is invoked exactly once, after the plan is built and
	// before any reset request or state change. Returning an error
	// aborts the run with nothing cleared remotely; a fresh run also
	// rolls its journal and temporary scan back. Required for
	// non-dry-run runs.
	Confirm func(Plan) error
	// Progress reports each batch outcome during the upload phase (may
	// be nil).
	Progress func(ProgressEvent)
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (o Options) uploadBudget() int { return o.MaxBatches }

func (o Options) now() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

// GrantOutcome reports what one scanned grant produced. Only counts and
// closed codes travel here — never input paths, issue texts, or server
// free text — so a plan rendered for a human cannot leak local paths or
// source diagnostics.
type GrantOutcome struct {
	Source      string   `json:"source"`
	Input       string   `json:"input,omitempty"`
	Exported    bool     `json:"exported"`
	BatchIDs    []string `json:"batchIds,omitempty"`
	Records     int      `json:"records"`
	Skipped     string   `json:"skipped,omitempty"`
	Code        string   `json:"code,omitempty"`
	Issues      int      `json:"issues,omitempty"`
	Quarantined int      `json:"quarantined,omitempty"`
	// OutOfScope counts the grant's records the live consent scope
	// excluded from the rebuild (quarantined recoverable in the rebuilt
	// state, delivered by this same command once the authorization
	// covers them).
	OutOfScope int `json:"outOfScope,omitempty"`
}

// PlannedBatch is one frozen pre-scan batch selected for the rebuild.
type PlannedBatch struct {
	BatchID       string    `json:"batchId"`
	File          string    `json:"file"`
	Source        string    `json:"source,omitempty"`
	Input         string    `json:"input,omitempty"`
	Records       int       `json:"records"`
	PayloadSHA256 string    `json:"payloadSha256"`
	CreatedAt     time.Time `json:"createdAt"`
}

// Plan is the offline-plannable, confirmable description of one run. It
// carries only counts, closed codes, ids, and hashes: the CLI renders it
// without leaking local paths or source diagnostics.
type Plan struct {
	DeviceID    string
	ServerURL   string
	StateDir    string
	JournalPath string
	JobID       string
	Resumed     bool

	OldDataEpoch     int64
	NextDataEpoch    int64
	ConsentRevision  int64
	ScopeFingerprint string

	// The live read authorization the scan ran under.
	HistoryFrom  *time.Time
	UploadUntil  *time.Time
	AllowedTools []string

	// The server's pre-reset projection (usage-reset-plan).
	RemoteRecordCount int64
	RemoteFirstDay    string
	RemoteLastDay     string

	Grants         []GrantOutcome
	Batches        []PlannedBatch
	PlannedRecords int
	TotalInJob     int
	DoneInJob      int

	ExcludedDisabled   []string
	ExcludedCursor     []string
	ExcludedDuplicate  []string
	ExcludedNotAllowed []string
	ExcludedOutOfScope int

	// ArtifactDigest aggregates the frozen batch payload hashes: the
	// single value a confirmation binds to.
	ArtifactDigest string

	QuarantinedRecords int
	PendingFinalize    bool
	CoverageNote       string
}

// ProgressEvent reports one frozen batch's outcome during the upload
// phase.
type ProgressEvent struct {
	BatchID       string
	UploadBatchID string
	Outcome       string // done | blocked | failed
	Records       int
	Uploaded      int
	Accepted      int
	Rejected      int
	Replay        bool
	Err           string
}

// Result reports what one run did.
type Result struct {
	Plan   Plan
	DryRun bool
	// Self is the live authorization snapshot the run planned against.
	Self syncclient.SelfStatus

	// Epoch is the durable data epoch after the journal transition (the
	// reset receipt's new epoch); zero before the switch.
	Epoch int64
	// ChangeSequence is the server change sequence of the reset (and,
	// once accepted, the completion).
	ChangeSequence int64

	ServerReset    bool
	ResetReplay    bool
	DeletedRecords int64
	LocalSwitched  bool

	Uploads         int
	UploadedBatches int
	UploadedRecords int
	AcceptedRecords int
	RejectedRecords int
	ReplayReceipts  int
	Blocked         int

	// Completed is true only when every frozen batch settled (done, or
	// blocked with its records quarantined recoverable), nothing was
	// rejected, the installed outbox holds no pending batch, and the
	// server accepted the completion marker. The website projection may
	// still lag; the CLI words this accordingly.
	Completed        bool
	CompletionReplay bool
	Remaining        int
	Stopped          string
	JournalPath      string
}

// coverageNote is the fixed scope statement every plan carries.
const coverageNote = "force recollection rebuilds this device's ordinary usage from its currently authorized local sources only: records outside the live consent scope, disabled or ungranted sources, and the Cursor account history are excluded and never cleared-and-rebuilt here; unreadable or deleted local history cannot be recovered by this flow"

// ErrNotBound reports an unbound device.
var ErrNotBound = errors.New("device is not bound; force recollection rebuilds a bound device only and never binds one itself; run toktrail bind or connect first")

// Run performs one force-recollect pass. It acquires the state
// directory's process lock for the entire run (a concurrent holder fails
// fast with runlock.ErrBusy) and never calls collection, connect, or any
// Cursor orchestration.
func Run(ctx context.Context, opt Options) (Result, error) {
	stateDir := strings.TrimSpace(opt.StateDir)
	if stateDir == "" {
		return Result{}, errors.New("force recollection requires a state directory")
	}
	if opt.MaxBatches < 0 {
		return Result{}, fmt.Errorf("max-batches must be 0 (the whole frozen plan) or a positive upload budget")
	}
	now := opt.now()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	// Lock before anything else: validation, local reads, the scan, the
	// switch, and the uploads all happen while this process exclusively
	// owns the state directory.
	lock, err := runlock.Acquire(stateDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	// Canonicalize the state root EARLY (symlinks evaluated): every
	// derived path, journal validation, and verified cleanup compares
	// against this canonical root, so a user symlinked state directory
	// works while a journal naming anywhere else fails closed.
	stateDir = canonicalStateDir(stateDir)

	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, ErrNotBound
	}
	if expected := strings.TrimSpace(opt.ExpectedDeviceID); expected != "" && expected != st.DeviceID {
		return Result{}, fmt.Errorf("this collector is bound as device %q but the force recollection was requested for device %q; refusing to rebuild a different device", st.DeviceID, expected)
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:3211"
	}
	serverURL = strings.TrimRight(serverURL, "/")
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	// Capability gate before any authenticated read: an older server has
	// no usage-reset endpoints at all.
	if err := probeUsageResetCapability(ctx, client, serverURL); err != nil {
		return Result{}, err
	}

	// Live authorization snapshot. In a dry run the GETs are deliberately
	// unaccounted: a dry run writes nothing anywhere, and nothing is sent.
	var self syncclient.SelfStatus
	if opt.DryRun {
		self, err = syncclient.FetchDeviceSelf(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
	} else {
		self, err = preflightSelfOnce(ctx, store, serverURL, client, now)
	}
	if err != nil {
		return Result{}, err
	}
	result := Result{DryRun: opt.DryRun, Self: self, JournalPath: journalPath(stateDir)}
	if devicePaused(self) {
		return result, fmt.Errorf("%w: the server reports collection paused for this device; the force recollection refuses to scan or clear anything while paused", syncclient.ErrDevicePaused)
	}
	liveEpoch, err := selfEpoch(self)
	if err != nil {
		return result, err
	}
	scope, err := scopeFromSelf(self, st)
	if err != nil {
		return result, err
	}

	// An unfinished journal resumes; a completed journal (or none) starts
	// a fresh pass. A corrupt journal fails closed.
	existing, hasJob, err := loadJob(stateDir)
	if err != nil {
		return result, err
	}
	if hasJob && existing.completed() {
		hasJob = false
	}
	if hasJob && opt.DryRun {
		return result, fmt.Errorf("an unfinished force-recollect job (%s, phase %s) exists; re-run without --dry-run to resume it, or remove %s and the recollect directories it names to abandon it", existing.RequestID, existing.Phase, journalPath(stateDir))
	}

	var j job
	freshJournal := false
	if hasJob {
		j = existing
		if j.DeviceID != st.DeviceID {
			return result, fmt.Errorf("the unfinished force-recollect job %s was planned for device %q, but this collector is bound as %q; remove %s and the recollect directories it names only if you accept abandoning that job", j.RequestID, j.DeviceID, st.DeviceID, journalPath(stateDir))
		}
		if j.ServerURL != serverURL {
			return result, fmt.Errorf("the unfinished force-recollect job %s targets server %s, but this run targets %s; re-run against the recorded server, or remove %s to abandon the job", j.RequestID, j.ServerURL, serverURL, journalPath(stateDir))
		}
		// Epoch fence at entry: before the reset the live epoch must
		// still be the old one — except the crash window where the
		// server applied THIS job's reset before the journal recorded it
		// (recognized by the self summary's reset task naming this job's
		// request id; requestReset then replays the identical request
		// for its receipt instead of issuing a second reset). After the
		// switch, the live epoch must be the installed one.
		switch {
		case j.Phase == phaseScanning || j.Phase == phaseScanned:
			if liveEpoch == j.OldDataEpoch {
				// normal pre-reset state
			} else if j.Phase == phaseScanned && liveEpoch == j.NextDataEpoch && self.UsageReset != nil && self.UsageReset.RequestID == j.RequestID {
				// crash after the reset, before the journal write
			} else {
				return result, fmt.Errorf("the server reports data epoch %d but the unfinished job %s planned %d -> %d; another usage reset moved the device's epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", liveEpoch, j.RequestID, j.OldDataEpoch, j.NextDataEpoch, journalPath(stateDir))
			}
		default:
			if liveEpoch != j.NextDataEpoch {
				return result, fmt.Errorf("%w: the server reports data epoch %d but the unfinished job %s installed epoch %d; another usage reset moved the device's epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", syncclient.ErrEpochStale, liveEpoch, j.RequestID, j.NextDataEpoch, journalPath(stateDir))
			}
		}
		// The journal's scope baseline is FROZEN, but an UNPOSTED job
		// (no reset payload yet — nothing was ever cleared) re-plans in
		// place under the live authorization: same request id (it was
		// never sent, so it is still unused), fresh scan, fresh
		// confirmation. Once the immutable reset payload is frozen the
		// plan can never change again: the resume must be able to REPLAY
		// the exact payload even under a changed authorization (the
		// server keeps the original receipt keyed on it), and the uploads
		// enforce the live scope per record.
		if j.ResetRequest == nil && !j.Scope.matches(scope) {
			// Discard the old temporary scan state: its batches were
			// scoped under the withdrawn authorization and must never mix
			// with the re-scan.
			if err := removeTreeVerified(stateDir, j.TempStateDir, j.RequestID); err != nil {
				return result, err
			}
			j.Scope = snapshotScope(scope)
			j.Phase = phaseScanning
			j.Grants = nil
			j.Outcomes = nil
			j.Batches = nil
			j.Exclusions = jobExclusions{}
			j.RemoteRecordCount = 0
			j.RemoteFirstDay = ""
			j.RemoteLastDay = ""
			if err := saveJob(stateDir, j, now); err != nil {
				return result, fmt.Errorf("cannot persist the re-planned job under the live authorization; nothing was cleared: %w", err)
			}
			// Fall through: the scan phase below re-classifies (the
			// grant list is gone) and re-scans under the live scope.
		}
	} else {
		// Fresh job: the current server epoch is the old epoch, and the
		// rebuild stamps old+1 into every scanned batch.
		requestID, err := newRequestID()
		if err != nil {
			return result, err
		}
		j = job{
			Schema:        journalSchema,
			RequestID:     requestID,
			Status:        statusRecollecting,
			Phase:         phaseScanning,
			DeviceID:      st.DeviceID,
			ServerURL:     serverURL,
			StateDir:      stateDir,
			OldDataEpoch:  liveEpoch,
			NextDataEpoch: liveEpoch + 1,
			Scope:         snapshotScope(scope),
			TempStateDir:  tempStateDirPath(stateDir, requestID),
			ArchiveDir:    archiveDirPath(stateDir, requestID),
			CreatedAt:     now().UTC(),
		}
		freshJournal = true
	}

	// The server's pre-reset projection: what a reset would clear right
	// now. Fetched on every pre-reset run (and frozen into the journal at
	// scan completion); a post-reset resume reports the frozen numbers.
	remotePlan, err := syncclient.FetchUsageResetPlan(ctx, store, syncclient.Options{ServerURL: serverURL, HTTPClient: client})
	if err != nil {
		return result, fmt.Errorf("the usage reset plan cannot be read; the force recollection fails closed before scanning or clearing anything: %w", err)
	}
	if remotePlan.DataEpoch != liveEpoch || remotePlan.ConsentRevision != self.ConsentRevision {
		return result, fmt.Errorf("%w: the usage reset plan and the device self view disagree on the data epoch or consent revision; failing closed instead of guessing", syncclient.ErrSelfProtocol)
	}
	if j.Phase == phaseScanning || j.Phase == phaseScanned {
		j.RemoteRecordCount = remotePlan.RecordCount
		j.RemoteFirstDay = dayString(remotePlan.FirstDay)
		j.RemoteLastDay = dayString(remotePlan.LastDay)
	}

	// Scan phase: a fresh (or crashed-mid-scan) job classifies the
	// original state's grants and runs the pre-scan in the temporary
	// state. A job past the scan keeps its frozen artifacts. A dry run
	// never persists the journal — its job lives in memory only.
	if j.Phase == phaseScanning {
		if len(j.Grants) == 0 {
			classes, excluded, err := classifyGrants(stateDir, scope)
			if err != nil {
				return result, err
			}
			scanned := make([]jobGrant, 0, len(classes))
			for _, class := range classes {
				if class.ok {
					scanned = append(scanned, jobGrant{Source: class.grant.Source, Input: class.grant.Input})
				}
			}
			if len(scanned) == 0 {
				return result, errors.New("no enabled local source grant is scannable under the current authorization; refusing to clear the device's ordinary usage with nothing to rebuild it from — enable the sources you want to rebuild with `toktrail sources enable --source <source> --input <absolute-path>` and re-run, or keep the current history")
			}
			j.Grants = scanned
			j.Exclusions = excluded
			if !opt.DryRun {
				// The journal is durable BEFORE any scan work and long
				// before the reset: it carries the request id, the
				// epochs, the scope, and the temporary state location, so
				// a crash anywhere after this point resumes instead of
				// restarting.
				if err := saveJob(stateDir, j, now); err != nil {
					return result, fmt.Errorf("cannot persist the force-recollect journal before the scan; nothing was scanned or cleared: %w", err)
				}
			}
		}
		if err := prepareTempState(j.TempStateDir, j.NextDataEpoch, self, serverURL); err != nil {
			return result, err
		}
		s := &scanState{tempDir: j.TempStateDir, scope: scopeFromJournal(j), now: now, excluded: j.Exclusions}
		// Each completed grant is journaled before the next one starts,
		// so a crash mid-scan resumes without re-exporting committed
		// sources (and without duplicating their records server-side).
		onGrantDone := func(done jobGrant) {
			if opt.DryRun {
				return
			}
			for idx := range j.Grants {
				if j.Grants[idx].Source == done.Source && j.Grants[idx].Input == done.Input {
					j.Grants[idx].Done = true
				}
			}
			if err := saveJob(stateDir, j, now); err != nil {
				// The journal write is best-effort here: a failure only
				// means a resume re-scans the grant (safe, deduplicated);
				// the scan continues.
				_ = err
			}
		}
		if err := scanGrants(ctx, s, j.Grants, onGrantDone); err != nil {
			if opt.DryRun {
				// A dry run owns its temporary state and leaves nothing
				// behind, but a failure still cleans it.
				_ = removeTreeVerified(stateDir, j.TempStateDir, j.RequestID)
			}
			return result, err
		}
		// Freeze: validate every committed batch, verify the scanned
		// grants are still locally enabled, and bind the artifact hashes
		// into the journal BEFORE the reset is requested.
		if err := verifyGrantsStillEnabled(stateDir, j.Grants); err != nil {
			return result, err
		}
		frozen, err := freezeArtifacts(j.TempStateDir, j.NextDataEpoch)
		if err != nil {
			return result, err
		}
		// Even a valid zero-record scan has an explicit empty outbox to
		// bind its state manifest; a missing manifest is never optional.
		tempOutbox := filepath.Join(j.TempStateDir, "outbox.json")
		if _, statErr := os.Lstat(tempOutbox); errors.Is(statErr, os.ErrNotExist) {
			if err := secureWithin(stateDir, tempOutbox); err != nil {
				return result, err
			}
			if err := os.WriteFile(tempOutbox, []byte("{\"batches\":[]}\n"), 0o600); err != nil {
				return result, err
			}
		} else if statErr != nil {
			return result, statErr
		}
		j.StoreHashes, err = freezeStores(stateDir, j.TempStateDir)
		if err != nil {
			return result, err
		}
		j.Outcomes = mergeOutcomes(s.outcomes, frozen)
		j.Exclusions = s.excluded
		j.Batches = nil
		for _, b := range frozen {
			j.Batches = append(j.Batches, jobBatch{
				BatchID:       b.BatchID,
				Source:        b.Source,
				Input:         b.Input,
				Records:       b.Records,
				PayloadSHA256: b.Sum,
				CreatedAt:     b.Created,
				Outcome:       outcomePlanned,
			})
		}
		j.Phase = phaseScanned
		if !opt.DryRun {
			if err := saveJob(stateDir, j, now); err != nil {
				return result, fmt.Errorf("cannot persist the frozen rebuild plan before the reset; nothing was cleared: %w", err)
			}
		}
	}

	// Artifact verification: every frozen batch file must still exist and
	// hash to the payload the journal froze — before the plan is shown
	// for confirmation, and again before the uploads rely on it.
	if err := verifyFrozenArtifacts(stateDir, j); err != nil {
		return result, err
	}

	plan, err := buildPlan(st, serverURL, stateDir, j, hasJob)
	if err != nil {
		return result, err
	}
	result.Plan = plan

	if opt.DryRun {
		// Verified cleanup of the temporary artifacts; the original state
		// and the server were never touched.
		if err := removeTreeVerified(stateDir, j.TempStateDir, j.RequestID); err != nil {
			return result, err
		}
		result.Plan.JournalPath = journalPath(stateDir)
		return result, nil
	}

	// Confirmation gate: exactly once, after the plan, before any reset
	// request or state change. An aborted FRESH run (nothing reset) rolls
	// its journal and temporary state back; an aborted resumed job keeps
	// its journal blocked, because its reset may already have happened.
	if opt.Confirm == nil {
		if freshJournal {
			_ = removeJobArtifacts(stateDir, j)
		}
		return result, errors.New("force recollection execution requires a confirmation callback; the CLI prompts (or passes --yes), and tests inject one")
	}
	if err := opt.Confirm(plan); err != nil {
		if freshJournal {
			if rmErr := removeJobArtifacts(stateDir, j); rmErr != nil {
				return result, fmt.Errorf("the force recollection was aborted before anything was cleared, but its journal could not be rolled back: %w (remove %s and %s manually to abandon)", err, journalPath(stateDir), j.TempStateDir)
			}
			return result, fmt.Errorf("force recollection aborted before any reset or state change, and the fresh job was rolled back: %w", err)
		}
		return result, fmt.Errorf("force recollection aborted; the unfinished job %s stays resumable (its reset may already have happened) — re-run the same command to continue, or remove %s and the recollect directories it names to abandon: %w", j.RequestID, journalPath(stateDir), err)
	}

	// Reset + switch: only for a scanned job. A job past this point
	// (crash resume) skips straight to the idempotent install.
	if j.Phase == phaseScanned {
		if err := verifyFrozenArtifacts(stateDir, j); err != nil {
			return result, err
		}
		self, err := preflightSelfOnce(ctx, store, serverURL, client, now)
		if err != nil {
			return result, fmt.Errorf("the post-confirmation authorization check failed; no reset was requested in this attempt, but an earlier attempt may already have cleared history. The job stays resumable: %w", err)
		}
		if devicePaused(self) {
			return result, fmt.Errorf("%w: the server reports collection paused for this device; no reset was requested in this attempt, but an earlier attempt may already have cleared history. Resume the device's authorization before continuing this job", syncclient.ErrDevicePaused)
		}
		receipt, err := requestReset(ctx, store, client, &j, self, now)
		if err != nil {
			result.Stopped = "reset refused"
			return result, err
		}
		j.Reset = &receipt
		j.Phase = phaseReset
		if err := saveJob(stateDir, j, now); err != nil {
			return result, fmt.Errorf("the server accepted the reset (epoch %d -> %d) but the journal could not record it; DO NOT run ordinary collection — re-run the same command, which resumes through the idempotent reset receipt: %w", receipt.PreviousDataEpoch, receipt.DataEpoch, err)
		}
	}
	result.ServerReset = j.Reset != nil
	if j.Reset != nil {
		result.ResetReplay = j.Reset.Replay
		result.DeletedRecords = j.Reset.DeletedRecords
		result.Epoch = j.Reset.DataEpoch
		result.ChangeSequence = j.Reset.ChangeSequence
	}

	// The local switch (archive + install) is idempotent and per-step
	// journaled; a crash mid-switch resumes exactly here.
	if j.Phase == phaseReset || j.Phase == phaseUpload {
		if err := installState(stateDir, &j, now); err != nil {
			result.Stopped = "local switch failed"
			return result, err
		}
	}
	result.LocalSwitched = j.Install != nil && j.Install.TempRemoved
	result.Epoch = j.NextDataEpoch
	plan, err = buildPlan(st, serverURL, stateDir, j, true)
	if err != nil {
		return result, err
	}
	result.Plan = plan

	// Upload phase: fresh epoch check, then drain. The frozen scope is
	// never re-scoped: a drift observed here stops the pass resumable.
	self, err = preflightSelfOnce(ctx, store, serverURL, client, now)
	if err != nil {
		result.Stopped = "authorization preflight failed"
		return result, fmt.Errorf("the rebuild stopped before uploading; the job stays resumable: %w", err)
	}
	if err := verifyUploadEpoch(self, j); err != nil {
		result.Stopped = "data epoch stale"
		return result, err
	}
	// A changed live scope does NOT stop the upload phase: every upload
	// re-checks the live consent per record (out-of-scope records are
	// quarantined recoverable by syncclient's own gate) and the drain
	// settles them — the frozen plan is never re-scoped here.
	emit := func(ev ProgressEvent) {
		if opt.Progress != nil {
			opt.Progress(ev)
		}
	}
	outcome, err := uploadBatches(ctx, store, client, &j, opt, &result, emit)
	if err != nil {
		result.Stopped = outcome.stopped
		if result.Stopped == "" {
			result.Stopped = "upload stopped"
		}
		result.Remaining = countNotDone(j)
		return result, err
	}
	if outcome.stopped != "" {
		result.Stopped = outcome.stopped
		result.Remaining = countNotDone(j)
		return result, nil
	}

	// Drain everything the frozen plan left behind: derived children of
	// a live-scope reorganization, quarantined records that became
	// recoverable, and the scan's own out-of-scope quarantine. This same
	// command is the only path that can deliver them while the journal
	// blocks ordinary collection.
	if err := drainRecoveryBatches(ctx, store, client, &j, opt, &result, &outcome); err != nil {
		if errors.Is(err, errBudgetStop) {
			result.Stopped = outcome.stopped
			result.Remaining = remainingWork(j)
			return result, nil
		}
		result.Stopped = "drain stopped"
		result.Remaining = remainingWork(j)
		return result, err
	}

	// Completion gate: every frozen batch settled (done, or blocked with
	// its records quarantined recoverable and the drain settled them),
	// nothing rejected anywhere in the job, and no pending batch left in
	// the installed outbox.
	if failed := countNotDone(j) - countBlocked(j); failed > 0 {
		result.Remaining = failed
		result.Stopped = "batches not settled"
		return result, errors.New("the rebuild cannot complete: frozen batch(es) are neither done nor blocked; re-run the same command to continue them")
	}
	settledRejected, err := auditOutboxSettled(stateDir)
	if err != nil {
		return result, err
	}
	rejected := settledRejected
	if recorded := countJobRejected(j); recorded > rejected {
		rejected = recorded // Defensive fallback if an outbox entry disappeared.
	}
	if rejected > 0 {
		result.Remaining = countNotDone(j)
		result.Stopped = "records rejected"
		return result, fmt.Errorf("the rebuild cannot complete: the server rejected %d record(s); those records were NOT rebuilt and retrying the same settled batches cannot correct them. Fix the cause, then remove %s to abandon this incomplete task and start a new explicitly confirmed force recollection. Keep the installed new-epoch state and isolated archives; do not restore old batches. No successful completion is reported", rejected, journalPath(stateDir))
	}
	pending, err := pendingOutboxCount(stateDir)
	if err != nil {
		return result, err
	}
	if pending > 0 {
		result.Remaining = pending
		result.Stopped = "outbox not drained"
		return result, fmt.Errorf("the rebuild cannot complete: %d batch(es) are still pending in the installed outbox; re-run the same command to drain them before the completion marker is sent", pending)
	}
	if j.Completion == nil {
		completion, err := completeReset(ctx, store, client, &j)
		if err != nil {
			result.Stopped = "completion refused"
			result.Remaining = remainingWork(j)
			return result, err
		}
		j.Completion = &completion
		at := now().UTC()
		j.CompletedAt = &at
		j.Status = statusCompleted
		if err := saveJob(stateDir, j, now); err != nil {
			return result, fmt.Errorf("the server accepted the completion marker but the journal could not record it; re-run the same command, which replays the idempotent completion and converges: %w", err)
		}
		result.CompletionReplay = completion.Replay
		result.ChangeSequence = completion.ChangeSequence
	} else {
		result.CompletionReplay = j.Completion.Replay
		result.ChangeSequence = j.Completion.ChangeSequence
	}
	result.Completed = true
	result.Plan.PendingFinalize = false
	return result, nil
}

// prepareTempState creates the empty temporary scan state and writes its
// device.json stub: the data epoch every scanned batch is stamped with
// (old+1, frozen before the reset) and the live consent revision (the
// history-filter transaction's quarantine revision). The stub is never
// installed — the real device.json is preserved and only its epoch
// advances.
func prepareTempState(tempDir string, nextEpoch int64, self syncclient.SelfStatus, serverURL string) error {
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return fmt.Errorf("cannot create the temporary scan state: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "batches"), 0o700); err != nil {
		return fmt.Errorf("cannot create the temporary scan state batches directory: %w", err)
	}
	store := statedir.New(tempDir)
	existing, err := store.Load()
	if err != nil {
		return err
	}
	if existing.DeviceID != "" {
		// A resumed scan keeps its stub (the epoch must never drift).
		if existing.DataEpoch != nextEpoch {
			return fmt.Errorf("the temporary scan state carries data epoch %d but the rebuild stamps %d; the temporary state diverged, failing closed", existing.DataEpoch, nextEpoch)
		}
		return nil
	}
	stub := statedir.DeviceState{
		ServerURL:       serverURL,
		DeviceID:        self.DeviceID,
		ConsentRevision: self.ConsentRevision,
		DataEpoch:       nextEpoch,
	}
	return store.Save(stub)
}

// verifyGrantsStillEnabled fails the job closed when a scanned grant was
// withdrawn locally during the scan: uploading its records would exceed
// the authorization the user chose, and excluding its batches would wedge
// the installed per-message state.
func verifyGrantsStillEnabled(stateDir string, scanned []jobGrant) error {
	enabled, err := grants.New(stateDir).Enabled()
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(enabled))
	for _, grant := range enabled {
		live[grant.Source+"\x00"+grant.Input] = true
	}
	for _, grant := range scanned {
		if !live[grant.Source+"\x00"+grant.Input] {
			return fmt.Errorf("the grant for source %s was disabled while the rebuild scan ran; refusing to upload data the user withdrew — re-enable the grant and re-run the same command to continue, or remove the journal and the recollect directories it names to abandon (nothing was cleared yet)", grant.Source)
		}
	}
	return nil
}

// mergeOutcomes folds the scan's per-grant outcomes together with the
// frozen artifact truth: a resumed scan re-runs already-committed sources
// (their records are known, so they legitimately export nothing new), and
// only the frozen batches carry the real per-grant coverage. Grants whose
// frozen contribution is zero keep their scan outcome (a legitimate empty
// source); grants with frozen batches report them whatever the re-scan
// observed.
func mergeOutcomes(outcomes []GrantOutcome, frozen []frozenBatch) []GrantOutcome {
	type key struct{ source, input string }
	byGrant := make(map[key][]frozenBatch)
	for _, b := range frozen {
		byGrant[key{b.Source, b.Input}] = append(byGrant[key{b.Source, b.Input}], b)
	}
	merged := make([]GrantOutcome, len(outcomes))
	copy(merged, outcomes)
	for idx := range merged {
		batches := byGrant[key{merged[idx].Source, merged[idx].Input}]
		if len(batches) == 0 {
			continue
		}
		merged[idx].Exported = true
		merged[idx].Code = GrantExported
		merged[idx].Skipped = ""
		merged[idx].Records = 0
		merged[idx].BatchIDs = nil
		for _, b := range batches {
			merged[idx].BatchIDs = append(merged[idx].BatchIDs, b.BatchID)
			merged[idx].Records += b.Records
		}
	}
	return merged
}

// verifyFrozenArtifacts re-validates every frozen batch file against its
// journaled payload hash before the plan is confirmed and before the
// uploads rely on it: pre-install at the temporary path, post-install at
// the installed path. Tampering or a diverged switch fails closed.
func verifyFrozenArtifacts(stateDir string, j job) error {
	for _, b := range j.Batches {
		path := batchFileFor(j, b.BatchID)
		if j.Phase == phaseReset && (j.Install == nil || !j.Install.Batches) {
			// A crash during the file-by-file install may leave each batch
			// in either location. Missing installed files are not evidence
			// of divergence until the Batches step has converged.
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				path = filepath.Join(j.TempStateDir, "batches", b.BatchID+".json")
			} else if err != nil {
				return err
			}
		}
		if err := secureWithin(stateDir, path); err != nil {
			return err
		}
		if err := verifyBatchFile(path, b.BatchID, b.PayloadSHA256); err != nil {
			return err
		}
	}
	return verifyFrozenStores(stateDir, j)
}

// buildPlan renders the confirmable plan from the job's durable state.
// resumed reports whether this run continued an existing journal job (a
// fresh scan plans false, so the CLI's confirmation wording never claims
// a resume that is not one).
func buildPlan(st statedir.DeviceState, serverURL, stateDir string, j job, resumed bool) (Plan, error) {
	plan := Plan{
		DeviceID:          st.DeviceID,
		ServerURL:         serverURL,
		StateDir:          stateDir,
		JournalPath:       journalPath(stateDir),
		JobID:             j.RequestID,
		Resumed:           resumed,
		OldDataEpoch:      j.OldDataEpoch,
		NextDataEpoch:     j.NextDataEpoch,
		ConsentRevision:   j.Scope.Revision,
		ScopeFingerprint:  j.Scope.Fingerprint,
		HistoryFrom:       j.Scope.HistoryFrom,
		UploadUntil:       j.Scope.UploadUntil,
		AllowedTools:      append([]string(nil), j.Scope.AllowedTools...),
		RemoteRecordCount: j.RemoteRecordCount,
		RemoteFirstDay:    j.RemoteFirstDay,
		RemoteLastDay:     j.RemoteLastDay,
		Grants:            append([]GrantOutcome(nil), j.Outcomes...),
		TotalInJob:        len(j.Batches),
		CoverageNote:      coverageNote,
	}
	for _, b := range j.Batches {
		plan.Batches = append(plan.Batches, PlannedBatch{
			BatchID:       b.BatchID,
			File:          batchFileFor(j, b.BatchID),
			Source:        b.Source,
			Input:         b.Input,
			Records:       b.Records,
			PayloadSHA256: b.PayloadSHA256,
			CreatedAt:     b.CreatedAt,
		})
		if b.Outcome == outcomeDone {
			plan.DoneInJob++
		}
		plan.PlannedRecords += b.Records
	}
	plan.ExcludedDisabled = append([]string(nil), j.Exclusions.Disabled...)
	plan.ExcludedCursor = append([]string(nil), j.Exclusions.Cursor...)
	plan.ExcludedDuplicate = append([]string(nil), j.Exclusions.Duplicate...)
	plan.ExcludedNotAllowed = append([]string(nil), j.Exclusions.NotAllowed...)
	plan.ExcludedOutOfScope = j.Exclusions.OutOfScope
	plan.ArtifactDigest = artifactDigest(j)
	plan.QuarantinedRecords = quarantineCountFor(j)
	plan.PendingFinalize = j.Phase == phaseUpload && countNotDone(j) == 0 && j.Completion == nil
	return plan, nil
}

// remainingWork reports how much work a resume still owes: unsettled
// frozen batches plus pending outbox entries.
func remainingWork(j job) int {
	n := 0
	for _, b := range j.Batches {
		if b.Outcome == outcomePlanned || b.Outcome == outcomeFailed {
			n++
		}
	}
	return n
}

// batchFileFor derives a frozen batch's current file location: the
// temporary path before the switch, the installed path after it.
func batchFileFor(j job, batchID string) string {
	if j.Phase == phaseReset || j.Phase == phaseUpload {
		return filepath.Join(j.StateDir, "batches", batchID+".json")
	}
	return filepath.Join(j.TempStateDir, "batches", batchID+".json")
}

// artifactDigest aggregates the frozen payload hashes into one
// confirmable value (order-stable: the journal's batch order).
func artifactDigest(j job) string {
	if len(j.Batches) == 0 && len(j.StoreHashes) == 0 {
		return ""
	}
	h := sha256.New()
	for _, b := range j.Batches {
		_, _ = h.Write([]byte(b.BatchID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(b.PayloadSHA256))
		_, _ = h.Write([]byte{0})
	}
	names := make([]string, 0, len(j.StoreHashes))
	for name := range j.StoreHashes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(j.StoreHashes[name]))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// quarantineCountFor counts the recoverable quarantine store of the state
// the job currently reads (the temporary one before the switch, the real
// one after it). Informational only.
func quarantineCountFor(j job) int {
	dir := j.StateDir
	if j.Phase == phaseScanning || j.Phase == phaseScanned {
		dir = j.TempStateDir
	}
	entries, err := quarantineStoreCount(dir)
	if err != nil {
		return 0
	}
	return entries
}

// dayString renders a nullable plan day for the plan struct ("" for
// null).
func dayString(day *string) string {
	if day == nil {
		return ""
	}
	return strings.TrimSpace(*day)
}

// scopeFromJournal rebuilds the scan's live scope from the journal's
// durable baseline.
func scopeFromJournal(j job) liveScope {
	scope := liveScope{revision: j.Scope.Revision, historyFrom: j.Scope.HistoryFrom, uploadUntil: j.Scope.UploadUntil}
	if len(j.Scope.AllowedTools) > 0 {
		scope.allowedTools = make(map[string]struct{}, len(j.Scope.AllowedTools))
		for _, tool := range j.Scope.AllowedTools {
			scope.allowedTools[tool] = struct{}{}
		}
	}
	return scope
}
