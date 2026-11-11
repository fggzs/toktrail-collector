package recollect

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/syncclient"
)

// force-recollect.json is the durable journal of one force-recollect job.
// It is recollect-owned state: nothing else in the collector writes it, and
// the only other reader is syncclient's reset-journal guard, which reads
// exactly two fields — requestId and status — and blocks every ordinary
// entrypoint while status is not "completed" (see
// syncclient.ResetJournalFile). The journal is what makes an interrupted
// rebuild resumable without a second server reset, keeps the artifact
// hashes frozen before the reset is requested, and pins the request id the
// idempotent reset/completion calls replay under.
const journalFileName = "force-recollect.json"

// journalSchema is the current on-disk schema of the journal.
const journalSchema = 1

// Status vocabulary. status uses the guard's closed set: "recollecting"
// while the job is unfinished and "completed" once the completion marker
// was accepted. phase is the driver's finer-grained progress marker; the
// guard deliberately ignores it, and every step transition is persisted
// before the step's effects are relied upon, so a crash resumes from the
// last durable phase. Because every phase's work is idempotent (move-if-
// exists installs, replayable reset/completion POSTs, resumable scans),
// a resume re-derives rather than trusts.
const (
	statusRecollecting = "recollecting"
	statusCompleted    = "completed"
)

// phase values. "scanning" covers the pre-scan (including its resume);
// "scanned" freezes the artifacts; "reset" records the accepted reset
// receipt (the local switch and uploads are still pending); "upload"
// records a finished local switch (uploads in progress or converging).
// The install between "reset" and "upload" journals its own per-step
// progress in installSteps so a crash mid-switch resumes exactly.
const (
	phaseScanning = "scanning"
	phaseScanned  = "scanned"
	phaseReset    = "reset"
	phaseUpload   = "upload"
)

// jobGrant is one grant the job scans, frozen when the job started. The
// grant set never changes for the lifetime of a job: a resume re-scans in
// the same temporary state under the same sources, so the frozen artifacts
// always correspond to the authorization the job was launched with. At
// freeze time every scanned grant must STILL be enabled locally (see
// scan.go), so a grant withdrawn mid-scan fails the job closed before the
// reset instead of uploading data the user no longer authorizes.
type jobGrant struct {
	Source string `json:"source"`
	Input  string `json:"input"`
	// Done marks a grant whose scan completed in an earlier attempt of
	// this job (every chunk committed, scan states saved): a resumed
	// scan skips it, so sources without a local known-record filter can
	// never re-export their already-committed records into duplicate
	// batches. The flag is journaled after each grant completes, so a
	// crash mid-source still re-scans that source (its dedup or the
	// server's record-key identity settles any partial commit).
	Done bool `json:"done,omitempty"`
}

// batchOutcome is the closed vocabulary of per-batch outcomes inside a job.
// "planned" is selected but not yet attempted; "done" has at least one
// server receipt and no outstanding error; "blocked" is a deterministic
// refusal (fully outside the live consent scope, reorganized away);
// "failed" is a transient error retried by the next run.
const (
	outcomePlanned = "planned"
	outcomeDone    = "done"
	outcomeBlocked = "blocked"
	outcomeFailed  = "failed"
)

// jobUpload is one concrete upload executed for a frozen batch. UploadBatchID
// is the batch id the server receipt names — the frozen id itself, or the
// deterministic child a live-scope reorganization produced when the consent
// narrowed between the scan and the upload.
type jobUpload struct {
	UploadBatchID   string    `json:"uploadBatchId"`
	ReceiptStatus   string    `json:"receiptStatus,omitempty"`
	AcceptedRecords int       `json:"acceptedRecords"`
	RejectedRecords int       `json:"rejectedRecords"`
	Replay          bool      `json:"replay"`
	SyncedAt        time.Time `json:"syncedAt,omitempty"`
}

// jobBatch is one frozen pre-scan batch. PayloadSHA256 freezes the batch
// file content the job was planned against (the hash is computed and
// journaled BEFORE the reset is requested), so a resume detects tampering
// before anything is uploaded. File paths are derived, never stored: the
// batch lives at <TempStateDir>/batches/<BatchID>.json until the install
// moves it to <StateDir>/batches/<BatchID>.json.
type jobBatch struct {
	BatchID       string      `json:"batchId"`
	Source        string      `json:"source,omitempty"`
	Input         string      `json:"input,omitempty"`
	Records       int         `json:"records"`
	PayloadSHA256 string      `json:"payloadSha256"`
	CreatedAt     time.Time   `json:"createdAt"`
	Outcome       string      `json:"outcome"`
	Attempts      int         `json:"attempts,omitempty"`
	Uploads       []jobUpload `json:"uploads,omitempty"`
	BlockedReason string      `json:"blockedReason,omitempty"`
	Error         string      `json:"error,omitempty"`
}

// installSteps records the durable per-step progress of the local state
// switch (archive + install). Every step is idempotent on its own; the
// journal record exists so a resume knows which steps already converged
// and so a crash mid-switch is diagnosable. Steps are marked only AFTER
// the step's effects are durable.
type installSteps struct {
	Archived     bool `json:"archived,omitempty"`
	Batches      bool `json:"batches,omitempty"`
	Outbox       bool `json:"outbox,omitempty"`
	Stores       bool `json:"stores,omitempty"`
	EpochStamped bool `json:"epochStamped,omitempty"`
	TempRemoved  bool `json:"tempRemoved,omitempty"`
}

// job is one force-recollect job. The reset request payload
// (ExpectedDataEpoch/ExpectedConsentRevision from Scope) is frozen here
// BEFORE the reset POST, so a crash between the server applying the reset
// and the journal write resumes by replaying the identical idempotent
// request instead of issuing a second reset.
type job struct {
	Schema    int    `json:"schema"`
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	Phase     string `json:"phase"`

	DeviceID  string `json:"deviceId"`
	ServerURL string `json:"serverUrl"`
	StateDir  string `json:"stateDir"`

	OldDataEpoch  int64 `json:"oldDataEpoch"`
	NextDataEpoch int64 `json:"nextDataEpoch"`

	// Scope is the consent scope baseline the scan ran under; it is
	// FROZEN with the artifacts. Uploads enforce the LIVE scope per
	// record regardless (syncclient's gate), so a later authorization
	// change never re-scopes the frozen plan.
	Scope *jobScope `json:"scope,omitempty"`

	// ResetRequest is the IMMUTABLE idempotency payload of the reset:
	// frozen durably BEFORE the first POST and replayed verbatim on every
	// retry, so a lost reset response followed by an authorization change
	// can never wedge the job behind a same-id-different-payload 409 —
	// the server keeps the original receipt keyed on exactly this
	// payload. The expected revision is the scope revision the plan was
	// frozen under, never the live one.
	ResetRequest *syncclient.UsageResetRequest `json:"resetRequest,omitempty"`

	// TempStateDir / ArchiveDir are strictly derived from StateDir and
	// RequestID (validated on load); the journal never accepts
	// free-form paths.
	TempStateDir string `json:"tempStateDir,omitempty"`
	ArchiveDir   string `json:"archiveDir,omitempty"`

	// RemoteRecordCount / RemoteFirstDay / RemoteLastDay freeze the
	// server's pre-reset projection (usage-reset-plan) at scan
	// completion, so a resumed run reports the coverage the user
	// confirmed instead of the post-reset emptiness.
	RemoteRecordCount int64  `json:"remoteRecordCount,omitempty"`
	RemoteFirstDay    string `json:"remoteFirstDay,omitempty"`
	RemoteLastDay     string `json:"remoteLastDay,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// CompletedAt is set when the completion marker was accepted.
	CompletedAt *time.Time `json:"completedAt,omitempty"`

	// Grants is the frozen grant list; Outcomes the per-grant scan report
	// frozen at scan completion (nil while scanning).
	Grants     []jobGrant     `json:"grants,omitempty"`
	Outcomes   []GrantOutcome `json:"outcomes,omitempty"`
	Exclusions jobExclusions  `json:"exclusions,omitempty"`

	Batches []jobBatch `json:"batches"`
	// StoreHashes freezes all ordinary pre-scan state (including quarantine
	// and baselines), not just the immediate upload batch payloads.
	StoreHashes map[string]string `json:"storeHashes"`

	// Reset is the accepted (or replayed) reset receipt.
	Reset *syncclient.UsageReset `json:"reset,omitempty"`
	// Completion is the accepted (or replayed) completion receipt.
	Completion *syncclient.UsageResetCompletion `json:"completion,omitempty"`
	// Install is the durable per-step progress of the local switch.
	Install *installSteps `json:"install,omitempty"`
}

// jobExclusions records what the job deliberately did not scan or upload,
// so a resumed run (and its dry-run reporting) stays honest about coverage.
type jobExclusions struct {
	Disabled   []string `json:"disabled,omitempty"`
	Cursor     []string `json:"cursor,omitempty"`
	Duplicate  []string `json:"duplicate,omitempty"`
	NotAllowed []string `json:"notAllowed,omitempty"`
	// OutOfScope counts the records the live consent scope excluded from
	// the scan (tool not allowed, before historyFrom, at/after
	// uploadUntil). They are quarantined recoverable in the rebuilt
	// state and delivered by this same command once the authorization
	// covers them.
	OutOfScope int `json:"outOfScope,omitempty"`
}

func (j job) completed() bool { return j.Status == statusCompleted }

func journalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), journalFileName)
}

// newRequestID mints the idempotency key of one rebuild. The server keeps
// a receipt per id, so the same id with the same payload can never clear
// the device's data twice.
func newRequestID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "recollect-" + hex.EncodeToString(b[:]), nil
}

// maxRequestIDLen mirrors syncclient's reset request id bound.
const maxRequestIDLen = 128

// validPathToken reports whether a journal-supplied identifier is safe to
// embed in a derived file path: non-empty, bounded, and restricted to
// letters, digits, dash, underscore, and dot — no separators, no
// traversal, no device or server control.
func validPathToken(id string, maxLen int) bool {
	if id == "" || len(id) > maxLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func validOutcome(outcome string) bool {
	switch outcome {
	case outcomePlanned, outcomeDone, outcomeBlocked, outcomeFailed:
		return true
	}
	return false
}

func validPayloadHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// loadJob reads the force-recollect journal of the canonical state
// directory. A missing journal is (false, nil); a corrupt journal —
// including one whose recorded paths or identifiers do not match the
// strictly derived expectations — is a hard error: the resume state is
// unknown, so the run fails closed instead of guessing. Removing the file
// (and the recollect directories it names) is the explicit user action to
// abandon an interrupted rebuild that has not reset anything remotely.
func loadJob(stateDir string) (job, bool, error) {
	root := canonicalStateDir(stateDir)
	b, err := os.ReadFile(journalPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return job{}, false, nil
	}
	if err != nil {
		return job{}, false, err
	}
	var j job
	if err := json.Unmarshal(b, &j); err != nil {
		return job{}, false, fmt.Errorf("corrupt %s: %w; failing closed (remove the file and the recollect directories it names only if you accept abandoning the rebuild)", journalPath(root), err)
	}
	if err := j.validate(root); err != nil {
		return job{}, false, err
	}
	return j, true, nil
}

// canonicalStateDir resolves the state directory to its canonical
// real-path (symlinks evaluated). The runlock has already created it by
// the time this runs; every derived-path validation in the package
// compares against this canonical root, so a state directory reached
// through a user symlink still behaves correctly while a journal that
// names anywhere else fails closed.
func canonicalStateDir(stateDir string) string {
	abs, err := filepath.Abs(strings.TrimSpace(stateDir))
	if err != nil {
		return filepath.Clean(strings.TrimSpace(stateDir))
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return filepath.Clean(abs)
}

func (j job) validate(root string) error {
	if j.Schema != journalSchema {
		return fmt.Errorf("corrupt force-recollect journal: unsupported schema %d", j.Schema)
	}
	if !validPathToken(j.RequestID, maxRequestIDLen) {
		return errors.New("corrupt force-recollect journal: missing or unsafe requestId")
	}
	switch j.Status {
	case statusRecollecting, statusCompleted:
	default:
		return fmt.Errorf("corrupt force-recollect journal: unknown status %q", j.Status)
	}
	switch j.Phase {
	case phaseScanning, phaseScanned, phaseReset, phaseUpload:
	default:
		return fmt.Errorf("corrupt force-recollect journal: unknown phase %q", j.Phase)
	}
	if j.Status == statusCompleted && j.Phase != phaseUpload {
		return errors.New("corrupt force-recollect journal: a completed job must be in the upload phase")
	}
	if j.DeviceID == "" || j.ServerURL == "" {
		return errors.New("corrupt force-recollect journal: missing device id or server url")
	}
	// The recorded state directory must BE this canonical state
	// directory, and the scratch/archive paths must be exactly the
	// derived ones — a journal naming any other location (a hand-edited
	// or foreign journal) fails closed before a single move or delete.
	if filepath.Clean(j.StateDir) != root {
		return fmt.Errorf("corrupt force-recollect journal: the recorded state directory does not match this state directory; refusing to resume a foreign job")
	}
	if j.TempStateDir != "" && j.TempStateDir != tempStateDirPath(root, j.RequestID) {
		return errors.New("corrupt force-recollect journal: the temporary state path is not the derived one; refusing to touch it")
	}
	if j.ArchiveDir != "" && j.ArchiveDir != archiveDirPath(root, j.RequestID) {
		return errors.New("corrupt force-recollect journal: the archive path is not the derived one; refusing to touch it")
	}
	if j.Phase != phaseScanning && (j.TempStateDir == "" || j.ArchiveDir == "") {
		return errors.New("corrupt force-recollect journal: a started job records no scratch or archive path")
	}
	if j.NextDataEpoch != j.OldDataEpoch+1 || j.OldDataEpoch < 0 {
		return fmt.Errorf("corrupt force-recollect journal: epochs %d -> %d are not a single step", j.OldDataEpoch, j.NextDataEpoch)
	}
	if j.Scope == nil || j.Scope.Revision <= 0 || strings.TrimSpace(j.Scope.Fingerprint) == "" {
		return errors.New("corrupt force-recollect journal: missing or malformed scope baseline")
	}
	if j.CreatedAt.IsZero() {
		return errors.New("corrupt force-recollect journal: missing createdAt")
	}
	// A job past the scan must carry frozen artifacts; every batch id is
	// path-embedded, so it must be a safe token; the reset receipt must
	// describe this request and the epochs the job froze; the completion
	// must name the same request.
	if j.Phase != phaseScanning && len(j.Grants) == 0 {
		return errors.New("corrupt force-recollect journal: a scanned job records no grants")
	}
	if j.Phase != phaseScanning && len(j.StoreHashes) == 0 {
		return errors.New("corrupt force-recollect journal: frozen state manifest is missing")
	}
	for name, hash := range j.StoreHashes {
		if filepath.Base(name) != name || name == "batches" || name == "resync" || !ordinaryStore(name) || !validPayloadHash(hash) {
			return errors.New("corrupt force-recollect journal: unsafe or invalid frozen state artifact")
		}
	}
	seen := make(map[string]bool, len(j.Batches))
	for idx, b := range j.Batches {
		if !validPathToken(b.BatchID, 160) {
			return fmt.Errorf("corrupt force-recollect journal: batch %d has a missing or unsafe batch id", idx)
		}
		if seen[b.BatchID] {
			return fmt.Errorf("corrupt force-recollect journal: duplicate batch %s", b.BatchID)
		}
		seen[b.BatchID] = true
		if b.Records <= 0 {
			return fmt.Errorf("corrupt force-recollect journal: batch %s has no record count", b.BatchID)
		}
		if !validPayloadHash(b.PayloadSHA256) {
			return fmt.Errorf("corrupt force-recollect journal: batch %s has a malformed payload hash", b.BatchID)
		}
		if !validOutcome(b.Outcome) {
			return fmt.Errorf("corrupt force-recollect journal: batch %s has unknown outcome %q", b.BatchID, b.Outcome)
		}
		if b.Outcome == outcomeDone && len(b.Uploads) == 0 {
			return fmt.Errorf("corrupt force-recollect journal: done batch %s records no upload", b.BatchID)
		}
		for uidx, u := range b.Uploads {
			if !validPathToken(u.UploadBatchID, 160) || u.AcceptedRecords+u.RejectedRecords <= 0 {
				return fmt.Errorf("corrupt force-recollect journal: batch %s upload %d is malformed", b.BatchID, uidx)
			}
		}
	}
	if j.ResetRequest != nil {
		if j.ResetRequest.RequestID != j.RequestID ||
			j.ResetRequest.ExpectedDataEpoch != j.OldDataEpoch ||
			j.ResetRequest.ExpectedConsentRevision != j.Scope.Revision {
			return errors.New("corrupt force-recollect journal: the frozen reset payload does not match the job")
		}
		if j.Phase == phaseScanning {
			return errors.New("corrupt force-recollect journal: a reset payload cannot precede the scanned phase")
		}
	}
	if j.Reset != nil {
		if j.Reset.RequestID != j.RequestID {
			return errors.New("corrupt force-recollect journal: the reset receipt names a different request id")
		}
		if j.Reset.DataEpoch != j.NextDataEpoch || j.Reset.PreviousDataEpoch != j.OldDataEpoch {
			return errors.New("corrupt force-recollect journal: the reset receipt epochs do not match the job")
		}
		if j.Phase == phaseScanning || j.Phase == phaseScanned {
			return errors.New("corrupt force-recollect journal: a reset receipt cannot precede the scanned phase")
		}
	}
	if j.Completion != nil {
		if j.Completion.RequestID != j.RequestID {
			return errors.New("corrupt force-recollect journal: the completion receipt names a different request id")
		}
		if j.Completion.DataEpoch != j.NextDataEpoch {
			return errors.New("corrupt force-recollect journal: the completion receipt epoch does not match the job")
		}
		if j.Status != statusCompleted || j.CompletedAt == nil {
			return errors.New("corrupt force-recollect journal: a completion receipt requires completed status")
		}
	}
	if j.Status == statusCompleted && (j.Reset == nil || j.Completion == nil) {
		return errors.New("corrupt force-recollect journal: a completed job lacks its reset or completion receipt")
	}
	return nil
}

// saveJob persists the journal atomically (tmp + rename, 0600). It is
// called before the reset request (freezing the artifacts and the exact
// idempotent payload), after every phase and install-step transition, and
// after every batch outcome, so a crash at any point leaves a resumeable
// state.
func saveJob(stateDir string, j job, now func() time.Time) error {
	stateDir = canonicalStateDir(stateDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if now == nil {
		now = time.Now
	}
	j.UpdatedAt = now().UTC()
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	path := journalPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
