package recollect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
)

// install.go implements the local state switch: after the server accepted
// the reset, the ordinary device-data stores of the ORIGINAL state are
// archived (moved, never deleted) and the scanned temporary state is
// installed in their place. Every step is idempotent — move-if-exists,
// derive-if-missing, set-once — and every step's completion is journaled
// in job.Install BEFORE the next step starts, so a crash mid-switch
// resumes exactly where it stopped. The journal guard keeps ordinary
// entrypoints blocked for the whole window, so no other flow can observe
// a half-switched state.
//
// What is archived (only code-known ordinary stores, never a blanket
// move of unknown files): the device outbox ledger and batch files, the
// cursor and message progress ledgers, the per-source scan ledgers,
// known-record caches and claude observation caches, the quarantine and
// override stores, the export/filter/reorg/sync-ACK transaction WALs,
// the preflight attempt accounting, and the resync work directory.
//
// What is preserved in place: the run lock (its inode must stay stable
// across owners), device.json (identity — only its DataEpoch field is
// advanced by the journal transition), the grants store, the managed
// consent overlay, the scheduler directory, every Cursor store (license,
// outbox, batches, revision), and anything the code does not own.

// recollectDirName is the recollect-owned subdirectory of the state
// directory holding the temporary scan states and the per-request
// archives.
const recollectDirName = "recollect"

// tempStateDirPath names the temporary scan state of one request.
func tempStateDirPath(stateDir, requestID string) string {
	return filepath.Join(stateDir, recollectDirName, "tmp-"+requestID)
}

// archiveDirPath names the archive directory of one request.
func archiveDirPath(stateDir, requestID string) string {
	return filepath.Join(stateDir, recollectDirName, "archive-"+requestID)
}

// ordinaryStoreFiles are the fixed-name ordinary stores the switch
// archives. Pattern stores (per-source ledgers and caches) are listed by
// prefix below.
var ordinaryStoreFiles = []string{
	"outbox.json",                  // device outbox ledger
	"adapter-cursors.json",         // export cursor ledger
	"message-progress.json",        // per-message baselines
	"scope-quarantine.json",        // recoverable quarantine store
	"overrides.json",               // record override ledger
	"export-transaction.json",      // export WAL
	"filter-transaction.json",      // history-filter WAL
	"scope-reorg-transaction.json", // scope reorg WAL
	"sync-ack-transaction.json",    // sync ACK WAL
	"preflight-attempts.json",      // authorization attempt accounting
}

// ordinaryStorePrefixes are the per-source store filename prefixes the
// switch archives; they are code-controlled constants, never user input.
var ordinaryStorePrefixes = []string{
	"scan-ledger-",         // per-source scan ledgers
	"known-records-",       // per-source known-record caches
	"claude-observations-", // per-input claude resume caches
}

// ordinaryStoreDirs are the ordinary store directories the switch
// archives. The scheduler directory and the recollect directory itself
// are deliberately absent (preserved), and so is every Cursor directory.
var ordinaryStoreDirs = []string{
	"batches", // device batch payloads
	"resync",  // resync journal and derived child batches
}

// installState performs the whole local switch under the caller's runlock:
// archive the ordinary stores, move the scanned batches in, install the
// rewritten outbox, move the remaining scanned stores, stamp the new data
// epoch into the preserved device.json, and remove the consumed temporary
// directory. Each step is idempotent and journaled; a failure leaves the
// job resumable at exactly the failed step.
func installState(stateDir string, j *job, now func() time.Time) error {
	if j.Install == nil {
		j.Install = &installSteps{}
	}
	if !j.Install.Archived {
		if err := archiveOrdinaryStores(stateDir, j.ArchiveDir); err != nil {
			return err
		}
		j.Install.Archived = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	if !j.Install.Batches {
		if err := installBatches(stateDir, j); err != nil {
			return err
		}
		j.Install.Batches = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	if !j.Install.Outbox {
		if err := installOutbox(stateDir, j); err != nil {
			return err
		}
		j.Install.Outbox = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	if !j.Install.Stores {
		if err := installScannedStores(stateDir, j.TempStateDir, j.StoreHashes); err != nil {
			return err
		}
		j.Install.Stores = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	if !j.Install.EpochStamped {
		if err := stampDataEpoch(stateDir, j.NextDataEpoch); err != nil {
			return err
		}
		j.Install.EpochStamped = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	if !j.Install.TempRemoved {
		if err := removeTreeVerified(stateDir, j.TempStateDir, j.RequestID); err != nil {
			return err
		}
		j.Install.TempRemoved = true
		if err := saveJob(stateDir, *j, now); err != nil {
			return err
		}
	}
	j.Phase = phaseUpload
	return saveJob(stateDir, *j, now)
}

// archiveOrdinaryStores moves every code-known ordinary store of the
// original state into the request's archive directory (same filesystem,
// atomic renames). Unknown files, the lock, identity, grants, managed
// consent, scheduler data, and every Cursor store are left untouched.
func archiveOrdinaryStores(stateDir, archiveDir string) error {
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == recollectDirName || name == journalFileName || name == ".collector.lock" ||
			name == "device.json" || name == "grants.json" || name == "sources.json" ||
			name == "managed-consent.json" || name == "scheduler" ||
			name == "cursor-outbox.json" || name == "cursor-source.json" || name == "cursor-batches" {
			continue
		}
		if !ordinaryStore(name) {
			continue
		}
		if err := moveInto(stateDir, filepath.Join(stateDir, name), filepath.Join(archiveDir, name)); err != nil {
			return fmt.Errorf("archive the ordinary state store %s: %w", name, err)
		}
	}
	return nil
}

// ordinaryStore reports whether a state-dir entry name is a code-known
// ordinary store the switch archives.
func ordinaryStore(name string) bool {
	for _, fixed := range ordinaryStoreFiles {
		if name == fixed {
			return true
		}
	}
	for _, dir := range ordinaryStoreDirs {
		if name == dir {
			return true
		}
	}
	for _, prefix := range ordinaryStorePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// moveInto renames src to dst when src exists; a missing src is a no-op
// (idempotent resume); an existing dst with src missing is a no-op too.
// Both existing at once is divergence and fails closed. Both paths must
// sit strictly inside the canonical state root with no symlink
// component between the root and either endpoint, so a hostile or
// corrupted journal can never aim a rename (and through it the archive
// or install steps) outside the state directory.
func moveInto(root, src, dst string) error {
	if err := secureWithin(root, src); err != nil {
		return err
	}
	if err := secureWithin(root, dst); err != nil {
		return err
	}
	_, srcErr := os.Lstat(src)
	if errors.Is(srcErr, os.ErrNotExist) {
		return nil
	}
	if srcErr != nil {
		return srcErr
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("both %s and %s exist; the switch state diverged, failing closed", filepath.Base(src), filepath.Base(dst))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}

// secureWithin reports whether path (absolute, clean) sits strictly
// inside the canonical root and no path component from the root down to
// the path is a symlink. The root itself was canonicalized with
// EvalSymlinks at run start, so a user-symlinked state directory works
// while any symlink planted INSIDE the tree fails closed.
func secureWithin(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root || !strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to touch a path outside the state directory")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	current := root
	for idx, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && idx == len(parts)-1 {
			// The final component may legitimately not exist yet (a
			// rename destination); every ancestor must exist and be a
			// real directory.
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to touch a path through a symlink component")
		}
	}
	return nil
}

// installBatches moves every frozen batch file from the temporary state
// into the real batches directory, verifying the payload hash at the
// destination (the same bytes the journal froze and the user confirmed).
func installBatches(stateDir string, j *job) error {
	if err := os.MkdirAll(filepath.Join(stateDir, "batches"), 0o700); err != nil {
		return err
	}
	for _, b := range j.Batches {
		tempFile := filepath.Join(j.TempStateDir, "batches", b.BatchID+".json")
		realFile := filepath.Join(stateDir, "batches", b.BatchID+".json")
		if err := moveInto(stateDir, tempFile, realFile); err != nil {
			return fmt.Errorf("install the scanned batch %s: %w", b.BatchID, err)
		}
		if err := verifyBatchFile(realFile, b.BatchID, b.PayloadSHA256); err != nil {
			return err
		}
	}
	return nil
}

// installOutbox builds the real outbox from the temporary state's ledger,
// restricted to the job's frozen batches and with every file path
// rewritten from the temporary directory to the real one. It runs after
// the batches moved and before the temporary directory is removed, so a
// crash in between re-derives the same ledger. When the temporary ledger
// is already gone (a resumed switch), the installed ledger is validated
// against the frozen batch list instead.
func installOutbox(stateDir string, j *job) error {
	realStore := outbox.New(stateDir)
	tempLedger := filepath.Join(j.TempStateDir, "outbox.json")
	raw, err := os.ReadFile(tempLedger)
	if errors.Is(err, os.ErrNotExist) {
		// Already installed by an earlier attempt: validate.
		out, lerr := realStore.Load()
		if lerr != nil {
			return lerr
		}
		return validateInstalledOutbox(out, j)
	}
	if err != nil {
		return err
	}
	if hash, ok := j.StoreHashes["outbox.json"]; ok {
		if err := verifyStoreFile(stateDir, tempLedger, hash); err != nil {
			return err
		}
	}
	var temp outbox.Outbox
	if err := json.Unmarshal(raw, &temp); err != nil {
		return fmt.Errorf("the temporary outbox ledger is not valid: %w", err)
	}
	byID := make(map[string]outbox.BatchEntry, len(temp.Batches))
	for _, entry := range temp.Batches {
		byID[entry.BatchID] = entry
	}
	installed := outbox.Outbox{Batches: make([]outbox.BatchEntry, 0, len(j.Batches))}
	for _, b := range j.Batches {
		entry, ok := byID[b.BatchID]
		if !ok {
			return fmt.Errorf("the temporary outbox does not list the frozen batch %s; the scan state diverged, failing closed", b.BatchID)
		}
		entry.File = filepath.Join(stateDir, "batches", b.BatchID+".json")
		installed.Batches = append(installed.Batches, entry)
	}
	if err := realStore.Save(installed); err != nil {
		return err
	}
	return validateInstalledOutbox(installed, j)
}

// validateInstalledOutbox checks the installed ledger against the frozen
// batch list: every frozen batch must be present exactly once, with its
// real file path and a pending or settled status.
func validateInstalledOutbox(out outbox.Outbox, j *job) error {
	byID := make(map[string]outbox.BatchEntry, len(out.Batches))
	for _, entry := range out.Batches {
		if _, dup := byID[entry.BatchID]; dup {
			return fmt.Errorf("the installed outbox lists batch %s twice; failing closed", entry.BatchID)
		}
		byID[entry.BatchID] = entry
	}
	for _, b := range j.Batches {
		entry, ok := byID[b.BatchID]
		if !ok {
			return fmt.Errorf("the installed outbox does not list the frozen batch %s; failing closed", b.BatchID)
		}
		if entry.File != filepath.Join(j.StateDir, "batches", b.BatchID+".json") {
			return fmt.Errorf("the installed outbox entry for batch %s does not point at the installed batch file; failing closed", b.BatchID)
		}
	}
	return nil
}

// installScannedStores moves the remaining scanned stores (cursor ledger,
// message progress, quarantine, per-source ledgers and caches) from the
// temporary state into the real one. The temporary device.json stub is
// deliberately NOT installed: the real device.json is preserved and only
// its data epoch advances (stampDataEpoch).
func installScannedStores(stateDir, tempDir string, hashes map[string]string) error {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "device.json" || name == "outbox.json" || name == ".collector.lock" {
			continue
		}
		if name == "batches" {
			// Moved file-by-file by installBatches; the (now empty or
			// absent) directory is removed with the temporary tree.
			continue
		}
		if !ordinaryStore(name) {
			// Unknown temporary content never lands in the real state.
			continue
		}
		hash, known := hashes[name]
		if !known {
			return fmt.Errorf("unconfirmed state artifact %s appeared after the pre-scan", name)
		}
		if err := verifyStoreFile(stateDir, filepath.Join(tempDir, name), hash); err != nil {
			return err
		}
		if err := moveInto(stateDir, filepath.Join(tempDir, name), filepath.Join(stateDir, name)); err != nil {
			return fmt.Errorf("install the scanned store %s: %w", name, err)
		}
	}
	for name, hash := range hashes {
		if name == "outbox.json" {
			continue // Installed separately with its file paths rewritten.
		}
		if err := verifyStoreFile(stateDir, filepath.Join(stateDir, name), hash); err != nil {
			return err
		}
	}
	return nil
}

// stampDataEpoch advances the preserved device.json's data epoch to the
// reset receipt's new epoch — the ONLY local transition that ever moves
// the durable epoch (an initial bind is the other one). Identity, grants,
// and every other field are preserved verbatim.
func stampDataEpoch(stateDir string, nextEpoch int64) error {
	store := statedir.New(stateDir)
	st, err := store.Load()
	if err != nil {
		return err
	}
	if st.DataEpoch == nextEpoch {
		return nil
	}
	if st.DataEpoch != 0 && st.DataEpoch != nextEpoch-1 {
		return fmt.Errorf("the local device data epoch is %d but the rebuild expects to advance %d -> %d; the state diverged, failing closed", st.DataEpoch, nextEpoch-1, nextEpoch)
	}
	st.DataEpoch = nextEpoch
	return store.Save(st)
}

// verifyBatchFile checks that the installed batch file exists and still
// hashes to the payload the job froze.
func verifyBatchFile(path, batchID, wantSum string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("the installed batch %s cannot be read: %w", batchID, err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSum {
		return fmt.Errorf("the installed batch %s does not match the payload hash frozen before the reset; failing closed", batchID)
	}
	return nil
}

// removeTreeVerified removes one recollect-owned tree only after
// verifying, against the canonical state root, that the path is exactly
// the derived temporary directory of the given request id: an exact base
// name (tmp-<requestID>), strictly inside the recollect subtree, with no
// symlink component between the root and the target. A malformed journal
// or a stray environment can therefore never aim the removal at user
// data; the state directory, the recollect root, and every archive stay
// untouchable.
func removeTreeVerified(stateDir, dir, requestID string) error {
	root := canonicalStateDir(stateDir)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	absDir = filepath.Clean(absDir)
	recollectRoot := filepath.Join(root, recollectDirName)
	if absDir == root || absDir == recollectRoot {
		return fmt.Errorf("refusing to remove the state directory or the recollect root")
	}
	if absDir != tempStateDirPath(root, requestID) {
		return fmt.Errorf("refusing to remove a path that is not the derived temporary state of request %s", requestID)
	}
	info, err := os.Lstat(absDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to remove a path that is not a directory")
	}
	// No symlink component between the root and the parent of the target
	// (the target itself was just Lstat'd as a real directory).
	if err := secureWithin(root, filepath.Dir(absDir)); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove a symlink")
	}
	if err := os.RemoveAll(absDir); err != nil {
		return err
	}
	// A dry run (and a rolled-back fresh abort) leaves no recollect
	// subtree behind: remove the recollect root when it became empty.
	// os.Remove only succeeds on an empty directory, so archives and
	// other jobs' trees are never touched.
	_ = os.Remove(filepath.Join(root, recollectDirName))
	return nil
}

// removeJobArtifacts removes a not-yet-reset job's journal and temporary
// tree — the rollback path of a fresh run the user declined to confirm.
// It is only ever called BEFORE the reset was requested (nothing remote
// happened), and only for a journal this run created.
func removeJobArtifacts(stateDir string, j job) error {
	if err := removeTreeVerified(stateDir, j.TempStateDir, j.RequestID); err != nil {
		return err
	}
	path := journalPath(stateDir)
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.Remove(path)
}
