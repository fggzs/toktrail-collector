package syncclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResetJournalFileName is the name of the force-recollect journal inside
// the collector state directory. The recollect driver owns the file's
// full content and lifecycle; this package only reads the two fields the
// guard needs — a JSON object carrying at least "requestId" (string) and
// "status" (string). Extra fields are ignored and never rewritten here,
// so the driver's richer journal survives untouched.
const ResetJournalFileName = "force-recollect.json"

// The closed vocabulary of journal statuses the guard understands. The
// interface contract uses "recollecting" for an in-progress reset and
// "completed" for a finished one; the guard deliberately treats every
// other value — including a missing or unknown status — as NOT completed,
// so a partially written, corrupted, or forward-compatible journal fails
// closed instead of letting ordinary collection run during a reset.
const (
	ResetJournalStatusRecollecting = "recollecting"
	ResetJournalStatusCompleted    = "completed"
)

// ResetJournalFile is the minimal projection of force-recollect.json the
// guard reads. It exists so callers (CLI entrypoints, the recollect
// driver's diagnostics) can inspect the same view the guard decisions
// are made from without depending on the driver's full journal schema.
type ResetJournalFile struct {
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
}

// ResetJournalPath returns the absolute-style path of the force-recollect
// journal inside stateDir. An empty stateDir yields the bare file name,
// which ReadResetJournal treats as "no journal".
func ResetJournalPath(stateDir string) string {
	return filepath.Join(strings.TrimSpace(stateDir), ResetJournalFileName)
}

// ReadResetJournal loads the guard's projection of the force-recollect
// journal. found is false when no journal exists; any other read or
// decode failure is an error the caller must fail closed on.
func ReadResetJournal(stateDir string) (ResetJournalFile, bool, error) {
	var file ResetJournalFile
	path := ResetJournalPath(stateDir)
	if strings.TrimSpace(stateDir) == "" {
		return file, false, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return file, false, nil
	}
	if err != nil {
		return file, false, err
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return file, false, fmt.Errorf("corrupt %s: %w; failing closed", ResetJournalFileName, err)
	}
	return file, true, nil
}

// GuardResetJournal enforces the force-recollect journal guard for one
// run.
//
// Semantics (fail closed on everything unusual):
//
//   - No journal in the state directory: an ordinary run (empty
//     allowedRequestID) proceeds. A run that named an allowed request id
//     fails: the recollect driver must create the journal BEFORE any
//     syncclient call, so a continuation with nothing to continue is an
//     inconsistency, not a pass.
//
//   - A journal whose status is exactly "completed" never blocks: the
//     reset finished and ordinary collection resumes (the driver may
//     keep or remove the completed file).
//
//   - Any other status — "recollecting", empty, unknown, or corrupted —
//     blocks an ordinary run with ErrResetInProgress. Only a run whose
//     allowedRequestID equals the journal's requestId exactly continues;
//     a different request id stays blocked (a second, unrelated recollect
//     request must never ride an in-progress journal).
//
// The data-epoch fences are independent of this guard: AllowedResetRequestID
// never weakens them.
func GuardResetJournal(stateDir, allowedRequestID string) error {
	allowedRequestID = strings.TrimSpace(allowedRequestID)
	file, found, err := ReadResetJournal(stateDir)
	if err != nil {
		return err
	}
	if !found {
		if allowedRequestID != "" {
			return fmt.Errorf("force-recollect continuation requested but %s does not exist; failing closed: create the journal before continuing a reset", ResetJournalFileName)
		}
		return nil
	}
	if file.Status == ResetJournalStatusCompleted {
		return nil
	}
	if allowedRequestID == "" {
		return fmt.Errorf("%w: %s exists with an unfinished reset (status %q); ordinary collection, connect and sync stop before any recover, export or upload until the force-recollect flow completes", ErrResetInProgress, ResetJournalFileName, journalStatusOrUnknown(file.Status))
	}
	if file.RequestID != allowedRequestID {
		return fmt.Errorf("%w: %s belongs to reset request %q, not the requesting continuation %q; failing closed", ErrResetInProgress, ResetJournalFileName, journalRequestOrUnknown(file.RequestID), allowedRequestID)
	}
	return nil
}

// CheckResetJournal is the ordinary-entrypoint form of the journal guard:
// it blocks whenever an unfinished force-recollect journal exists and
// offers no bypass. Collection rounds, connect runs and sync entrypoints
// call it before any recover, export or upload work.
func CheckResetJournal(stateDir string) error {
	return GuardResetJournal(stateDir, "")
}

// journalStatusOrUnknown renders an unfinished journal's status for the
// guarded error message. The status is untrusted on-disk text, but it is
// local state-directory content (written by the local recollect driver),
// not server-controlled data; an empty value still collapses to a fixed
// label rather than echoing nothing.
func journalStatusOrUnknown(status string) string {
	if strings.TrimSpace(status) == "" {
		return "unknown"
	}
	return status
}

// journalRequestOrUnknown renders the journal's request id the same way;
// it appears only in the mismatch error, where both sides are locally
// supplied strings.
func journalRequestOrUnknown(requestID string) string {
	if strings.TrimSpace(requestID) == "" {
		return "(missing)"
	}
	return requestID
}
