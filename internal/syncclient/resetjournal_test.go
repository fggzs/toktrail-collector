package syncclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeResetJournal(t *testing.T, stateDir, body string) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, ResetJournalFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGuardResetJournalNoJournal(t *testing.T) {
	stateDir := t.TempDir()
	if err := GuardResetJournal(stateDir, ""); err != nil {
		t.Fatalf("ordinary run without a journal must pass, got %v", err)
	}
}

func TestGuardResetJournalNoJournalWithAllowedRequestFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	err := GuardResetJournal(stateDir, "req-1")
	if err == nil {
		t.Fatal("a continuation without any journal must fail closed")
	}
	if errors.Is(err, ErrResetInProgress) {
		t.Fatalf("missing-journal continuation is an inconsistency, not the in-progress sentinel: %v", err)
	}
}

func TestGuardResetJournalBlocksOrdinaryRunWhileUnfinished(t *testing.T) {
	for _, status := range []string{"recollecting", "", "unknown-status", "Recollecting"} {
		stateDir := t.TempDir()
		writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"`+status+`","extraField":"ignored"}`)
		err := GuardResetJournal(stateDir, "")
		if !errors.Is(err, ErrResetInProgress) {
			t.Fatalf("status %q must block an ordinary run with ErrResetInProgress, got %v", status, err)
		}
	}
}

func TestGuardResetJournalAllowsMatchingContinuation(t *testing.T) {
	stateDir := t.TempDir()
	writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)
	if err := GuardResetJournal(stateDir, "req-1"); err != nil {
		t.Fatalf("the journal's own request id must pass the guard, got %v", err)
	}
}

func TestGuardResetJournalRejectsDifferentRequestID(t *testing.T) {
	stateDir := t.TempDir()
	writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)
	err := GuardResetJournal(stateDir, "req-2")
	if !errors.Is(err, ErrResetInProgress) {
		t.Fatalf("a different request id must stay blocked with ErrResetInProgress, got %v", err)
	}
}

func TestGuardResetJournalCompletedNeverBlocks(t *testing.T) {
	stateDir := t.TempDir()
	writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"completed"}`)
	if err := GuardResetJournal(stateDir, ""); err != nil {
		t.Fatalf("a completed journal must not block an ordinary run, got %v", err)
	}
	if err := GuardResetJournal(stateDir, "req-other"); err != nil {
		t.Fatalf("a completed journal must not block any run, got %v", err)
	}
}

func TestGuardResetJournalCorruptFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	writeResetJournal(t, stateDir, `{not json`)
	if err := GuardResetJournal(stateDir, ""); err == nil {
		t.Fatal("a corrupt journal must fail closed")
	}
}

func TestGuardResetJournalEmptyStateDirIsNoJournal(t *testing.T) {
	if err := GuardResetJournal("", ""); err != nil {
		t.Fatalf("an empty state directory has no journal and must pass, got %v", err)
	}
	if err := GuardResetJournal("   ", ""); err != nil {
		t.Fatalf("a blank state directory has no journal and must pass, got %v", err)
	}
}

func TestCheckResetJournalIsOrdinaryForm(t *testing.T) {
	stateDir := t.TempDir()
	if err := CheckResetJournal(stateDir); err != nil {
		t.Fatalf("no journal must pass, got %v", err)
	}
	writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)
	if err := CheckResetJournal(stateDir); !errors.Is(err, ErrResetInProgress) {
		t.Fatalf("unfinished journal must block, got %v", err)
	}
}

func TestReadResetJournalPreservesExtraFieldsOnDisk(t *testing.T) {
	stateDir := t.TempDir()
	body := `{"requestId":"req-1","status":"recollecting","artifacts":["a"],"dataEpoch":3}`
	writeResetJournal(t, stateDir, body)
	file, found, err := ReadResetJournal(stateDir)
	if err != nil || !found {
		t.Fatalf("read failed: %v %v", err, found)
	}
	if file.RequestID != "req-1" || file.Status != "recollecting" {
		t.Fatalf("unexpected projection: %#v", file)
	}
	// The guard must never rewrite the driver's journal.
	raw, err := os.ReadFile(filepath.Join(stateDir, ResetJournalFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != body {
		t.Fatalf("journal file was modified: %s", string(raw))
	}
}

func TestResetJournalPathLayout(t *testing.T) {
	if got := ResetJournalPath("/tmp/state"); got != filepath.Join("/tmp/state", "force-recollect.json") {
		t.Fatalf("unexpected journal path %q", got)
	}
	if !strings.HasSuffix(ResetJournalFileName, ".json") {
		t.Fatalf("journal file name %q must be a json file", ResetJournalFileName)
	}
}
