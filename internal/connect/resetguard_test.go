package connect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

func writeConnectResetJournal(t *testing.T, stateDir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stateDir, "force-recollect.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSyncBlockedByForceRecollectJournal covers the sync entrypoint guard:
// an unfinished journal stops the orchestration before any collection
// round, backlog pass, dry-run plan or lock handoff — with zero network
// traffic and no state consumption.
func TestSyncBlockedByForceRecollectJournal(t *testing.T) {
	stateDir := t.TempDir()
	seedBoundState(t, stateDir, "http://127.0.0.1:1", "dev-guard-1")
	writeConnectResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)

	_, err := Sync(t.Context(), SyncOptions{StateDir: stateDir})
	if !errors.Is(err, syncclient.ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
}

// TestSyncDryRunAlsoBlockedByForceRecollectJournal pins that the offline
// dry-run plan is blocked too: the rule stays one-shaped while a reset is
// in flight.
func TestSyncDryRunAlsoBlockedByForceRecollectJournal(t *testing.T) {
	stateDir := t.TempDir()
	seedBoundState(t, stateDir, "http://127.0.0.1:1", "dev-guard-1")
	writeConnectResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)

	_, err := Sync(t.Context(), SyncOptions{StateDir: stateDir, ResyncDryRun: true})
	if !errors.Is(err, syncclient.ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress for the dry run too, got %v", err)
	}
}

// TestSyncCompletedJournalDoesNotBlock covers the resume-after-reset
// shape: a completed journal leaves ordinary sync working again.
func TestSyncCompletedJournalDoesNotBlock(t *testing.T) {
	stateDir := t.TempDir()
	seedBoundState(t, stateDir, "http://127.0.0.1:1", "dev-guard-1")
	writeConnectResetJournal(t, stateDir, `{"requestId":"req-1","status":"completed"}`)

	// The guard must pass; the run then fails later on its own terms
	// (unreachable server), NOT with the reset sentinel.
	_, err := Sync(t.Context(), SyncOptions{StateDir: stateDir})
	if errors.Is(err, syncclient.ErrResetInProgress) {
		t.Fatal("a completed journal must not block sync")
	}
}

// TestConnectRunBlockedByForceRecollectJournal covers connect's own
// entrypoint: the guard fires before the connect URL is even parsed or
// the config fetched, and the partial result reports the binding as not
// attempted.
func TestConnectRunBlockedByForceRecollectJournal(t *testing.T) {
	stateDir := t.TempDir()
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL: "http://127.0.0.1:1", DeviceID: "dev-guard-1", DeviceSecret: strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}
	writeConnectResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)

	res, err := Run(t.Context(), Options{
		URL:      "http://127.0.0.1:1/api/collector/connect#" + strings.Repeat("a", 64),
		StateDir: stateDir,
	})
	if !errors.Is(err, syncclient.ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
	if res.BindStatus != BindNotAttempted {
		t.Fatalf("the blocked run must report the binding as not attempted, got %q", res.BindStatus)
	}
}

// TestStopReasonPhrasesForResetStates pins the display phrases so the
// blocked states stay human-explainable without raw error text.
func TestStopReasonPhrasesForResetStates(t *testing.T) {
	epochPhrase := StopReasonPhrase(collection.StopEpochStale)
	if epochPhrase == "" || epochPhrase == "an unexpected error occurred" {
		t.Fatalf("epoch_stale must have its own fixed phrase, got %q", epochPhrase)
	}
	resetPhrase := StopReasonPhrase(collection.StopResetInProgress)
	if resetPhrase == "" || resetPhrase == "an unexpected error occurred" {
		t.Fatalf("reset_in_progress must have its own fixed phrase, got %q", resetPhrase)
	}
	if got := stopReasonStatus(collection.StopEpochStale); got != "blocked" {
		t.Fatalf("epoch_stale must display as blocked, got %q", got)
	}
	if got := stopReasonStatus(collection.StopResetInProgress); got != "blocked" {
		t.Fatalf("reset_in_progress must display as blocked, got %q", got)
	}
}
