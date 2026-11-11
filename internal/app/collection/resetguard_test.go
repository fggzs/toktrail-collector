package collection

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	synccmd "toktrail-collector/internal/syncclient"
)

func writeForceRecollectJournal(t *testing.T, stateDir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stateDir, "force-recollect.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunBlockedByForceRecollectJournal covers the periodic entrypoint
// guard: an unfinished journal stops the round before any recovery,
// grant sync, scan or upload — zero network traffic, nothing exported.
func TestRunBlockedByForceRecollectJournal(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-blocked-1")
	writeForceRecollectJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)

	_, err := Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, synccmd.ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
	if got := server.totalRequests(); got != 0 {
		t.Fatalf("a journaled reset must stop the round before any network traffic, got %d requests", got)
	}
	// The pending batch must be untouched.
	entry, ok, err := outbox.New(stateDir).PendingByID("batch-blocked-1")
	if err != nil || !ok || entry.Status != outbox.StatusPending {
		t.Fatalf("pending batch must stay pending: %v %v %#v", err, ok, entry)
	}
}

// TestDrainPendingBlockedByForceRecollectJournal covers the drain-only
// entrypoint guard.
func TestDrainPendingBlockedByForceRecollectJournal(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-blocked-1")
	writeForceRecollectJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)

	_, err := DrainPending(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, synccmd.ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
	if got := server.totalRequests(); got != 0 {
		t.Fatalf("a journaled reset must stop the drain before any network traffic, got %d requests", got)
	}
}

// TestRunProceedsAfterCompletedJournal covers the non-blocking completed
// state: once the recollect driver marks the journal completed, ordinary
// collection resumes (the fake server has no grants configured, so the
// round is the historical no-grants drain shape).
func TestRunProceedsAfterCompletedJournal(t *testing.T) {
	stateDir := t.TempDir()
	server := fakeServer(t)
	bindDevice(t, stateDir, server.URL)
	writePendingBatch(t, stateDir, "batch-after-reset-1")
	writeForceRecollectJournal(t, stateDir, `{"requestId":"req-1","status":"completed"}`)

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedBatches != 1 {
		t.Fatalf("a completed journal must not block the drain, got %+v", res)
	}
}

// epochFakeServer serves a self snapshot with an explicit dataEpoch and
// counts every request, so the pre-scan fence test can assert the round
// stopped right after the grant-sync self fetch.
func epochFakeServer(t *testing.T, dataEpoch int64) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var total atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total.Add(1)
		if r.Method == http.MethodGet && r.URL.Path == "/v1/devices/self" {
			device := map[string]any{
				"deviceId":         "dev-1",
				"consentRevision":  7,
				"uploadAuthorized": true,
				"revoked":          false,
			}
			if dataEpoch >= 0 {
				device["dataEpoch"] = dataEpoch
			}
			writeJSONForTest(w, http.StatusOK, map[string]any{"device": device})
			return
		}
		writeJSONForTest(w, http.StatusNotFound, map[string]any{})
	}))
	t.Cleanup(server.Close)
	return server, &total
}

// TestRunEpochStaleStopsRoundBeforeScanning covers the pre-scan epoch
// fence: a server whose data epoch no longer matches the locally locked
// one stops the round inside the grant sync — before any grant write,
// source read, export or upload.
func TestRunEpochStaleStopsRoundBeforeScanning(t *testing.T) {
	stateDir := t.TempDir()
	server, total := epochFakeServer(t, 4)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL: server.URL, DeviceID: "dev-1", DeviceSecret: testSecret, DataEpoch: 3,
	}); err != nil {
		t.Fatal(err)
	}
	// A granted source the round must never read.
	enableGrant(t, stateDir, "claude-code-jsonl", t.TempDir())

	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if !errors.Is(err, synccmd.ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
	if res.ExportedBatches != 0 || res.SyncedBatches != 0 {
		t.Fatalf("an epoch-stale round must not export or sync, got %+v", res)
	}
	if got := total.Load(); got != 1 {
		t.Fatalf("the round must stop after exactly the grant-sync self fetch, got %d requests", got)
	}
	// Nothing may have been written into the outbox.
	out, loadErr := outbox.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(out.Batches) != 0 {
		t.Fatalf("an epoch-stale round must not create batches, got %d", len(out.Batches))
	}
}

// TestRunEpochMatchScansNormally covers the healthy path: matching
// epochs keep the legacy no-grants no-op shape exactly.
func TestRunEpochMatchScansNormally(t *testing.T) {
	stateDir := t.TempDir()
	server, total := epochFakeServer(t, 3)
	if err := statedir.New(stateDir).Save(statedir.DeviceState{
		ServerURL: server.URL, DeviceID: "dev-1", DeviceSecret: testSecret, DataEpoch: 3,
	}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(t.Context(), Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoGrants || res.Skipped == "" {
		t.Fatalf("matching epochs must keep the no-op shape, got %+v", res)
	}
	if got := total.Load(); got != 1 {
		t.Fatalf("expected exactly the grant-sync self request, got %d", got)
	}
}

// TestClassifyRunErrorEpochSentinels pins the stable stop-reason mapping
// for the two terminal reset states.
func TestClassifyRunErrorEpochSentinels(t *testing.T) {
	reason, ok := ClassifyRunError(synccmd.ErrEpochStale, nil)
	if !ok || reason != StopEpochStale {
		t.Fatalf("ErrEpochStale must classify as StopEpochStale, got %q %v", reason, ok)
	}
	reason, ok = ClassifyRunError(synccmd.ErrResetInProgress, nil)
	if !ok || reason != StopResetInProgress {
		t.Fatalf("ErrResetInProgress must classify as StopResetInProgress, got %q %v", reason, ok)
	}
	// Wrapped forms classify identically.
	reason, ok = ClassifyRunError(errors.Join(errors.New("periodic"), synccmd.ErrEpochStale), nil)
	if !ok || reason != StopEpochStale {
		t.Fatalf("wrapped ErrEpochStale must classify as StopEpochStale, got %q %v", reason, ok)
	}
}

// TestSummarizeEpochStableContract pins the §6.5 JSON values.
func TestSummarizeEpochStableContract(t *testing.T) {
	summary := SummarizeNotRun(synccmd.ErrEpochStale, "periodic", 1)
	if summary.StopReason != StopEpochStale || string(summary.StopReason) != "epoch_stale" {
		t.Fatalf("stable contract must carry epoch_stale, got %q", summary.StopReason)
	}
	summary = SummarizeNotRun(synccmd.ErrResetInProgress, "periodic", 1)
	if summary.StopReason != StopResetInProgress || string(summary.StopReason) != "reset_in_progress" {
		t.Fatalf("stable contract must carry reset_in_progress, got %q", summary.StopReason)
	}
	if strings.Contains(strings.Join([]string{string(summary.StopReason)}, ""), " ") {
		t.Fatal("stop reasons must stay single-token")
	}
}
