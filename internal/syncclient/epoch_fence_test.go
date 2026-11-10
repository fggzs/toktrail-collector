package syncclient

import (
	"encoding/json"
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
)

// serveSelfEpoch serves a device self snapshot carrying an explicit
// dataEpoch, mirroring a server that speaks the usage-reset feature.
func serveSelfEpoch(w http.ResponseWriter, r *http.Request, revision int64, dataEpoch *int64) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/v1/devices/self" {
		return false
	}
	device := map[string]any{
		"deviceId":         "dev-1",
		"consentRevision":  revision,
		"uploadAuthorized": true,
		"revoked":          false,
	}
	if dataEpoch != nil {
		device["dataEpoch"] = *dataEpoch
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
	return true
}

// epochTestRecord returns one privacy-safe record body for batch files.
func epochTestRecord(key string) map[string]any {
	return map[string]any{
		"recordKey":      key,
		"kind":           "delta",
		"occurredAt":     "2026-11-01T10:00:00Z",
		"tool":           "claude-code",
		"model":          nil,
		"input":          "10",
		"cacheRead":      nil,
		"cacheWrite":     "0",
		"output":         "5",
		"adapterVersion": "test-adapter-1",
		"sourceType":     "fixture",
	}
}

func epochTestBatch(batchID string, dataEpoch *int64) map[string]any {
	body := map[string]any{
		"batchId": batchID,
		"records": []map[string]any{epochTestRecord(batchID + "-r1"), epochTestRecord(batchID + "-r2")},
	}
	if dataEpoch != nil {
		body["dataEpoch"] = *dataEpoch
	}
	return body
}

// setupEpochState saves a bound device state at the given data epoch.
func setupEpochState(t *testing.T, dataEpoch int64) statedir.Store {
	t.Helper()
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{
		ServerURL:    "http://unused",
		DeviceID:     "dev-1",
		DeviceSecret: strings.Repeat("a", 64),
		DataEpoch:    dataEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRunEpochFenceBlocksUnstampedBatchAfterReset(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-old", nil))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("no HTTP traffic may happen before the epoch fence, got %d requests", posts.Load())
	}
}

func TestRunEpochFenceBlocksOldEpochBatch(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-old", epochPtr(2)))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("no HTTP traffic may happen, got %d requests", posts.Load())
	}
}

func TestRunEpochFenceBlocksNewerEpochBatchOnLegacyState(t *testing.T) {
	store := setupEpochState(t, 0)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(1)))
	_, err := Run(t.Context(), store, Options{ServerURL: "http://127.0.0.1:1", BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
}

func TestRunEpochFenceLegacyBatchOnLegacyStateUploads(t *testing.T) {
	store := setupEpochState(t, 0)
	batchFile := writeBatchFile(t, epochTestBatch("batch-legacy", nil))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, nil) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DataEpoch != nil {
			t.Fatalf("legacy batch must upload without a dataEpoch stamp, got %d", *got.DataEpoch)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted", "acceptedRecords": 2, "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-11-01T10:12:00Z",
		}})
	}))
	defer server.Close()
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile}); err != nil {
		t.Fatal(err)
	}
}

func TestRunEpochFenceMatchingEpochUploadsWithStamp(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(3)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, epochPtr(3)) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.DataEpoch == nil || *got.DataEpoch != 3 {
			t.Fatalf("batch must carry its durable data epoch 3, got %#v", got.DataEpoch)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted", "acceptedRecords": 2, "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-11-01T10:12:00Z",
		}})
	}))
	defer server.Close()
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile}); err != nil {
		t.Fatal(err)
	}
}

func TestRunEpochFenceSelfMismatchStopsUpload(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(3)))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, epochPtr(4)) {
			return
		}
		posts.Add(1)
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("no ingest POST may follow an epoch mismatch, got %d", posts.Load())
	}
}

func TestRunEpochFenceSelfLegacyServerBlocksAdvancedLocalState(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(3)))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, nil) {
			return
		}
		posts.Add(1)
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("no ingest POST may follow an epoch mismatch, got %d", posts.Load())
	}
}

func TestRunEpochFenceServerConflictMapsToSentinel(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(3)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, epochPtr(3)) {
			return
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "device_epoch_stale", "message": "server free text never echoed",
		}})
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale, got %v", err)
	}
}

func TestRunJournalGuardBlocksOrdinarySendBeforeAnyTraffic(t *testing.T) {
	store := setupEpochState(t, 0)
	batchFile := writeBatchFile(t, epochTestBatch("batch-1", nil))
	writeResetJournal(t, store.Dir(), `{"requestId":"req-1","status":"recollecting"}`)
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile})
	if !errors.Is(err, ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("journal guard must stop before any HTTP traffic, got %d requests", posts.Load())
	}
}

func TestRunJournalGuardAllowsMatchingRecollectionContinuation(t *testing.T) {
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-new", epochPtr(3)))
	writeResetJournal(t, store.Dir(), `{"requestId":"req-1","status":"recollecting","dataEpoch":3}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, epochPtr(3)) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted", "acceptedRecords": 2, "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-11-01T10:12:00Z",
		}})
	}))
	defer server.Close()
	res, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile, AllowedResetRequestID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Status != "accepted" {
		t.Fatalf("unexpected receipt: %#v", res.Receipt)
	}
}

func TestRunJournalGuardContinuationStillEnforcesEpoch(t *testing.T) {
	// The continuation bypasses the journal guard but never the epoch
	// fences: a batch stamped with the old epoch must stay refused even
	// under the journal's own request id.
	store := setupEpochState(t, 3)
	batchFile := writeBatchFile(t, epochTestBatch("batch-old", epochPtr(2)))
	writeResetJournal(t, store.Dir(), `{"requestId":"req-1","status":"recollecting"}`)
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
	}))
	defer server.Close()
	_, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile, AllowedResetRequestID: "req-1"})
	if !errors.Is(err, ErrEpochStale) {
		t.Fatalf("want ErrEpochStale despite the journal bypass, got %v", err)
	}
	if posts.Load() != 0 {
		t.Fatalf("no HTTP traffic may happen, got %d", posts.Load())
	}
}

func TestRunJournalGuardRejectsForeignRequestID(t *testing.T) {
	store := setupEpochState(t, 0)
	batchFile := writeBatchFile(t, epochTestBatch("batch-1", nil))
	writeResetJournal(t, store.Dir(), `{"requestId":"req-1","status":"recollecting"}`)
	_, err := Run(t.Context(), store, Options{ServerURL: "http://127.0.0.1:1", BatchFile: batchFile, AllowedResetRequestID: "req-2"})
	if !errors.Is(err, ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress, got %v", err)
	}
}

func TestRunJournalGuardCompletedJournalAllowsOrdinarySend(t *testing.T) {
	store := setupEpochState(t, 0)
	batchFile := writeBatchFile(t, epochTestBatch("batch-1", nil))
	writeResetJournal(t, store.Dir(), `{"requestId":"req-1","status":"completed"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveSelfEpoch(w, r, 7, nil) {
			return
		}
		var got BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"batch": map[string]any{
			"batchId": got.BatchID, "status": "accepted", "acceptedRecords": 2, "rejectedRecords": 0,
			"replay": false, "receivedAt": "2026-11-01T10:12:00Z",
		}})
	}))
	defer server.Close()
	if _, err := Run(t.Context(), store, Options{ServerURL: server.URL, BatchFile: batchFile}); err != nil {
		t.Fatal(err)
	}
}

// TestRunJournalGuardFallsBackToStoreDir covers the StateDir-less history
// retransmission shape: the store points at a real state directory while
// Options.StateDir stays empty, and the guard must still see the journal.
func TestRunJournalGuardFallsBackToStoreDir(t *testing.T) {
	stateDir := t.TempDir()
	store := statedir.New(stateDir)
	if err := store.Save(statedir.DeviceState{
		ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}
	batchFile := writeBatchFile(t, epochTestBatch("batch-1", nil))
	writeResetJournal(t, stateDir, `{"requestId":"req-1","status":"recollecting"}`)
	_, err := Run(t.Context(), store, Options{ServerURL: "http://127.0.0.1:1", BatchFile: batchFile})
	if !errors.Is(err, ErrResetInProgress) {
		t.Fatalf("want ErrResetInProgress through the store-dir fallback, got %v", err)
	}
}

// registerEpochTestBatch writes a batch file and registers it as a
// pending outbox entry, mirroring the export pipeline's durable shape.
func registerEpochTestBatch(t *testing.T, stateDir, batchID, source, input string, dataEpoch *int64) (outbox.BatchEntry, BatchRequest) {
	t.Helper()
	batch := BatchRequest{BatchID: batchID, DataEpoch: dataEpoch, Records: []json.RawMessage{
		mustJSON(t, epochTestRecord(batchID+"-r1")),
		mustJSON(t, epochTestRecord(batchID+"-r2")),
	}}
	parentPath := filepath.Join(stateDir, "batches", batchID+".json")
	if err := os.MkdirAll(filepath.Dir(parentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parentPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: batchID, File: parentPath, Source: source, Input: input, RecordCount: len(batch.Records),
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry, batch
}

// TestReorgChildrenKeepParentEpoch drives a scope split on a batch that
// carries a data epoch and verifies the child batch file keeps it.
func TestReorgChildrenKeepParentEpoch(t *testing.T) {
	stateDir := t.TempDir()
	entry, batch := registerEpochTestBatch(t, stateDir, "parent-1", "src-a", "/in/a", epochPtr(4))
	scope := liveScope{revision: 9}
	journal, err := splitBatchUnderScope(stateDir, entry, batch, scope, "pre-post-scope")
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.NewBatches) != 1 {
		t.Fatalf("want one kept child, got %#v", journal.NewBatches)
	}
	plan := journal.NewBatches[0]
	if plan.DataEpoch == nil || *plan.DataEpoch != 4 {
		t.Fatalf("child plan must carry the parent epoch 4, got %#v", plan.DataEpoch)
	}
	child, err := loadBatch(batchFilePath(stateDir, plan.BatchID), plan.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if child.DataEpoch == nil || *child.DataEpoch != 4 {
		t.Fatalf("child batch file must carry the parent epoch 4, got %#v", child.DataEpoch)
	}
}

// TestReorgChildrenKeepLegacyNilEpoch verifies a legacy (unstamped) batch
// reorganizes into legacy children — the split never invents a stamp.
func TestReorgChildrenKeepLegacyNilEpoch(t *testing.T) {
	stateDir := t.TempDir()
	entry, batch := registerEpochTestBatch(t, stateDir, "parent-legacy", "src-a", "/in/a", nil)
	scope := liveScope{revision: 9}
	journal, err := splitBatchUnderScope(stateDir, entry, batch, scope, "pre-post-scope")
	if err != nil {
		t.Fatal(err)
	}
	plan := journal.NewBatches[0]
	if plan.DataEpoch != nil {
		t.Fatalf("legacy child plan must stay unstamped, got %d", *plan.DataEpoch)
	}
	child, err := loadBatch(batchFilePath(stateDir, plan.BatchID), plan.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if child.DataEpoch != nil {
		t.Fatalf("legacy child batch must stay unstamped, got %d", *child.DataEpoch)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
