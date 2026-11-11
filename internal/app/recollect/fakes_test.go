package recollect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// fakeRemote is a synthetic toktrail server speaking the wire the
// recollect flow drives: capabilities, device self, the usage-reset plan,
// the idempotent usage reset, its completion, and the ordinary ingest
// endpoint with data-epoch fencing and batch-idempotent receipts. It is
// test-local only — no production code path touches it.
type fakeRemote struct {
	mu sync.Mutex

	deviceID     string
	secret       string
	epoch        int64
	revision     int64
	paused       bool
	noCapability bool
	// uploadUntil / allowedTools shape the live consent scope the self
	// view reports.
	uploadUntil  *time.Time
	allowedTools []string
	// loseResetResponse makes the reset endpoint APPLY the reset but
	// answer with a transport-level failure, simulating a lost response.
	loseResetResponse bool

	// resetCount counts the DISTINCT resets applied (a replayed request
	// id must not bump it).
	resetCount int
	resets     map[string]syncclient.UsageReset
	// resetPayloads freezes the first payload per request id; a different
	// payload under the same id is a conflict.
	resetPayloads map[string]syncclient.UsageResetRequest
	completions   map[string]syncclient.UsageResetCompletion

	// ingest state
	receipts        map[string]syncclient.BatchReceipt
	rejectRecordKey string // record key rejected with record_conflict
	ingestEpoch   int64  // the epoch the ingest endpoint enforces
	ingestedBodies []syncclient.BatchRequest

	// selfViews allows a test to observe every self GET.
	selfCalls int
}

func newFakeRemote(t *testing.T) (*fakeRemote, *httptest.Server) {
	t.Helper()
	f := &fakeRemote{
		deviceID:      "device-recollect",
		secret:        "testsecret",
		epoch:         3,
		revision:      7,
		resets:        map[string]syncclient.UsageReset{},
		resetPayloads: map[string]syncclient.UsageResetRequest{},
		completions:   map[string]syncclient.UsageResetCompletion{},
		receipts:      map[string]syncclient.BatchReceipt{},
		ingestEpoch:   3,
	}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+f.deviceID+"."+f.secret && r.URL.Path != "/v1/capabilities" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_unauthorized", "message": "bad credentials"}})
			return
		}
		switch r.URL.Path {
		case "/v1/capabilities":
			features := []string{"batch-idempotency", "device-usage-reset"}
			if f.noCapability {
				features = []string{"batch-idempotency"}
			}
			json.NewEncoder(w).Encode(map[string]any{"service": "toktrail-server", "features": features})
			return
		case "/v1/devices/self":
			f.selfCalls++
			v := 1
			self := syncclient.SelfStatus{
				DeviceID: f.deviceID, ConsentRevision: f.revision, UploadAuthorized: true,
				GrantProtocolVersion: &v, DataEpoch: &f.epoch,
				UploadUntil:  f.uploadUntil,
				AllowedTools: f.allowedTools,
			}
			if f.paused {
				self.Paused = true
			}
			if task, ok := f.latestTask(); ok {
				self.UsageReset = &task
			}
			json.NewEncoder(w).Encode(map[string]any{"device": self})
			return
		case "/v1/devices/usage-reset-plan":
			first, last := "2026-01-02", "2026-11-01"
			json.NewEncoder(w).Encode(map[string]any{"plan": syncclient.UsageResetPlan{
				DeviceID: f.deviceID, ApplicationID: "app", ExternalSubjectID: "subj",
				DataEpoch: f.epoch, ConsentRevision: f.revision, RecordCount: 4242,
				FirstDay: &first, LastDay: &last,
			}})
			return
		case "/v1/devices/usage-reset":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var req syncclient.UsageResetRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(400)
				return
			}
			f.handleReset(w, req)
			return
		case "/v1/ingest/batches":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var batch syncclient.BatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				w.WriteHeader(400)
				return
			}
			f.handleIngest(w, r, batch)
			return
		}
		if len(r.URL.Path) > len("/v1/devices/usage-reset/") && r.URL.Path[len(r.URL.Path)-len("/complete"):] == "/complete" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				DataEpoch int64 `json:"dataEpoch"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(400)
				return
			}
			requestID := r.URL.Path[len("/v1/devices/usage-reset/") : len(r.URL.Path)-len("/complete")]
			f.handleComplete(w, requestID, body.DataEpoch)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(h.Close)
	return f, h
}

// latestTask renders the server's per-device usage-reset summary from its
// recorded receipts and completions.
func (f *fakeRemote) latestTask() (syncclient.DeviceUsageReset, bool) {
	var latest *syncclient.UsageReset
	for id := range f.resets {
		receipt := f.resets[id]
		if latest == nil || receipt.ResetAt.After(latest.ResetAt) {
			r := receipt
			latest = &r
		}
	}
	if latest == nil {
		return syncclient.DeviceUsageReset{}, false
	}
	task := syncclient.DeviceUsageReset{
		RequestID:      latest.RequestID,
		DataEpoch:      latest.DataEpoch,
		Status:         "recollecting",
		ResetAt:        latest.ResetAt,
		ChangeSequence: latest.ChangeSequence,
	}
	if completion, ok := f.completions[latest.RequestID]; ok {
		task.Status = "completed"
		at := completion.CompletedAt
		task.CompletedAt = &at
		task.ChangeSequence = completion.ChangeSequence
	}
	return task, true
}

// handleReset implements the idempotent reset: the same request id with
// the same payload replays the original receipt BEFORE the epoch CAS; a
// different payload under the same id, or a CAS mismatch (epoch or
// consent revision), is a 409 conflict.
func (f *fakeRemote) handleReset(w http.ResponseWriter, req syncclient.UsageResetRequest) {
	if prior, ok := f.resets[req.RequestID]; ok {
		if f.resetPayloads[req.RequestID] != req {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_reset_conflict", "message": "request id reused with a different payload"}})
			return
		}
		replay := prior
		replay.Replay = true
		json.NewEncoder(w).Encode(map[string]any{"reset": replay})
		return
	}
	if req.ExpectedDataEpoch != f.epoch || req.ExpectedConsentRevision != f.revision {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_epoch_stale", "message": "expected epoch or revision moved"}})
		return
	}
	if f.loseResetResponse {
		// The reset applies but the response never arrives: the client
		// sees a server error and must recover by replaying the identical
		// request.
		f.resetCount++
		f.epoch = req.ExpectedDataEpoch + 1
		f.ingestEpoch = f.epoch
		receipt := syncclient.UsageReset{
			RequestID:         req.RequestID,
			DeviceID:          f.deviceID,
			ApplicationID:     "app",
			ExternalSubjectID: "subj",
			PreviousDataEpoch: req.ExpectedDataEpoch,
			DataEpoch:         f.epoch,
			ConsentRevision:   f.revision,
			SubjectGeneration: 1,
			ChangeSequence:    int64(100 + f.resetCount),
			ResetAt:           time.Now().UTC(),
			DeletedRecords:    4242,
		}
		f.resets[req.RequestID] = receipt
		f.resetPayloads[req.RequestID] = req
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "internal", "message": "response lost"}})
		return
	}
	f.resetCount++
	f.epoch = req.ExpectedDataEpoch + 1
	f.ingestEpoch = f.epoch
	receipt := syncclient.UsageReset{
		RequestID:         req.RequestID,
		DeviceID:          f.deviceID,
		ApplicationID:     "app",
		ExternalSubjectID: "subj",
		PreviousDataEpoch: req.ExpectedDataEpoch,
		DataEpoch:         f.epoch,
		ConsentRevision:   f.revision,
		SubjectGeneration: 1,
		ChangeSequence:    int64(100 + f.resetCount),
		ResetAt:           time.Now().UTC(),
		DeletedRecords:    4242,
	}
	f.resets[req.RequestID] = receipt
	f.resetPayloads[req.RequestID] = req
	json.NewEncoder(w).Encode(map[string]any{"reset": receipt})
}

// handleComplete accepts the completion marker only for the latest task
// under the current epoch, idempotently per request id.
func (f *fakeRemote) handleComplete(w http.ResponseWriter, requestID string, dataEpoch int64) {
	if prior, ok := f.completions[requestID]; ok {
		if prior.DataEpoch != dataEpoch {
			w.WriteHeader(http.StatusConflict)
			return
		}
		replay := prior
		replay.Replay = true
		json.NewEncoder(w).Encode(map[string]any{"completion": replay})
		return
	}
	receipt, ok := f.resets[requestID]
	if !ok || receipt.DataEpoch != f.epoch || dataEpoch != f.epoch {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_reset_conflict", "message": "not the latest task under the current epoch"}})
		return
	}
	completion := syncclient.UsageResetCompletion{
		RequestID:      requestID,
		DeviceID:       f.deviceID,
		DataEpoch:      dataEpoch,
		ChangeSequence: receipt.ChangeSequence + 1,
		CompletedAt:    time.Now().UTC(),
	}
	f.completions[requestID] = completion
	json.NewEncoder(w).Encode(map[string]any{"completion": completion})
}

// handleIngest enforces the data-epoch fence (a batch stamped with an
// older epoch is a 409 device_epoch_stale) and answers batch-idempotent
// receipts.
func (f *fakeRemote) handleIngest(w http.ResponseWriter, r *http.Request, batch syncclient.BatchRequest) {
	if batch.DataEpoch == nil || *batch.DataEpoch != f.ingestEpoch {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "device_epoch_stale", "message": "batch data epoch does not match the device epoch"}})
		return
	}
	if r.Header.Get("X-Consent-Revision") != fmt.Sprint(f.revision) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "scope_changed", "message": "consent revision moved"}})
		return
	}
	f.ingestedBodies = append(f.ingestedBodies, batch)
	if prior, ok := f.receipts[batch.BatchID]; ok {
		prior.Replay = true
		json.NewEncoder(w).Encode(map[string]any{"batch": prior})
		return
	}
	receipt := syncclient.BatchReceipt{
		BatchID:         batch.BatchID,
		Status:          "accepted",
		AcceptedRecords: len(batch.Records),
		ReceivedAt:      time.Now().UTC(),
	}
	if f.rejectRecordKey != "" {
		for idx, raw := range batch.Records {
			var probe map[string]any
			_ = json.Unmarshal(raw, &probe)
			if fmt.Sprint(probe["recordKey"]) != f.rejectRecordKey {
				continue
			}
			receipt.AcceptedRecords--
			receipt.RejectedRecords++
			// The status word must agree with the counts exactly the way
			// the server contract derives it.
			switch {
			case receipt.RejectedRecords == 0:
				receipt.Status = "accepted"
			case receipt.AcceptedRecords == 0:
				receipt.Status = "rejected"
			default:
				receipt.Status = "partial_error"
			}
			receipt.RecordErrors = append(receipt.RecordErrors, syncclient.RecordError{Index: idx, RecordKey: f.rejectRecordKey, Code: "record_conflict", Message: "synthetic conflict"})
		}
	}
	f.receipts[batch.BatchID] = receipt
	json.NewEncoder(w).Encode(map[string]any{"batch": receipt})
}

// ---------------------------------------------------------------------
// Local state fixtures
// ---------------------------------------------------------------------

// newBoundState creates a state directory with a bound device matching
// the fake remote.
func newBoundState(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	st := statedir.DeviceState{
		ServerURL:       serverURL,
		ApplicationID:   "app",
		ExternalSubjectID: "subj",
		DeviceID:        "device-recollect",
		DeviceSecret:    "testsecret",
		ConsentRevision: 7,
	}
	if err := statedir.New(dir).Save(st); err != nil {
		t.Fatal(err)
	}
	return dir
}

// enableGrant records an enabled local source grant.
func enableGrant(t *testing.T, stateDir, source, input string) {
	t.Helper()
	if _, err := grants.New(stateDir).Enable(source, input); err != nil {
		t.Fatal(err)
	}
}

// writeUsageJSON writes a normalized usage-json fixture file and returns
// its path.
func writeUsageJSON(t *testing.T, path string, keys ...string) string {
	t.Helper()
	records := make([]map[string]any, 0, len(keys))
	for idx, key := range keys {
		records = append(records, map[string]any{
			"recordKey":      key,
			"kind":           "delta",
			"occurredAt":     fmt.Sprintf("2026-10-0%dT10:00:00Z", (idx%9)+1),
			"tool":           "Codex",
			"model":          nil,
			"input":          "100",
			"cacheRead":      "20",
			"cacheWrite":     "5",
			"output":         "50",
			"adapterVersion": "test",
			"sourceType":     "fixture",
		})
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeClaudeLine appends one assistant usage line to a claude-code-jsonl
// session file, creating it as needed.
func writeClaudeLine(t *testing.T, path, messageID string, input, output uint64, stamp string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := map[string]any{
		"type": "assistant",
		"message": map[string]any{
			"id":    messageID,
			"usage": map[string]any{"input_tokens": input, "output_tokens": output},
		},
		"timestamp": stamp,
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

// confirmAll is a Confirm callback that always proceeds.
func confirmAll(Plan) error { return nil }

// abortConfirm is a Confirm callback that always declines.
func abortConfirm(Plan) error { return fmt.Errorf("declined in test") }

// loadJobForTest reads the journal from a state dir.
func loadJobForTest(t *testing.T, stateDir string) (job, bool) {
	t.Helper()
	j, ok, err := loadJob(stateDir)
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	return j, ok
}
