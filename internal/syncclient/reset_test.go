package syncclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
)

// TestQuarantineRecoveryStampsOriginEpoch quarantines a record from a
// batch stamped with data epoch 2 and verifies the recovery batch —
// created under a strictly newer consent revision while the device is
// still at epoch 2 — carries the SAME stamp, not the live state's and
// not a fresh one.
func TestQuarantineRecoveryStampsOriginEpoch(t *testing.T) {
	stateDir := t.TempDir()
	// Origin batch: registered in the ledger with its file in a
	// non-default location, stamped epoch 2.
	originFile := filepath.Join(t.TempDir(), "origin.json")
	origin := BatchRequest{BatchID: "origin-1", DataEpoch: epochPtr(2), Records: []json.RawMessage{
		mustJSON(t, epochTestRecord("recover-1")),
	}}
	b, err := json.Marshal(origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
		BatchID: "origin-1", File: originFile, Source: "src-a", Input: "/in/a", RecordCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// The quarantined record references the origin batch.
	record := mustJSON(t, epochTestRecord("recover-1"))
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
		Source: "src-a", Input: "/in/a", RecordKey: "recover-1", Record: record,
		OriginBatchID: "origin-1", Reason: "outside_time_window", ConsentRevision: 5,
		QuarantinedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	// Recovery under a strictly newer revision with a scope that fits.
	recovered, err := recoverQuarantinedWithScope(stateDir, SelfStatus{DeviceID: "dev-1", ConsentRevision: 9})
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Fatalf("want 1 recovered record, got %d", recovered)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range out.Batches {
		if entry.Status != outbox.StatusPending || strings.HasPrefix(entry.BatchID, "origin-") {
			continue
		}
		found = true
		batch, err := loadBatch(entry.File, entry.BatchID)
		if err != nil {
			t.Fatal(err)
		}
		if batch.DataEpoch == nil || *batch.DataEpoch != 2 {
			t.Fatalf("recovery batch must carry the origin epoch 2, got %#v", batch.DataEpoch)
		}
	}
	if !found {
		t.Fatal("no recovery batch was created")
	}
}

// TestQuarantineRecoveryDisagreementFailsClosed quarantines records from
// two origin batches stamped with different epochs and verifies the
// recovery refuses to pick a side.
func TestQuarantineRecoveryDisagreementFailsClosed(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now().UTC()
	for _, spec := range []struct {
		batchID string
		epoch   *int64
		key     string
	}{
		{"origin-a", epochPtr(2), "key-a"},
		{"origin-b", epochPtr(3), "key-b"},
	} {
		originFile := filepath.Join(stateDir, "batches", spec.batchID+".json")
		if err := os.MkdirAll(filepath.Dir(originFile), 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(BatchRequest{BatchID: spec.batchID, DataEpoch: spec.epoch, Records: []json.RawMessage{
			mustJSON(t, epochTestRecord(spec.key)),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(originFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := outbox.New(stateDir).AddPending(outbox.AddBatchOptions{
			BatchID: spec.batchID, File: originFile, Source: "src-a", Input: "/in/a", RecordCount: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
			Source: "src-a", Input: "/in/a", RecordKey: spec.key,
			Record: mustJSON(t, epochTestRecord(spec.key)), OriginBatchID: spec.batchID,
			Reason: "outside_time_window", ConsentRevision: 5, QuarantinedAt: now,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := recoverQuarantinedWithScope(stateDir, SelfStatus{DeviceID: "dev-1", ConsentRevision: 9})
	if err == nil {
		t.Fatal("disagreeing origin epochs must fail the recovery closed")
	}
	entries, loadErr := quarantine.New(stateDir).Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(entries) != 2 {
		t.Fatalf("both records must stay quarantined, got %d", len(entries))
	}
}

// TestQuarantineRecoveryUnknownOriginStaysUnstamped covers a quarantine
// store whose origin batches cannot be located (a legacy hand-migrated
// store): the recovery batch carries no stamp, which the upload fence
// still refuses once the local epoch has moved.
func TestQuarantineRecoveryUnknownOriginStaysUnstamped(t *testing.T) {
	stateDir := t.TempDir()
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
		Source: "src-a", Input: "/in/a", RecordKey: "legacy-1",
		Record: mustJSON(t, epochTestRecord("legacy-1")), OriginBatchID: "gone-batch",
		Reason: "outside_time_window", ConsentRevision: 5, QuarantinedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	recovered, err := recoverQuarantinedWithScope(stateDir, SelfStatus{DeviceID: "dev-1", ConsentRevision: 9})
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Fatalf("want the legacy record recovered, got %d", recovered)
	}
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range out.Batches {
		if entry.Status != outbox.StatusPending {
			continue
		}
		batch, err := loadBatch(entry.File, entry.BatchID)
		if err != nil {
			t.Fatal(err)
		}
		if batch.DataEpoch != nil {
			t.Fatalf("unknown origin must recover unstamped, got %d", *batch.DataEpoch)
		}
	}
}

// ---------------------------------------------------------------------------
// Reset API client
// ---------------------------------------------------------------------------

func setupResetStore(t *testing.T, dataEpoch int64) statedir.Store {
	t.Helper()
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{
		ServerURL:         "http://unused",
		DeviceID:          "dev-1",
		DeviceSecret:      strings.Repeat("a", 64),
		ApplicationID:     "app-1",
		ExternalSubjectID: "sub-1",
		DataEpoch:         dataEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestFetchUsageResetPlan(t *testing.T) {
	store := setupResetStore(t, 0)
	firstDay, lastDay := "2026-01-05", "2026-11-09"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/devices/usage-reset-plan" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusNotFound, map[string]any{})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-1."+strings.Repeat("a", 64) {
			t.Errorf("missing device bearer auth: %q", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{
			"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"dataEpoch": 2, "consentRevision": 9, "recordCount": 4321,
			"firstDay": firstDay, "lastDay": lastDay,
		}})
	}))
	defer server.Close()
	plan, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DeviceID != "dev-1" || plan.DataEpoch != 2 || plan.ConsentRevision != 9 || plan.RecordCount != 4321 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if plan.FirstDay == nil || *plan.FirstDay != firstDay || plan.LastDay == nil || *plan.LastDay != lastDay {
		t.Fatalf("unexpected day range: %#v", plan)
	}
}

func TestFetchUsageResetPlanNullableDays(t *testing.T) {
	store := setupResetStore(t, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{
			"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"dataEpoch": 0, "consentRevision": 1, "recordCount": 0,
			"firstDay": nil, "lastDay": nil,
		}})
	}))
	defer server.Close()
	plan, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if plan.FirstDay != nil || plan.LastDay != nil {
		t.Fatalf("empty device must report null days, got %#v", plan)
	}
}

func TestFetchUsageResetPlanForeignDeviceRefused(t *testing.T) {
	store := setupResetStore(t, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{
			"deviceId": "dev-other", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"dataEpoch": 1, "consentRevision": 1, "recordCount": 1,
		}})
	}))
	defer server.Close()
	_, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL})
	if !errors.Is(err, ErrDeviceUnauthorized) {
		t.Fatalf("a foreign device plan must fail with ErrDeviceUnauthorized, got %v", err)
	}
}

func TestFetchUsageResetPlanReflectedSecretRefused(t *testing.T) {
	store := setupResetStore(t, 0)
	secret := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{
			"deviceId": "dev-1", "applicationId": "app-" + secret, "externalSubjectId": "sub-1",
			"dataEpoch": 1, "consentRevision": 1, "recordCount": 1,
		}})
	}))
	defer server.Close()
	_, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL})
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("a reflected secret must fail with ErrSelfProtocol, got %v", err)
	}
}

func TestFetchUsageResetPlanMissingObjectFails(t *testing.T) {
	store := setupResetStore(t, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer server.Close()
	_, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL})
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("a missing plan object must fail with ErrSelfProtocol, got %v", err)
	}
}

func TestRequestUsageReset(t *testing.T) {
	store := setupResetStore(t, 2)
	var body map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices/usage-reset" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusNotFound, map[string]any{})
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"reset": map[string]any{
			"requestId": "req-42", "deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"previousDataEpoch": 2, "dataEpoch": 3, "consentRevision": 10, "subjectGeneration": 1,
			"changeSequence": 77, "resetAt": "2026-11-10T05:00:00Z", "replay": false, "deletedRecords": 4321,
		}})
	}))
	defer server.Close()
	reset, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
		RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The request body must carry the CAS values verbatim.
	var sent UsageResetRequest
	if err := json.Unmarshal(body["requestId"], &sent.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body["expectedDataEpoch"], &sent.ExpectedDataEpoch); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body["expectedConsentRevision"], &sent.ExpectedConsentRevision); err != nil {
		t.Fatal(err)
	}
	if sent != (UsageResetRequest{RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10}) {
		t.Fatalf("unexpected request body: %#v", sent)
	}
	if reset.RequestID != "req-42" || reset.PreviousDataEpoch != 2 || reset.DataEpoch != 3 ||
		reset.DeletedRecords != 4321 || reset.ChangeSequence != 77 || reset.Replay {
		t.Fatalf("unexpected reset receipt: %#v", reset)
	}
	// The client must not touch local state: installing the epoch is the
	// recollect driver's journal transition.
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DataEpoch != 2 {
		t.Fatalf("RequestUsageReset must not advance the local epoch, got %d", saved.DataEpoch)
	}
}

func TestRequestUsageResetConflict(t *testing.T) {
	store := setupResetStore(t, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{
			"code": "epoch_mismatch", "message": "server free text never echoed",
		}})
	}))
	defer server.Close()
	_, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
		RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
	})
	if !errors.Is(err, ErrResetConflict) {
		t.Fatalf("HTTP 409 must map to ErrResetConflict, got %v", err)
	}
}

func TestRequestUsageResetRevoked(t *testing.T) {
	store := setupResetStore(t, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "device_revoked"}})
	}))
	defer server.Close()
	_, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
		RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
	})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("a revoked device must fail with ErrDeviceRevoked, got %v", err)
	}
}

func TestRequestUsageResetRequestIDMismatchRefused(t *testing.T) {
	store := setupResetStore(t, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"reset": map[string]any{
			"requestId": "req-other", "deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"previousDataEpoch": 2, "dataEpoch": 3, "consentRevision": 10,
			"resetAt": "2026-11-10T05:00:00Z", "deletedRecords": 1,
		}})
	}))
	defer server.Close()
	_, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
		RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
	})
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("a receipt naming another request id must fail with ErrSelfProtocol, got %v", err)
	}
}

func TestRequestUsageResetValidatesRequestID(t *testing.T) {
	store := setupResetStore(t, 0)
	for _, id := range []string{"", "   ", "has space", "has/slash", strings.Repeat("x", 129)} {
		if _, err := RequestUsageReset(t.Context(), store, Options{}, UsageResetRequest{RequestID: id}); err == nil {
			t.Fatalf("request id %q must be rejected", id)
		}
	}
	if _, err := RequestUsageReset(t.Context(), store, Options{}, UsageResetRequest{RequestID: "req-42", ExpectedDataEpoch: -1}); err == nil {
		t.Fatal("a negative expected epoch must be rejected")
	}
}

func TestCompleteUsageReset(t *testing.T) {
	store := setupResetStore(t, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/devices/usage-reset/req-42/complete" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusNotFound, map[string]any{})
			return
		}
		var body struct {
			DataEpoch int64 `json:"dataEpoch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.DataEpoch != 3 {
			t.Fatalf("completion must carry the new epoch 3, got %d", body.DataEpoch)
		}
		writeJSON(w, http.StatusOK, map[string]any{"completion": map[string]any{
			"requestId": "req-42", "deviceId": "dev-1", "dataEpoch": 3,
			"changeSequence": 91, "completedAt": "2026-11-10T06:00:00Z", "replay": false,
		}})
	}))
	defer server.Close()
	completion, err := CompleteUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetCompletionRequest{
		RequestID: "req-42", DataEpoch: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completion.RequestID != "req-42" || completion.DataEpoch != 3 || completion.ChangeSequence != 91 {
		t.Fatalf("unexpected completion: %#v", completion)
	}
}

func TestCompleteUsageResetEpochMismatchRefused(t *testing.T) {
	store := setupResetStore(t, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"completion": map[string]any{
			"requestId": "req-42", "deviceId": "dev-1", "dataEpoch": 4,
			"changeSequence": 91, "completedAt": "2026-11-10T06:00:00Z",
		}})
	}))
	defer server.Close()
	_, err := CompleteUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetCompletionRequest{
		RequestID: "req-42", DataEpoch: 3,
	})
	if !errors.Is(err, ErrSelfProtocol) {
		t.Fatalf("an epoch-mismatching completion must fail with ErrSelfProtocol, got %v", err)
	}
}

func TestCompleteUsageResetConflict(t *testing.T) {
	store := setupResetStore(t, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "not_latest_task"}})
	}))
	defer server.Close()
	_, err := CompleteUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetCompletionRequest{
		RequestID: "req-42", DataEpoch: 3,
	})
	if !errors.Is(err, ErrResetConflict) {
		t.Fatalf("HTTP 409 must map to ErrResetConflict, got %v", err)
	}
}

func TestResetClientRequiresBoundDevice(t *testing.T) {
	store := statedir.New(t.TempDir())
	if _, err := FetchUsageResetPlan(t.Context(), store, Options{}); err == nil {
		t.Fatal("an unbound device must fail the plan fetch")
	}
	if _, err := RequestUsageReset(t.Context(), store, Options{}, UsageResetRequest{RequestID: "req-1"}); err == nil {
		t.Fatal("an unbound device must fail the reset request")
	}
	if _, err := CompleteUsageReset(t.Context(), store, Options{}, UsageResetCompletionRequest{RequestID: "req-1"}); err == nil {
		t.Fatal("an unbound device must fail the completion")
	}
}

// TestRequestUsageResetImpossibleEpochTransitionRefused covers the
// stricter receipt validation: the reset must advance the epoch by
// exactly one and never touch the consent revision the CAS matched.
func TestRequestUsageResetImpossibleEpochTransitionRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(reset map[string]any)
	}{
		{"epoch skips ahead", func(r map[string]any) { r["dataEpoch"] = 5 }},
		{"epoch does not advance", func(r map[string]any) { r["dataEpoch"] = 2 }},
		{"zero epoch", func(r map[string]any) { r["dataEpoch"] = 0; r["previousDataEpoch"] = -1 }},
		{"consent revision moved", func(r map[string]any) { r["consentRevision"] = 11 }},
		{"zero reset timestamp", func(r map[string]any) { r["resetAt"] = "0001-01-01T00:00:00Z" }},
		{"negative change sequence", func(r map[string]any) { r["changeSequence"] = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := setupResetStore(t, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reset := map[string]any{
					"requestId": "req-42", "deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
					"previousDataEpoch": 2, "dataEpoch": 3, "consentRevision": 10,
					"subjectGeneration": 1, "changeSequence": 77, "resetAt": "2026-11-10T05:00:00Z",
					"replay": false, "deletedRecords": 10,
				}
				tc.mutate(reset)
				writeJSON(w, http.StatusOK, map[string]any{"reset": reset})
			}))
			defer server.Close()
			_, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
				RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
			})
			if !errors.Is(err, ErrSelfProtocol) {
				t.Fatalf("an inconsistent receipt must fail with ErrSelfProtocol, got %v", err)
			}
		})
	}
}

// TestCompleteUsageResetInconsistentReceiptRefused covers the stricter
// completion validation.
func TestCompleteUsageResetInconsistentReceiptRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(completion map[string]any)
	}{
		{"zero completion timestamp", func(c map[string]any) { c["completedAt"] = "0001-01-01T00:00:00Z" }},
		{"negative change sequence", func(c map[string]any) { c["changeSequence"] = -3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := setupResetStore(t, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				completion := map[string]any{
					"requestId": "req-42", "deviceId": "dev-1", "dataEpoch": 3,
					"changeSequence": 91, "completedAt": "2026-11-10T06:00:00Z", "replay": false,
				}
				tc.mutate(completion)
				writeJSON(w, http.StatusOK, map[string]any{"completion": completion})
			}))
			defer server.Close()
			_, err := CompleteUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetCompletionRequest{
				RequestID: "req-42", DataEpoch: 3,
			})
			if !errors.Is(err, ErrSelfProtocol) {
				t.Fatalf("an inconsistent completion must fail with ErrSelfProtocol, got %v", err)
			}
		})
	}
}

// TestRequestUsageResetPositiveFieldRequirements pins the strict
// critical-field rules: subject generation and change sequence must be
// positive, and the expected consent revision must be positive before
// the request is even sent.
func TestRequestUsageResetPositiveFieldRequirements(t *testing.T) {
	// Pre-send validation: a non-positive expected revision fails
	// locally with zero HTTP traffic.
	store := setupResetStore(t, 0)
	if _, err := RequestUsageReset(t.Context(), store, Options{}, UsageResetRequest{
		RequestID: "req-42", ExpectedDataEpoch: 0, ExpectedConsentRevision: 0,
	}); err == nil {
		t.Fatal("a non-positive expected consent revision must be rejected before sending")
	}
	cases := []struct {
		name   string
		mutate func(reset map[string]any)
	}{
		{"zero subject generation", func(r map[string]any) { r["subjectGeneration"] = 0 }},
		{"zero change sequence", func(r map[string]any) { r["changeSequence"] = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := setupResetStore(t, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reset := map[string]any{
					"requestId": "req-42", "deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
					"previousDataEpoch": 2, "dataEpoch": 3, "consentRevision": 10,
					"subjectGeneration": 1, "changeSequence": 77, "resetAt": "2026-11-10T05:00:00Z",
					"replay": false, "deletedRecords": 10,
				}
				tc.mutate(reset)
				writeJSON(w, http.StatusOK, map[string]any{"reset": reset})
			}))
			defer server.Close()
			_, err := RequestUsageReset(t.Context(), store, Options{ServerURL: server.URL}, UsageResetRequest{
				RequestID: "req-42", ExpectedDataEpoch: 2, ExpectedConsentRevision: 10,
			})
			if !errors.Is(err, ErrSelfProtocol) {
				t.Fatalf("want ErrSelfProtocol, got %v", err)
			}
		})
	}
}

// TestFetchUsageResetPlanRequiresPositiveRevision pins the plan's
// critical-field rule.
func TestFetchUsageResetPlanRequiresPositiveRevision(t *testing.T) {
	store := setupResetStore(t, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{
			"deviceId": "dev-1", "applicationId": "app-1", "externalSubjectId": "sub-1",
			"dataEpoch": 2, "consentRevision": 0, "recordCount": 5,
		}})
	}))
	defer server.Close()
	if _, err := FetchUsageResetPlan(t.Context(), store, Options{ServerURL: server.URL}); !errors.Is(err, ErrSelfProtocol) {
		t.Fatal("a plan without a positive consent revision must be refused")
	}
}
