package bind

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"toktrail-collector/internal/local/statedir"
)

// newEpochBindServer serves a bind receipt that always reports the given
// data epoch and echoes the request's application/subject identity.
func newEpochBindServer(t *testing.T, dataEpoch *int64, calls *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			*calls++
		}
		var got bindRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		device := map[string]any{
			"deviceId":          "dev-1",
			"applicationId":     got.ApplicationID,
			"externalSubjectId": got.ExternalSubjectID,
			"deviceName":        got.DeviceName,
			"platform":          got.Platform,
			"consentRevision":   1,
			"boundAt":           "2026-11-10T10:00:00Z",
			"replay":            false,
		}
		if dataEpoch != nil {
			device["dataEpoch"] = *dataEpoch
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": device})
	}))
}

func bindEpochOptions(serverURL string) Options {
	return Options{
		ServerURL:         serverURL,
		Ticket:            "ticket-1",
		ApplicationID:     "leaderboard-local",
		ExternalSubjectID: "user-1",
		DeviceName:        "MacBook",
	}
}

func TestInitialBindAdoptsReceiptDataEpoch(t *testing.T) {
	server := newEpochBindServer(t, epochPtr(5), nil)
	defer server.Close()
	store := statedir.New(t.TempDir())
	if _, err := Run(t.Context(), store, bindEpochOptions(server.URL)); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DataEpoch != 5 {
		t.Fatalf("initial bind must adopt the receipt epoch 5, got %d", saved.DataEpoch)
	}
}

func TestInitialBindLegacyServerEpochZero(t *testing.T) {
	// No dataEpoch field at all: an old server, or a new server's
	// initial epoch 0 — both land on the local epoch 0.
	server := newEpochBindServer(t, nil, nil)
	defer server.Close()
	store := statedir.New(t.TempDir())
	if _, err := Run(t.Context(), store, bindEpochOptions(server.URL)); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DataEpoch != 0 {
		t.Fatalf("a legacy receipt must bind at epoch 0, got %d", saved.DataEpoch)
	}
}

func TestRebindKeepsLocalEpoch(t *testing.T) {
	// An already-bound state (epoch 2) re-binds against a server now
	// reporting epoch 7: the local epoch must NOT advance — the blocked
	// state is deliberate, so the old outbox can never be relabeled with
	// the new epoch. Only force-recollect resolves the mismatch.
	calls := 0
	server := newEpochBindServer(t, epochPtr(7), &calls)
	defer server.Close()
	store := statedir.New(t.TempDir())
	if err := store.Save(statedir.DeviceState{
		ServerURL: server.URL, DeviceID: "dev-1", DeviceSecret: "old-secret",
		ApplicationID: "leaderboard-local", ExternalSubjectID: "user-1",
		BindRequestID: "req-old", DataEpoch: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), store, bindEpochOptions(server.URL)); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DataEpoch != 2 {
		t.Fatalf("re-bind must keep the local epoch 2, got %d", saved.DataEpoch)
	}
	if calls != 1 {
		t.Fatalf("exactly one bind round trip expected, got %d", calls)
	}
}

func TestInitialBindRejectsNegativeReceiptEpoch(t *testing.T) {
	// A hostile receipt with a negative epoch must not poison the state;
	// the local epoch stays 0 (defensive: the contract says nonnegative).
	server := newEpochBindServer(t, epochPtr(-3), nil)
	defer server.Close()
	store := statedir.New(t.TempDir())
	if _, err := Run(t.Context(), store, bindEpochOptions(server.URL)); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.DataEpoch != 0 {
		t.Fatalf("a negative receipt epoch must clamp to 0, got %d", saved.DataEpoch)
	}
}

func epochPtr(v int64) *int64 { return &v }
