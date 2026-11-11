package statedir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataEpochRoundTrips(t *testing.T) {
	store := New(t.TempDir())
	if err := store.Save(DeviceState{
		ServerURL: "http://unused", DeviceID: "dev-1", DeviceSecret: "s", DataEpoch: 3,
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DataEpoch != 3 {
		t.Fatalf("data epoch must round-trip, got %d", loaded.DataEpoch)
	}
}

func TestDataEpochDefaultsToZeroForLegacyState(t *testing.T) {
	// A pre-epoch state file carries no dataEpoch field; loading it must
	// yield the legacy epoch 0, not an error.
	dir := t.TempDir()
	legacy := `{"serverUrl":"http://unused","deviceId":"dev-1","deviceSecret":"s","consentRevision":7,"boundAt":"2026-10-20T10:00:00Z","updatedAt":"2026-10-20T10:00:00Z"}`
	if err := writeFileForTest(filepath.Join(dir, stateFileName), legacy); err != nil {
		t.Fatal(err)
	}
	loaded, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DataEpoch != 0 {
		t.Fatalf("legacy state must load at epoch 0, got %d", loaded.DataEpoch)
	}
}

func TestSaveOmitsZeroEpochForLegacyCompatibility(t *testing.T) {
	// Saving an epoch-0 state keeps the historical file shape: no
	// dataEpoch field, so downgrades and diff tools see no churn.
	dir := t.TempDir()
	store := New(dir)
	if err := store.Save(DeviceState{DeviceID: "dev-1", DeviceSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Fatal("save must stamp UpdatedAt")
	}
	if loaded.DataEpoch != 0 {
		t.Fatalf("fresh state must be epoch 0, got %d", loaded.DataEpoch)
	}
}

func TestDirExposesStateDirectory(t *testing.T) {
	dir := t.TempDir()
	if got := New(dir).Dir(); got != dir {
		t.Fatalf("Dir must return the state directory, got %q", got)
	}
	if got := New("").Dir(); got != "" {
		t.Fatalf("an empty store must expose an empty dir, got %q", got)
	}
	if got := New("  /tmp/x  ").Dir(); got != "/tmp/x" {
		t.Fatalf("Dir must trim, got %q", got)
	}
}

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
