package resync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/syncclient"
)

func TestArchiveChildKeepsParentDataEpoch(t *testing.T) {
	dir := t.TempDir()
	epoch := int64(7)
	kept := json.RawMessage(`{"recordKey":"keep","kind":"delta","occurredAt":"2026-11-10T00:00:00Z","tool":"Codex","input":"1","output":"1"}`)
	removed := json.RawMessage(`{"recordKey":"remove","kind":"delta","occurredAt":"2020-01-01T00:00:00Z","tool":"Codex","input":"2","output":"1"}`)
	batch := syncclient.BatchRequest{BatchID: "parent", Records: []json.RawMessage{kept, removed}, DataEpoch: &epoch}
	targets, err := deriveUploads(dir, jobBatch{BatchID: "parent", File: filepath.Join(dir, "parent.json"), Source: "codex-jsonl"}, batch, []json.RawMessage{kept}, liveScope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets=%d", len(targets))
	}
	payload, err := os.ReadFile(targets[0].File)
	if err != nil {
		t.Fatal(err)
	}
	var child syncclient.BatchRequest
	if err := json.Unmarshal(payload, &child); err != nil {
		t.Fatal(err)
	}
	if child.DataEpoch == nil || *child.DataEpoch != epoch {
		t.Fatal("scope-filtered archive child lost the original epoch")
	}
}
