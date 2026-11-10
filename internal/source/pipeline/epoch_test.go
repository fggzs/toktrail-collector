package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

func TestExportFreezesDataEpochAndSplitRetainsIt(t *testing.T) {
	dir := t.TempDir()
	if err := statedir.New(dir).Save(statedir.DeviceState{DataEpoch: 3}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(input, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	var records []adapter.Record
	for i := 0; i < 501; i++ {
		records = append(records, adapter.Record{
			"recordKey": fmt.Sprintf("epoch-%d", i), "kind": "delta",
			"occurredAt": "2026-11-10T00:00:00Z", "tool": "Codex", "model": "model-corrected",
			"input": "10", "output": "2", "cacheRead": "0", "cacheWrite": "0",
			"adapterVersion": "synthetic", "sourceType": adapter.UsageJSONSource,
		})
	}
	prepared, err := PrepareFromLoaded(adapter.Options{Source: adapter.UsageJSONSource, Input: input, StateDir: dir, Output: filepath.Join(dir, "batch.json"), BatchID: "epoch-batch"}, adapter.LoadResult{Records: records})
	if err != nil {
		t.Fatal(err)
	}
	// Split must use the prepared batch's epoch, not a newly fetched state.
	if err := statedir.New(dir).Save(statedir.DeviceState{DataEpoch: 4}); err != nil {
		t.Fatal(err)
	}
	parts, err := SplitPreparedExport(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("parts = %d", len(parts))
	}
	for _, part := range parts {
		var batch adapter.Batch
		if err := json.Unmarshal(part.Payload, &batch); err != nil {
			t.Fatal(err)
		}
		if batch.DataEpoch == nil || *batch.DataEpoch != 3 {
			t.Fatalf("split lost frozen epoch: %s", part.Payload)
		}
	}
}

func TestEpochZeroExportPreservesLegacyEnvelope(t *testing.T) {
	dir := t.TempDir()
	prepared, err := PrepareFromLoaded(adapter.Options{Source: adapter.UsageJSONSource, Input: "synthetic", StateDir: dir, Output: filepath.Join(dir, "b.json"), BatchID: "legacy"}, adapter.LoadResult{})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(prepared.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, exists := envelope["dataEpoch"]; exists {
		t.Fatal("epoch-zero legacy export changed wire envelope")
	}
}
