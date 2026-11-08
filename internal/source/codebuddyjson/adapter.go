package codebuddyjson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// Adapter exposes the CodeBuddy conversation index source to the collector
// pipeline.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.CodeBuddyJSONSource,
		Description: "CodeBuddy conversation index JSON (per-request usage)",
		Load: func(opt adapter.Options) (adapter.LoadResult, error) {
			return loadRecordsContext(opt.ContextOrBackground(), opt.Input)
		},
		FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
			ctx := opt.ContextOrBackground()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if strings.TrimSpace(opt.StateDir) == "" {
				return records, nil
			}
			return filterKnownRecordsContext(ctx, opt.StateDir, records)
		},
	}
}

// filterKnownRecordsContext checks immutable outbox and quarantine records,
// so repeated full rescans cannot enqueue the same request twice. The context
// is consulted at coarse boundaries (entry, per outbox batch, per stored
// record, before the quarantine load, per quarantine entry, per fresh
// record); on cancellation it returns ctx.Err() (matchable with
// errors.Is(err, context.Canceled) or errors.Is(err, context.DeadlineExceeded))
// and no partial result — the fresh slice accumulated so far is discarded, so
// a filter cut short never exports a prefix of the scan. A nil
// Options.Context reaches here as context.Background() via
// ContextOrBackground and keeps the exact pre-cancellation behavior.
func filterKnownRecordsContext(ctx context.Context, stateDir string, records []adapter.Record) ([]adapter.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	known := make(map[string][]byte)
	remember := func(raw []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var record adapter.Record
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		key := adapter.StringField(record, "recordKey")
		if key == "" {
			return fmt.Errorf("stored CodeBuddy record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored CodeBuddy record %s has conflicting content", key)
		}
		known[key] = canonical
		return nil
	}
	ledger, err := outbox.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range ledger.Batches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Source != adapter.CodeBuddyJSONSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown CodeBuddy outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read CodeBuddy history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("CodeBuddy history batch identity mismatch")
		}
		for _, record := range batch.Records {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := remember(record); err != nil {
				return nil, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Source != adapter.CodeBuddyJSONSource {
			continue
		}
		if err := remember(entry.Record); err != nil {
			return nil, err
		}
	}
	fresh := make([]adapter.Record, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := adapter.StringField(record, "recordKey")
		canonical, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if previous, exists := known[key]; exists {
			if !bytes.Equal(previous, canonical) {
				return nil, fmt.Errorf("CodeBuddy record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}
