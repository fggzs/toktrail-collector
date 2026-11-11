package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
)

const (
	MaxBatchRecords      = 500
	MaxBatchPayloadBytes = 768 * 1024 // 786432 bytes
)

type PreparedExport struct {
	BatchID string
	Output  string
	Records int
	Payload []byte
	// OldestAt/NewestAt bound the records' occurredAt times (nil when no
	// record carries a valid timestamp). The upload queue uses them to give
	// recent data priority without ever reordering the batches themselves.
	OldestAt *time.Time
	NewestAt *time.Time
	// ScanStates are the per-file content states this scan observed. They
	// are persisted by the commit caller only after every chunk of this
	// export is committed (see internal/local/scanledger).
	ScanStates map[string]scanledger.FileState
	// MessageUpdates carries the per-message pending intervals an interval
	// source (claude-code-jsonl) produced alongside this batch; the commit
	// transaction must persist them together with the batch.
	MessageUpdates []progress.MessagePendingUpdate
}

func (p *Pipeline) PrepareExport(opt adapter.Options) (PreparedExport, error) {
	opt = withDefaults(opt)
	if err := p.RecoverPendingFilter(opt.StateDir); err != nil {
		return PreparedExport{}, err
	}
	loaded, err := p.LoadSource(opt)
	if err != nil {
		return PreparedExport{}, err
	}
	return p.PrepareFromLoaded(opt, loaded)
}

// RecoverPendingFilter completes any history-filter transaction an earlier
// crash left half-applied. It must run BEFORE any adapter loads records
// (adapters read the message baselines and, through their export filter, the
// quarantine store, and both must reflect the converged post-recovery state).
// A concurrent scan phase calls it once, sequentially, before starting its
// workers.
func (p *Pipeline) RecoverPendingFilter(stateDir string) error {
	return recoverPendingFilterTxn(stateDir)
}

// LoadSource reads and parses one source without filtering. It is read-only
// apart from an adapter's own content caches, so several sources may be
// loaded concurrently; filtering, which may rewrite the quarantine store,
// stays serialized in PrepareFromLoaded.
func (p *Pipeline) LoadSource(opt adapter.Options) (adapter.LoadResult, error) {
	opt = withDefaults(opt)
	ctx := opt.ContextOrBackground()
	if err := ctx.Err(); err != nil {
		return adapter.LoadResult{}, err
	}
	if err := p.validateInput(opt); err != nil {
		return adapter.LoadResult{}, err
	}
	loaded, err := p.registry.LoadRecordsForSource(opt)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return adapter.LoadResult{}, err
	}
	return loaded, nil
}

// PrepareFromLoaded applies the source filters to an already loaded result
// and produces the export payload. It is the state-touching half of
// preparation (history cutoff, quarantine), so callers run it serially.
func (p *Pipeline) PrepareFromLoaded(opt adapter.Options, loaded adapter.LoadResult) (PreparedExport, error) {
	opt = withDefaults(opt)
	ctx := opt.ContextOrBackground()
	if err := ctx.Err(); err != nil {
		return PreparedExport{}, err
	}
	if strings.TrimSpace(opt.Output) == "" {
		return PreparedExport{}, errors.New("missing output file")
	}
	batchID := strings.TrimSpace(opt.BatchID)
	if batchID == "" {
		batchID = "local-" + time.Now().UTC().Format("20060102T150405Z")
	}
	var err error
	records := loaded.Records
	plugin, _ := p.registry.Lookup(opt.Source)
	if plugin.FilterForExport != nil {
		records, err = plugin.FilterForExport(opt, records)
		if err != nil {
			return PreparedExport{}, err
		}
	}
	messageUpdates := loaded.MessageUpdates
	records, messageUpdates, err = FilterHistoryCutoff(opt, records, messageUpdates)
	if err != nil {
		return PreparedExport{}, err
	}
	if err := ctx.Err(); err != nil {
		return PreparedExport{}, err
	}
	valid := make([]adapter.Record, 0, len(records))
	var oldestAt, newestAt *time.Time
	for idx, record := range records {
		if err := ctx.Err(); err != nil {
			return PreparedExport{}, err
		}
		if err := adapter.ValidateRecord(record); err != nil {
			return PreparedExport{}, fmt.Errorf("record %d invalid: %w", idx, err)
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return PreparedExport{}, fmt.Errorf("marshal record %d: %w", idx, err)
		}
		if len(raw) > MaxBatchPayloadBytes {
			return PreparedExport{}, fmt.Errorf("record %d exceeds maximum allowed size (%d bytes > %d bytes); failing closed", idx, len(raw), MaxBatchPayloadBytes)
		}
		valid = append(valid, record)
		if at, ok := adapter.OccurredAt(record); ok {
			if oldestAt == nil || at.Before(*oldestAt) {
				clone := at
				oldestAt = &clone
			}
			if newestAt == nil || at.After(*newestAt) {
				clone := at
				newestAt = &clone
			}
		}
	}
	var epoch *int64
	if opt.StateDir != "" {
		state, loadErr := statedir.New(opt.StateDir).Load()
		if loadErr != nil {
			return PreparedExport{}, fmt.Errorf("read export data epoch: %w", loadErr)
		}
		if state.DataEpoch < 0 {
			return PreparedExport{}, errors.New("invalid export data epoch")
		}
		if state.DataEpoch > 0 {
			value := state.DataEpoch
			epoch = &value
		}
	}
	payload, err := json.MarshalIndent(adapter.Batch{BatchID: batchID, Records: valid, DataEpoch: epoch}, "", "  ")
	if err != nil {
		return PreparedExport{}, err
	}
	if err := ctx.Err(); err != nil {
		return PreparedExport{}, err
	}
	return PreparedExport{BatchID: batchID, Output: opt.Output, Records: len(valid), Payload: append(payload, '\n'), MessageUpdates: messageUpdates, ScanStates: loaded.ScanStates, OldestAt: oldestAt, NewestAt: newestAt}, nil
}

// SplitPreparedExport partitions a PreparedExport into chunks that each satisfy
// <= 500 records and <= 768 KiB serialized compact envelope body.
// If the export already satisfies both bounds, it is returned as a single chunk.
// MessageUpdates are partitioned per chunk according to each record's recordKey.
// Any single record exceeding 768 KiB fails closed.
func (p *Pipeline) SplitPreparedExport(prepared PreparedExport) ([]PreparedExport, error) {
	if prepared.Records == 0 {
		return []PreparedExport{prepared}, nil
	}
	var batch adapter.Batch
	if err := json.Unmarshal(prepared.Payload, &batch); err != nil {
		return nil, fmt.Errorf("unmarshal prepared batch payload: %w", err)
	}
	if len(batch.Records) == 0 {
		return []PreparedExport{prepared}, nil
	}

	// Validate each record and measure compact sizes
	compactRecords := make([][]byte, len(batch.Records))
	recordKeys := make([]string, len(batch.Records))
	for idx, record := range batch.Records {
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("marshal record %d: %w", idx, err)
		}
		if len(raw) > MaxBatchPayloadBytes {
			return nil, fmt.Errorf("record %d exceeds maximum allowed size (%d bytes > %d bytes); failing closed", idx, len(raw), MaxBatchPayloadBytes)
		}
		compactRecords[idx] = raw
		if key, ok := record["recordKey"].(string); ok {
			recordKeys[idx] = key
		}
	}

	// Check if already within limits as a single batch
	compactBatch, err := json.Marshal(adapter.Batch{BatchID: prepared.BatchID, Records: batch.Records, DataEpoch: batch.DataEpoch})
	if err == nil && len(batch.Records) <= MaxBatchRecords && len(compactBatch) <= MaxBatchPayloadBytes {
		return []PreparedExport{prepared}, nil
	}

	// Partition records into chunks
	envelope, err := json.Marshal(adapter.Batch{BatchID: prepared.BatchID + "-part-0001", Records: []adapter.Record{}, DataEpoch: batch.DataEpoch})
	if err != nil {
		return nil, fmt.Errorf("marshal split envelope: %w", err)
	}
	dummyOverhead := len(envelope)
	var chunks [][]adapter.Record
	var chunkKeysList [][]string

	var currentChunk []adapter.Record
	var currentKeys []string
	currentSize := dummyOverhead

	for idx, recBytes := range compactRecords {
		recSize := len(recBytes)
		if dummyOverhead+recSize > MaxBatchPayloadBytes {
			return nil, fmt.Errorf("record %d with envelope exceeds %d bytes; failing closed", idx, MaxBatchPayloadBytes)
		}
		projected := currentSize + recSize
		if len(currentChunk) > 0 {
			projected += 1 // comma
		}
		if len(currentChunk) > 0 && (len(currentChunk) >= MaxBatchRecords || projected > MaxBatchPayloadBytes) {
			chunks = append(chunks, currentChunk)
			chunkKeysList = append(chunkKeysList, currentKeys)
			currentChunk = nil
			currentKeys = nil
			currentSize = dummyOverhead
			projected = dummyOverhead + recSize
		}
		currentChunk = append(currentChunk, batch.Records[idx])
		currentKeys = append(currentKeys, recordKeys[idx])
		currentSize = projected
	}
	if len(currentChunk) > 0 {
		chunks = append(chunks, currentChunk)
		chunkKeysList = append(chunkKeysList, currentKeys)
	}

	outDir := filepath.Dir(prepared.Output)
	result := make([]PreparedExport, len(chunks))
	for i, chunk := range chunks {
		suffix := fmt.Sprintf("-part-%04d", i+1)
		base := prepared.BatchID
		if len(base)+len(suffix) > 128 {
			h := sha256.Sum256([]byte(prepared.BatchID))
			digest := hex.EncodeToString(h[:])[:8]
			maxPrefix := 128 - len(suffix) - 1 - len(digest)
			if maxPrefix < 1 {
				maxPrefix = 1
			}
			base = base[:maxPrefix] + "-" + digest
		}
		childID := base + suffix
		childOutput := filepath.Join(outDir, childID+".json")

		// Verify compact payload limit
		compact, err := json.Marshal(adapter.Batch{BatchID: childID, Records: chunk, DataEpoch: batch.DataEpoch})
		if err != nil {
			return nil, fmt.Errorf("marshal child batch %s: %w", childID, err)
		}
		if len(compact) > MaxBatchPayloadBytes {
			return nil, fmt.Errorf("child batch %s exceeds %d bytes; failing closed", childID, MaxBatchPayloadBytes)
		}

		payload, err := json.MarshalIndent(adapter.Batch{BatchID: childID, Records: chunk, DataEpoch: batch.DataEpoch}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("indent child batch %s: %w", childID, err)
		}

		// Subset MessageUpdates by recordKey
		keySet := make(map[string]bool, len(chunkKeysList[i]))
		for _, k := range chunkKeysList[i] {
			if k != "" {
				keySet[k] = true
			}
		}
		var childUpdates []progress.MessagePendingUpdate
		for _, u := range prepared.MessageUpdates {
			if keySet[u.RecordKey] {
				childUpdates = append(childUpdates, u)
			}
		}

		result[i] = PreparedExport{
			BatchID:        childID,
			Output:         childOutput,
			Records:        len(chunk),
			Payload:        append(payload, '\n'),
			MessageUpdates: childUpdates,
		}
	}

	return result, nil
}

func (p *Pipeline) WritePreparedExport(prepared PreparedExport) error {
	if err := os.WriteFile(prepared.Output, prepared.Payload, 0o600); err != nil {
		return err
	}
	return nil
}

func PrepareExport(opt adapter.Options) (PreparedExport, error) { return production.PrepareExport(opt) }

// RecoverPendingFilter completes any half-applied history-filter transaction
// through the production registry.
func RecoverPendingFilter(stateDir string) error { return production.RecoverPendingFilter(stateDir) }

// LoadSource reads and parses one source through the production registry,
// without filtering. Safe to call concurrently for different sources.
func LoadSource(opt adapter.Options) (adapter.LoadResult, error) {
	return production.LoadSource(opt)
}

// PrepareFromLoaded filters an already loaded result through the production
// registry and produces the export payload.
func PrepareFromLoaded(opt adapter.Options, loaded adapter.LoadResult) (PreparedExport, error) {
	return production.PrepareFromLoaded(opt, loaded)
}
func SplitPreparedExport(prepared PreparedExport) ([]PreparedExport, error) {
	return production.SplitPreparedExport(prepared)
}
func WritePreparedExport(prepared PreparedExport) error {
	return production.WritePreparedExport(prepared)
}
