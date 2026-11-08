// Package codebuddyhistory collects token usage from local CodeBuddy IDE
// (CodeBuddy CN) session history. CodeBuddy stores one index.json per
// conversation under
//
//	~/AppData/Local/CodeBuddyExtension/Data/<userId>/CodeBuddyIDE/<userId>/history/<workspace>/<conversation>/index.json
//
// whose `requests[]` entries carry per-request usage counters. The adapter
// is passive: it only reads index.json files and never writes to the
// CodeBuddy directory. Conversation bodies (messages/*.json) are not read.
package codebuddyhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

const (
	codebuddyTool           = "CodeBuddy"
	codebuddyAdapterVersion = "codebuddy-history-v1"
	maxIssues               = 50
)

// requestUsage mirrors the usage object CodeBuddy records per request.
// Pointers keep "field absent" distinct from "field is zero": the adapter
// fails closed on absent core counters instead of coercing them to zero.
type requestUsage struct {
	InputTokens       *json.Number `json:"inputTokens"`
	OutputTokens      *json.Number `json:"outputTokens"`
	TotalTokens       *json.Number `json:"totalTokens"`
	LastTokens        *json.Number `json:"lastTokens"`
	CacheTokens       *json.Number `json:"cacheTokens"`
	CachedWriteTokens *json.Number `json:"cachedWriteTokens"`
	CachedMissTokens  *json.Number `json:"cachedMissTokens"`
	Credit            *json.Number `json:"credit"`
}

type requestEntry struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"`
	State     string        `json:"state"`
	StartedAt *json.Number  `json:"startedAt"`
	Usage     *requestUsage `json:"usage"`
}

type sessionIndexFile struct {
	Requests []requestEntry `json:"requests"`
}

// LoadRecords reads CodeBuddy session usage from an explicitly granted path.
// The path may be any ancestor of the history tree (typically
// ~/AppData/Local/CodeBuddyExtension/Data) or a single index.json file.
// Only completed requests are collected: running requests publish partial
// usage snapshots that would double count once the request completes, and
// canceled requests lack a startedAt timestamp. It keeps the historical
// uncancellable signature for direct callers; the adapter's Load passes its
// cancellation scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during discovery and once per file. On cancellation it returns ctx.Err()
// (matchable with errors.Is) and no partial result, so a scan cut short
// never exports half of the CodeBuddy usage.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	files, err := discoverSessionIndexes(ctx, root)
	if err != nil {
		return result, err
	}
	issue := func(file string, reason string) {
		result.Quarantined++
		if len(result.Issues) < maxIssues {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: 0, Reason: reason})
		}
	}
	records := make(map[string]adapter.Record)
	conflicts := make(map[string]bool)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		observations, err := parseSessionIndex(file)
		if err != nil {
			issue(file, err.Error())
			continue
		}
		for _, obs := range observations {
			if obs.Issue != "" {
				issue(file, obs.Issue)
				continue
			}
			rec := codebuddyRecord(obs)
			key := adapter.StringField(rec, "recordKey")
			if conflicts[key] {
				continue
			}
			if old, exists := records[key]; exists {
				if !sameRecord(old, rec) {
					delete(records, key)
					conflicts[key] = true
					issue(file, "conflicting usage for the same CodeBuddy request")
				}
				continue
			}
			records[key] = rec
		}
	}
	for _, record := range records {
		result.Records = append(result.Records, record)
	}
	sort.Slice(result.Records, func(i, j int) bool {
		a, b := result.Records[i], result.Records[j]
		if adapter.StringField(a, "occurredAt") == adapter.StringField(b, "occurredAt") {
			return adapter.StringField(a, "recordKey") < adapter.StringField(b, "recordKey")
		}
		return adapter.StringField(a, "occurredAt") < adapter.StringField(b, "occurredAt")
	})
	if len(result.Records) > 0 && len(result.Issues) < maxIssues {
		result.Issues = append(result.Issues, adapter.LineIssue{File: "", Line: 0, Reason: "CodeBuddy request indexes do not record model identifiers; model reported unknown"})
	}
	return result, nil
}

// discoverSessionIndexes returns every index.json whose parent directory
// sits inside a "history" directory: <any ancestor>/history/<workspace>/
// <conversation>/index.json. Hidden directories are skipped. A root that
// names a single index.json file is accepted directly. A missing root
// returns an error, matching the shared jsonl discovery behavior.
func discoverSessionIndexes(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := strings.TrimSpace(root)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if filepath.Base(clean) != "index.json" {
			return nil, fmt.Errorf("codebuddy-history input must be a directory or an index.json file")
		}
		return []string{clean}, nil
	}
	var files []string
	err = filepath.WalkDir(clean, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if d.IsDir() {
			if p != clean && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "index.json" || !d.Type().IsRegular() {
			return nil
		}
		// require .../history/<workspace>/<conversation>/index.json
		convDir := filepath.Dir(p)
		wsDir := filepath.Dir(convDir)
		if filepath.Base(filepath.Dir(wsDir)) != "history" {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// parseSessionIndex converts one index.json into per-request observations.
// The file is decoded strictly (json.Number, no unknown-shape guessing):
// malformed JSON quarantines the whole file; malformed single requests
// quarantine only that request.
func parseSessionIndex(file string) ([]codebuddyObservation, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var index sessionIndexFile
	if err := decoder.Decode(&index); err != nil {
		return nil, fmt.Errorf("invalid session index JSON")
	}
	var observations []codebuddyObservation
	conversationID := filepath.Base(filepath.Dir(file))
	for _, req := range index.Requests {
		// Only completed requests carry final usage. Running requests
		// publish partial snapshots (collecting them would double count
		// once the request completes) and canceled requests lack the
		// startedAt timestamp, so both are skipped without diagnostics.
		if req.State != "complete" {
			continue
		}
		if req.Usage == nil {
			continue
		}
		obs, reason := parseRequest(conversationID, req)
		if reason != "" {
			observations = append(observations, codebuddyObservation{File: file, Issue: reason})
			continue
		}
		observations = append(observations, obs)
	}
	return observations, nil
}

func parseRequest(conversationID string, req requestEntry) (codebuddyObservation, string) {
	if strings.TrimSpace(req.ID) == "" {
		return codebuddyObservation{}, "completed request without id"
	}
	if req.StartedAt == nil {
		return codebuddyObservation{}, "completed request without startedAt"
	}
	ms, ok := parseMillis(*req.StartedAt)
	if !ok {
		return codebuddyObservation{}, "invalid startedAt"
	}
	usage := req.Usage
	if usage.InputTokens == nil || usage.OutputTokens == nil || usage.CacheTokens == nil || usage.CachedMissTokens == nil {
		return codebuddyObservation{}, "completed request without complete token counters"
	}
	input, ok := parseUint(*usage.InputTokens)
	if !ok {
		return codebuddyObservation{}, "invalid inputTokens"
	}
	output, ok := parseUint(*usage.OutputTokens)
	if !ok {
		return codebuddyObservation{}, "invalid outputTokens"
	}
	cacheRead, ok := parseUint(*usage.CacheTokens)
	if !ok {
		return codebuddyObservation{}, "invalid cacheTokens"
	}
	cacheMiss, ok := parseUint(*usage.CachedMissTokens)
	if !ok {
		return codebuddyObservation{}, "invalid cachedMissTokens"
	}
	var cacheWrite uint64
	if usage.CachedWriteTokens != nil {
		cacheWrite, ok = parseUint(*usage.CachedWriteTokens)
		if !ok {
			return codebuddyObservation{}, "invalid cachedWriteTokens"
		}
	}
	// CodeBuddy semantics verified against real histories: inputTokens is
	// the total input including cache reads, so cacheTokens +
	// cachedMissTokens must equal inputTokens, and totalTokens must equal
	// inputTokens + outputTokens. Violations mean the format changed;
	// fail closed rather than uploading distorted counters.
	if sum, ok := adapter.AddUint64Checked(cacheRead, cacheMiss); !ok || sum != input {
		return codebuddyObservation{}, "CodeBuddy usage cache split does not sum to inputTokens"
	}
	if usage.TotalTokens != nil {
		if total, ok := parseUint(*usage.TotalTokens); ok {
			if inOut, ok := adapter.AddUint64Checked(input, output); !ok || total != inOut {
				return codebuddyObservation{}, "CodeBuddy usage totalTokens does not match known counters"
			}
		}
	}
	return codebuddyObservation{
		ConversationID: conversationID,
		RequestID:      req.ID,
		Timestamp:      time.UnixMilli(ms).UTC(),
		Input:          cacheMiss,
		CacheRead:      cacheRead,
		CacheWrite:     cacheWrite,
		Output:         output,
	}, ""
}

// codebuddyObservation is either a parsed request or an issue carrier.
type codebuddyObservation struct {
	ConversationID string
	RequestID      string
	Timestamp      time.Time
	Input          uint64
	CacheRead      uint64
	CacheWrite     uint64
	Output         uint64
	// File and Issue are set when the request failed validation; the
	// caller turns them into a quarantine entry.
	File  string
	Issue string
}

func codebuddyRecord(obs codebuddyObservation) adapter.Record {
	identity := obs.ConversationID + "/" + obs.RequestID
	return adapter.Record{
		"recordKey":      "codebuddy-history:" + adapter.ShortHash(identity),
		"groupKey":       "codebuddy-request:" + adapter.ShortHash(identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           codebuddyTool,
		"model":          "unknown",
		"input":          fmt.Sprintf("%d", obs.Input),
		"cacheRead":      fmt.Sprintf("%d", obs.CacheRead),
		"cacheWrite":     fmt.Sprintf("%d", obs.CacheWrite),
		"output":         fmt.Sprintf("%d", obs.Output),
		"adapterVersion": codebuddyAdapterVersion,
		"sourceType":     adapter.CodeBuddyHistorySource,
	}
}

func parseUint(n json.Number) (uint64, bool) {
	return adapter.ParseUint(strings.TrimSpace(n.String()))
}

func parseMillis(n json.Number) (int64, bool) {
	v, ok := adapter.ParseUint(strings.TrimSpace(n.String()))
	if !ok || v > (1<<53) {
		return 0, false
	}
	return int64(v), true
}

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

// Adapter exposes the CodeBuddy source to the collector pipeline.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.CodeBuddyHistorySource,
		Description: "CodeBuddy IDE session history usage JSON",
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
// so repeated full rescans cannot re-export known CodeBuddy records. The
// context is consulted at coarse boundaries; on cancellation it returns
// ctx.Err() and no partial result. A nil Options.Context reaches here as
// context.Background() and keeps the exact pre-cancellation behavior.
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
		if entry.Source != adapter.CodeBuddyHistorySource {
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
		if entry.Source == adapter.CodeBuddyHistorySource {
			if err := remember(entry.Record); err != nil {
				return nil, err
			}
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
