// Package opencodesqlite collects token usage from the local OpenCode CLI
// session database. OpenCode stores every conversation message in a SQLite
// database at ~/.local/share/opencode/opencode.db; assistant rows in the
// session_message table carry per-request usage counters in their data JSON.
// The adapter is passive: it opens the database read-only (immutable DSN, no
// sidecar files) and never writes to the OpenCode directory.
package opencodesqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

const (
	opencodeTool           = "OpenCode"
	opencodeAdapterVersion = "opencode-sqlite-v1"
	dbName                 = "opencode.db"
	maxIssues              = 50
	perDBTimeout           = 30 * time.Second
)

// opencodeObservation is either a parsed assistant request or an issue
// carrier; the loader turns Issue entries into quarantine diagnostics.
type opencodeObservation struct {
	MessageID   string
	Timestamp   time.Time
	Model       string
	Input       uint64
	CacheRead   uint64
	CacheWrite  uint64
	Output      uint64
	IssueReason string
}

// LoadRecords reads OpenCode assistant usage from an explicitly granted
// path. The path may be the OpenCode data directory (containing opencode.db)
// or the database file itself. It keeps the historical uncancellable
// signature for direct callers; the adapter's Load passes its cancellation
// scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support. On cancellation it
// returns ctx.Err() and no partial result, so a scan cut short never
// exports half of the OpenCode usage.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	files, err := discoverDatabases(ctx, root)
	if err != nil {
		return result, err
	}
	records := make(map[string]adapter.Record)
	conflicts := make(map[string]bool)
	issue := func(file string, reason string) {
		result.Quarantined++
		if len(result.Issues) < maxIssues {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: 0, Reason: reason})
		}
	}
	modelMissingReported := false
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		observations, err := readDB(ctx, file)
		if err != nil {
			return adapter.LoadResult{}, contextErr(ctx, err)
		}
		for _, obs := range observations {
			if obs.IssueReason != "" {
				issue(file, obs.IssueReason)
				continue
			}
			if obs.Model == "unknown" && !modelMissingReported {
				modelMissingReported = true
			}
			rec := opencodeRecord(obs)
			key := adapter.StringField(rec, "recordKey")
			if conflicts[key] {
				continue
			}
			if old, exists := records[key]; exists {
				if !sameRecord(old, rec) {
					delete(records, key)
					conflicts[key] = true
					issue(file, "conflicting usage for the same OpenCode message")
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
	if modelMissingReported && len(result.Issues) < maxIssues {
		result.Issues = append(result.Issues, adapter.LineIssue{File: "", Line: 0, Reason: "some OpenCode messages do not record a model identifier; those records report model unknown"})
	}
	return result, nil
}

// discoverDatabases resolves the granted path to OpenCode database files.
// A directory input yields the opencode.db it contains (the standard layout
// keeps one database at the data root); a file input must be that database.
func discoverDatabases(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := strings.TrimSpace(root)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if !strings.EqualFold(filepath.Base(clean), dbName) {
			return nil, fmt.Errorf("OpenCode input file %q must be %s", clean, dbName)
		}
		return []string{clean}, nil
	}
	candidate := filepath.Join(clean, dbName)
	if info, err := os.Stat(candidate); err != nil || info.IsDir() {
		return nil, fmt.Errorf("OpenCode input directory %q does not contain %s", clean, dbName)
	}
	return []string{candidate}, nil
}

// readDB scans one OpenCode database for assistant message usage. It derives
// a bounded deadline from ctx so cancellation and parent deadlines propagate
// into the query and every row; each row is checked for cancellation before
// parsing. The read-only immutable DSN never creates sidecar files in a live
// OpenCode directory; fresh WAL-only commits become visible on a later read
// after OpenCode checkpoints, which is acceptable for scheduled collection.
func readDB(ctx context.Context, path string) ([]opencodeObservation, error) {
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(ctx, perDBTimeout)
	defer cancel()
	// session_message is the current layout's authoritative message store:
	// every assistant row there (including sessions only present in the v2
	// tables) also exists in the legacy message table or supersedes it, so
	// reading session_message alone avoids double counting.
	const query = `SELECT id, COALESCE(data, '') FROM session_message WHERE type = 'assistant' ORDER BY time_created ASC, id ASC`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		// A database without the session_message table predates the v2
		// layout; treat it as empty rather than failing the scan.
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("query OpenCode session_message: %w", err)
	}
	defer rows.Close()
	var out []opencodeObservation
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		obs := parseAssistantMessage(id, data)
		out = append(out, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, contextErr(ctx, err)
	}
	return out, nil
}

// parseAssistantMessage decodes one assistant message's data JSON. OpenCode
// records usage with OpenAI-style disjoint buckets: tokens.input excludes
// cache reads, tokens.cache.read/write are listed separately, and
// tokens.reasoning is an informational subset of output. The v2 layout does
// not persist a tokens.total, so no total check is possible; malformed or
// incomplete rows become quarantine issues instead of records.
func parseAssistantMessage(id, raw string) opencodeObservation {
	if strings.TrimSpace(id) == "" {
		return opencodeObservation{IssueReason: "assistant message without id"}
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var msg struct {
		Tokens struct {
			Input     *json.Number `json:"input"`
			Output    *json.Number `json:"output"`
			Reasoning *json.Number `json:"reasoning"`
			Cache     struct {
				Read  *json.Number `json:"read"`
				Write *json.Number `json:"write"`
			} `json:"cache"`
		} `json:"tokens"`
		Model *struct {
			ProviderID string `json:"providerID"`
			ID         string `json:"id"`
		} `json:"model"`
		Time struct {
			Created *json.Number `json:"created"`
		} `json:"time"`
	}
	if err := decoder.Decode(&msg); err != nil {
		return opencodeObservation{IssueReason: "invalid assistant message JSON"}
	}
	if msg.Tokens.Input == nil || msg.Tokens.Output == nil {
		return opencodeObservation{IssueReason: "assistant message without complete token counters"}
	}
	input, ok := parseUint(*msg.Tokens.Input)
	if !ok {
		return opencodeObservation{IssueReason: "invalid tokens.input"}
	}
	output, ok := parseUint(*msg.Tokens.Output)
	if !ok {
		return opencodeObservation{IssueReason: "invalid tokens.output"}
	}
	var cacheRead, cacheWrite uint64
	if msg.Tokens.Cache.Read != nil {
		if cacheRead, ok = parseUint(*msg.Tokens.Cache.Read); !ok {
			return opencodeObservation{IssueReason: "invalid tokens.cache.read"}
		}
	}
	if msg.Tokens.Cache.Write != nil {
		if cacheWrite, ok = parseUint(*msg.Tokens.Cache.Write); !ok {
			return opencodeObservation{IssueReason: "invalid tokens.cache.write"}
		}
	}
	var occurred time.Time
	if msg.Time.Created != nil {
		if ms, ok := parseMillis(*msg.Time.Created); ok {
			occurred = time.UnixMilli(ms).UTC()
		}
	}
	if occurred.IsZero() {
		return opencodeObservation{IssueReason: "assistant message without time.created"}
	}
	model := "unknown"
	if msg.Model != nil && strings.TrimSpace(msg.Model.ID) != "" {
		provider := strings.TrimSpace(msg.Model.ProviderID)
		if provider != "" {
			model = provider + "/" + strings.TrimSpace(msg.Model.ID)
		} else {
			model = strings.TrimSpace(msg.Model.ID)
		}
		if err := adapter.ValidateModel(model); err != nil {
			return opencodeObservation{IssueReason: "invalid model identifier"}
		}
	}
	return opencodeObservation{
		MessageID:  id,
		Timestamp:  occurred,
		Model:      model,
		Input:      input,
		CacheRead:  cacheRead,
		CacheWrite: cacheWrite,
		Output:     output,
	}
}

func opencodeRecord(obs opencodeObservation) adapter.Record {
	return adapter.Record{
		"recordKey":      "opencode-sqlite:" + adapter.ShortHash(obs.MessageID),
		"groupKey":       "opencode-message:" + adapter.ShortHash(obs.MessageID),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     obs.Timestamp.UTC().Format(time.RFC3339),
		"tool":           opencodeTool,
		"model":          obs.Model,
		"input":          fmt.Sprintf("%d", obs.Input),
		"cacheRead":      fmt.Sprintf("%d", obs.CacheRead),
		"cacheWrite":     fmt.Sprintf("%d", obs.CacheWrite),
		"output":         fmt.Sprintf("%d", obs.Output),
		"adapterVersion": opencodeAdapterVersion,
		"sourceType":     adapter.OpenCodeSQLiteSource,
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

func contextErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// sqliteReadOnlyDSN renders a read-only immutable DSN without creating
// SQLite sidecar files in a live OpenCode directory.
func sqliteReadOnlyDSN(path string) string {
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case runtime.GOOS == "windows" && c == '\\':
			b.WriteByte('/')
		case c == '%' || c == '?' || c == '#' || c == ' ':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("?mode=ro&immutable=1")
	return b.String()
}

// Adapter exposes the OpenCode source to the collector pipeline.
func Adapter() adapter.Adapter {
	return adapter.Adapter{
		Source:      adapter.OpenCodeSQLiteSource,
		Description: "OpenCode CLI session usage SQLite",
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
// so repeated full rescans cannot re-export known OpenCode records. The
// context is consulted at coarse boundaries; on cancellation it returns
// ctx.Err() and no partial result.
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
			return fmt.Errorf("stored OpenCode record has no key")
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if old, exists := known[key]; exists && !bytes.Equal(old, canonical) {
			return fmt.Errorf("stored OpenCode record %s has conflicting content", key)
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
		if entry.Source != adapter.OpenCodeSQLiteSource {
			continue
		}
		switch entry.Status {
		case outbox.StatusPending, outbox.StatusSynced, outbox.StatusReorganized:
		default:
			return nil, fmt.Errorf("unknown OpenCode outbox status %q", entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("read OpenCode history batch %s: %w", entry.BatchID, err)
		}
		var batch struct {
			BatchID string            `json:"batchId"`
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("OpenCode history batch identity mismatch")
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
		if entry.Source == adapter.OpenCodeSQLiteSource {
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
				return nil, fmt.Errorf("OpenCode record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}
