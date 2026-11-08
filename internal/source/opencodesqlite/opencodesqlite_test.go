package opencodesqlite

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/source/adapter"
)

// makeOpenCodeDB creates an OpenCode-like database with a session_message
// table at dir/opencode.db and returns the data directory path.
func makeOpenCodeDB(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close fixture database: %v", err)
		}
	}()
	if _, err := db.Exec(`CREATE TABLE session_message (
		id TEXT PRIMARY KEY,
		session_id TEXT,
		type TEXT,
		seq INTEGER,
		time_created INTEGER,
		time_updated INTEGER,
		data TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	return dir
}

func insertAssistant(t *testing.T, dir, id string, created int64, data string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close fixture database: %v", err)
		}
	}()
	if _, err := db.Exec(`INSERT INTO session_message (id, session_id, type, seq, time_created, time_updated, data) VALUES (?, 'ses_1', 'assistant', 1, ?, ?, ?)`, id, created, created, data); err != nil {
		t.Fatal(err)
	}
}

func assistantData(modelID string, input, output, reasoning, cacheRead, cacheWrite int64, created int64) string {
	return `{"agent":"build","model":{"providerID":"minimax","id":` + quote(modelID) + `,"variant":"default"},"cost":0.01,` +
		`"tokens":{"input":` + itoa(input) + `,"output":` + itoa(output) + `,"reasoning":` + itoa(reasoning) + `,"cache":{"read":` + itoa(cacheRead) + `,"write":` + itoa(cacheWrite) + `}},` +
		`"time":{"created":` + itoa(created) + `,"completed":` + itoa(created+1000) + `}}`
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestLoadRecordsParsesAssistantUsage(t *testing.T) {
	dir := makeOpenCodeDB(t, t.TempDir())
	insertAssistant(t, dir, "msg_1", 1790000001000,
		assistantData("MiniMax-M3", 23291, 472, 0, 0, 0, 1790000001000))
	insertAssistant(t, dir, "msg_2", 1790000062000,
		assistantData("MiniMax-M2.7", 2090, 158, 7, 25440, 0, 1790000062000))

	res, err := LoadRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Records) != 2 {
		t.Fatalf("unexpected result: %d records, quarantined %d, issues %#v", len(res.Records), res.Quarantined, res.Issues)
	}
	first := res.Records[0]
	if first["tool"] != "OpenCode" || first["sourceType"] != adapter.OpenCodeSQLiteSource {
		t.Fatalf("unexpected identity fields: %#v", first)
	}
	if first["model"] != "minimax/MiniMax-M3" {
		t.Fatalf("model must be provider/model: %#v", first["model"])
	}
	// OpenCode input excludes cache reads (OpenAI-style disjoint buckets).
	if first["input"] != "23291" || first["cacheRead"] != "0" || first["cacheWrite"] != "0" || first["output"] != "472" {
		t.Fatalf("unexpected usage mapping: %#v", first)
	}
	second := res.Records[1]
	if second["input"] != "2090" || second["cacheRead"] != "25440" || second["cacheWrite"] != "0" || second["output"] != "158" {
		t.Fatalf("cache read must stay a separate bucket: %#v", second)
	}
	for _, rec := range res.Records {
		if !adapter.RecordIsUploadSafe(rec) {
			t.Fatalf("record is not upload safe: %#v", rec)
		}
		if err := adapter.ValidateRecord(rec); err != nil {
			t.Fatalf("record violates shared contract: %v", err)
		}
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "msg_") || strings.Contains(string(raw), "ses_1") {
			t.Fatalf("record leaked private source data: %s", raw)
		}
	}
	again, err := LoadRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.StringField(again.Records[0], "recordKey") != adapter.StringField(first, "recordKey") {
		t.Fatalf("recordKey is not stable across rescans")
	}
}

func TestLoadRecordsSkipsNonAssistantAndQuarantinesBrokenRows(t *testing.T) {
	dir := makeOpenCodeDB(t, t.TempDir())
	// broken: missing input counter
	insertAssistant(t, dir, "msg_bad1", 1790000001000, `{"tokens":{"output":10},"time":{"created":1790000001000}}`)
	// broken: invalid JSON
	insertAssistant(t, dir, "msg_bad2", 1790000002000, `{not json`)
	// broken: missing time.created
	insertAssistant(t, dir, "msg_bad3", 1790000003000, `{"tokens":{"input":1,"output":2}}`)
	// broken: negative counter
	insertAssistant(t, dir, "msg_bad4", 1790000004000, `{"tokens":{"input":-5,"output":2},"time":{"created":1790000004000}}`)

	res, err := LoadRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("broken rows must never become records: %#v", res)
	}
	if res.Quarantined != 4 {
		t.Fatalf("expected 4 quarantined entries, got %d: %#v", res.Quarantined, res.Issues)
	}
}

func TestLoadRecordsMissingModelReportsUnknown(t *testing.T) {
	dir := makeOpenCodeDB(t, t.TempDir())
	insertAssistant(t, dir, "msg_1", 1790000001000,
		`{"tokens":{"input":100,"output":20,"reasoning":0,"cache":{"read":0,"write":0}},"time":{"created":1790000001000}}`)

	res, err := LoadRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0]["model"] != "unknown" {
		t.Fatalf("missing model must report unknown: %#v", res)
	}
}

func TestLoadRecordsInputDirectoryWithoutDBFails(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadRecords(root); err == nil {
		t.Fatalf("directory without opencode.db must fail")
	}
}
