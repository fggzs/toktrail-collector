package codebuddyhistory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

// writeSessionIndex writes one history/<workspace>/<conversation>/index.json
// under root and returns its path.
func writeSessionIndex(t *testing.T, root, workspace, conversation, content string) string {
	t.Helper()
	path := filepath.Join(root, "history", workspace, conversation, "index.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func requestJSON(id string, startedAt int64, input, output, total, cache, miss, write int64) string {
	return fmt.Sprintf(`{"id":%q,"type":"craft","state":"complete","startedAt":%d,"usage":{"inputTokens":%d,"outputTokens":%d,"totalTokens":%d,"lastTokens":0,"cacheTokens":%d,"cachedWriteTokens":%d,"cachedMissTokens":%d,"credit":1.5}}`,
		id, startedAt, input, output, total, cache, write, miss)
}

func TestLoadRecordsParsesCompletedRequests(t *testing.T) {
	root := t.TempDir()
	writeSessionIndex(t, root, "ws1", "conv1",
		`{"messages":[],"requests":[`+
			requestJSON("req-1", 1790000001000, 78677, 1609, 80286, 31360, 47317, 0)+","+
			requestJSON("req-2", 1790000062000, 500, 100, 600, 400, 100, 25)+
			`]}`)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || len(res.Records) != 2 {
		t.Fatalf("unexpected result: %d records, quarantined %d, issues %#v", len(res.Records), res.Quarantined, res.Issues)
	}
	first := res.Records[0]
	if first["tool"] != "CodeBuddy" || first["sourceType"] != adapter.CodeBuddyHistorySource {
		t.Fatalf("unexpected identity fields: %#v", first)
	}
	if first["occurredAt"] != "2026-09-21T14:13:21Z" {
		t.Fatalf("millisecond epoch must map to UTC RFC3339: %#v", first["occurredAt"])
	}
	// toktrail mapping: net input is the cache miss part, cache read is
	// the cached part; include totals stay input + cache read + cache
	// write + output, which equals CodeBuddy's inputTokens + outputTokens.
	wantInput := "47317"
	if first["input"] != wantInput || first["cacheRead"] != "31360" || first["cacheWrite"] != "0" || first["output"] != "1609" {
		t.Fatalf("unexpected usage mapping: %#v", first)
	}
	second := res.Records[1]
	if second["input"] != "100" || second["cacheRead"] != "400" || second["cacheWrite"] != "25" || second["output"] != "100" {
		t.Fatalf("unexpected second mapping: %#v", second)
	}
	for _, rec := range res.Records {
		if !adapter.RecordIsUploadSafe(rec) {
			t.Fatalf("record is not upload safe: %#v", rec)
		}
		if err := adapter.ValidateRecord(rec); err != nil {
			t.Fatalf("record violates shared contract: %v", err)
		}
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), "ws1") || strings.Contains(string(raw), "conv1") || strings.Contains(string(raw), "req-") {
			t.Fatalf("record leaked private source data: %s", raw)
		}
	}
	// recordKey must be stable across rescans.
	again, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.StringField(again.Records[0], "recordKey") != adapter.StringField(first, "recordKey") {
		t.Fatalf("recordKey is not stable across rescans")
	}
}

func TestLoadRecordsSkipsIncompleteRequests(t *testing.T) {
	root := t.TempDir()
	writeSessionIndex(t, root, "ws1", "conv1",
		`{"messages":[],"requests":[`+
			`{"id":"running-1","type":"craft","state":"running","startedAt":1790000001000,"usage":{"inputTokens":10,"outputTokens":1}},`+
			`{"id":"canceled-1","type":"craft","state":"canceled","usage":{"inputTokens":10,"outputTokens":1}},`+
			`{"id":"nousage-1","type":"craft","state":"complete","startedAt":1790000002000}`+
			`]}`)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 {
		t.Fatalf("incomplete requests must be skipped silently: %#v", res)
	}
}

func TestLoadRecordsQuarantinesBrokenUsage(t *testing.T) {
	root := t.TempDir()
	// cache split does not sum to inputTokens
	writeSessionIndex(t, root, "ws1", "conv1",
		`{"messages":[],"requests":[{"id":"bad-1","type":"craft","state":"complete","startedAt":1790000001000,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":30,"cachedWriteTokens":0,"cachedMissTokens":20}}]}`)
	// totalTokens disagrees with input + output
	writeSessionIndex(t, root, "ws1", "conv2",
		`{"messages":[],"requests":[{"id":"bad-2","type":"craft","state":"complete","startedAt":1790000002000,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":999,"cacheTokens":30,"cachedWriteTokens":0,"cachedMissTokens":70}}]}`)
	// missing core counter
	writeSessionIndex(t, root, "ws1", "conv3",
		`{"messages":[],"requests":[{"id":"bad-3","type":"craft","state":"complete","startedAt":1790000003000,"usage":{"outputTokens":10}}]}`)
	// malformed JSON file
	writeSessionIndex(t, root, "ws1", "conv4", `{"requests":[`)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("broken usage must never become records: %#v", res)
	}
	if res.Quarantined != 4 {
		t.Fatalf("expected 4 quarantined entries, got %d: %#v", res.Quarantined, res.Issues)
	}
}

func TestLoadRecordsIgnoresNonHistoryLayout(t *testing.T) {
	root := t.TempDir()
	// index.json not under a history directory
	stray := filepath.Join(root, "somewhere", "else", "index.json")
	if err := os.MkdirAll(filepath.Dir(stray), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte(`{"requests":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// hidden directory is skipped
	writeSessionIndex(t, root, ".hidden", "conv1", `{"requests":[]}`)

	res, err := LoadRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || res.Quarantined != 0 {
		t.Fatalf("non-history layout must be ignored: %#v", res)
	}
}
