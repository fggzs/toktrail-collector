package codebuddyhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

// writeFixture writes one file, creating parents. Test-only helper.
func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// conversationFixture lays out one conversation directory exactly as
// CodeBuddy writes it: messages/ beside index.json.
func conversationFixture(t *testing.T, root, project, conversation, index string) string {
	t.Helper()
	dir := filepath.Join(root, project, conversation)
	if err := os.MkdirAll(filepath.Join(dir, messagesDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, indexFileName)
	writeFixture(t, path, index)
	return path
}

// messageFixture writes one message file. extra is the JSON-encoded string
// CodeBuddy records beside the message body.
func messageFixture(t *testing.T, indexPath, id, role, extra string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"role":      role,
		"message":   `{"role":"` + role + `","content":[{"type":"text","text":"hello"}]}`,
		"id":        id,
		"extra":     extra,
		"createdAt": "2026-10-03T07:54:16.230Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(filepath.Dir(indexPath), messagesDirName, id+".json"), string(body))
}

// extraFixture renders the recorded extra payload (a JSON string in the file).
func extraFixture(t *testing.T, requestID, modelID string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"requestId":       requestID,
		"modelId":         modelID,
		"modelName":       "Hy4 preview",
		"isHelperMessage": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// realIndex mirrors a conversation index captured from CodeBuddy IDE: two
// completed turns with usage, one turn still streaming, one all-zero turn, one
// canceled turn without usage, and one request with no id.
const realIndex = `{
  "messages": [
    {"id":"m1","type":"text","role":"user","isComplete":true},
    {"id":"m2","type":"text","role":"assistant","isComplete":false},
    {"id":"m3","type":"text","role":"user","isComplete":true},
    {"id":"m4","type":"text","role":"assistant","isComplete":false}
  ],
  "requests": [
    {"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,
     "usage":{"inputTokens":322180,"outputTokens":5538,"totalTokens":327718,"lastTokens":84468,
              "cacheTokens":240576,"cachedWriteTokens":0,"cachedMissTokens":81604,"credit":5}},
    {"id":"r2","type":"craft","messages":["m3","m4"],"state":"complete","startedAt":1791014424445,
     "usage":{"inputTokens":1480504,"outputTokens":0,"totalTokens":1480504,"lastTokens":98927,
              "cacheTokens":0,"cachedWriteTokens":0,"cachedMissTokens":0,"credit":0}},
    {"id":"r3","type":"craft","messages":["m5"],"state":"streaming","startedAt":1791045445333,
     "usage":{"inputTokens":5000,"outputTokens":10,"totalTokens":5010}},
    {"id":"r4","type":"craft","messages":["m6"],"state":"complete","startedAt":1791045445333,
     "usage":{"inputTokens":0,"outputTokens":0,"totalTokens":0}},
    {"id":"r5","type":"craft","messages":["m7"],"state":"canceled"},
    {"id":"","type":"craft","messages":[],"state":"complete","startedAt":1791045445333,
     "usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}
  ]
}`

func TestLoadRecordsParsesConversationIndexes(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "e006e7ae", "eedd4e0a", realIndex)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))
	messageFixture(t, indexPath, "m4", "assistant", extraFixture(t, "r2", "hy4-preview-ioa"))
	// A workspace-level conversation list must never be read as usage.
	writeFixture(t, filepath.Join(root, "e006e7ae", indexFileName), `{"conversations":[{"id":"eedd4e0a"}]}`)

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %d (%#v)", len(result.Records), result.Records)
	}
	// The request without a stable id is quarantined; the streaming, all-zero
	// and canceled turns carry nothing to account for.
	if result.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined request, got %d", result.Quarantined)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %#v", result.Issues)
	}

	first, second := result.Records[0], result.Records[1]
	for _, record := range result.Records {
		if err := adapter.ValidateRecord(record); err != nil {
			t.Fatalf("record failed wire validation: %v (%#v)", err, record)
		}
	}
	if got := adapter.StringField(first, "occurredAt"); got != "2026-10-03T07:54:13Z" {
		t.Fatalf("unexpected occurredAt %q", got)
	}
	if got := adapter.StringField(second, "occurredAt"); got != "2026-10-03T08:00:24Z" {
		t.Fatalf("unexpected occurredAt %q", got)
	}
	for _, record := range result.Records {
		if got := adapter.StringField(record, "tool"); got != codebuddyTool {
			t.Fatalf("tool = %q want %q", got, codebuddyTool)
		}
		if got := adapter.StringField(record, "model"); got != "hy4-preview-ioa" {
			t.Fatalf("model = %q want the recorded modelId", got)
		}
		if got := adapter.StringField(record, "kind"); got != "delta" {
			t.Fatalf("kind = %q want delta", got)
		}
		if got := adapter.StringField(record, "sourceType"); got != adapter.CodeBuddyHistorySource {
			t.Fatalf("sourceType = %q", got)
		}
		if got := adapter.StringField(record, "adapterVersion"); got != codebuddyAdapterVersion {
			t.Fatalf("adapterVersion = %q", got)
		}
		if record["resetKey"] != nil {
			t.Fatalf("resetKey must stay nil for delta records")
		}
	}
	// Identity stays on the codebuddy-history-v1 rule: both keys hash the
	// "<conversation>/<request>" pair, so they differ per request.
	if adapter.StringField(first, "recordKey") == adapter.StringField(second, "recordKey") {
		t.Fatalf("record keys must be distinct per request")
	}
	if adapter.StringField(first, "groupKey")[0:len("codebuddy-request:")] != "codebuddy-request:" {
		t.Fatalf("group keys must keep the codebuddy-request domain")
	}
	if adapter.StringField(first, "recordKey")[0:len("codebuddy-history:")] != "codebuddy-history:" {
		t.Fatalf("record keys must keep the codebuddy-history domain")
	}
	// r1: cached 240576, uncached 81604 out of 322180 prompt.
	if got := adapter.StringField(first, "input"); got != "81604" {
		t.Fatalf("r1 input = %q", got)
	}
	if got := adapter.StringField(first, "cacheRead"); got != "240576" {
		t.Fatalf("r1 cacheRead = %q", got)
	}
	if got := adapter.StringField(first, "cacheWrite"); got != "0" {
		t.Fatalf("r1 cacheWrite = %q", got)
	}
	if got := adapter.StringField(first, "output"); got != "5538" {
		t.Fatalf("r1 output = %q", got)
	}
	// r2 records cachedMissTokens=0, which means "not reported", so the whole
	// prompt stays uncached and the counters still reconcile with totalTokens.
	if got := adapter.StringField(second, "input"); got != "1480504" {
		t.Fatalf("r2 input = %q", got)
	}
	if got := adapter.StringField(second, "cacheRead"); got != "0" {
		t.Fatalf("r2 cacheRead = %q", got)
	}
	if got := adapter.StringField(second, "output"); got != "0" {
		t.Fatalf("r2 output = %q", got)
	}
}

func TestLoadRecordsReportsUnknownModelWithoutQuarantine(t *testing.T) {
	root := t.TempDir()
	// The message files are missing entirely: the usage still exports, the
	// model is reported as unknown, and nothing is quarantined.
	conversationFixture(t, root, "e006e7ae", "eedd4e0a", realIndex)

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result.Records))
	}
	if result.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined request, got %d", result.Quarantined)
	}
	for _, record := range result.Records {
		if got := adapter.StringField(record, "model"); got != codebuddyUnknownModel {
			t.Fatalf("model = %q want unknown", got)
		}
	}
	if len(result.Issues) != 3 {
		t.Fatalf("expected 2 model issues plus the missing-id issue, got %#v", result.Issues)
	}
}

func TestLoadRecordsIgnoresForeignModelAttribution(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "e006e7ae", "eedd4e0a", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":false}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	indexPath := filepath.Join(root, "e006e7ae", "eedd4e0a", indexFileName)
	// The file claims another request, so its model must not be borrowed.
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r0", "other-model"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
		t.Fatalf("model = %q want unknown", got)
	}
}

func TestLoadRecordsSkipsEmptyUsageRows(t *testing.T) {
	root := t.TempDir()
	// Older conversations keep {"inputTokens":null,...} placeholders for
	// turns that never recorded counts; they account for nothing.
	conversationFixture(t, root, "e006e7ae", "eedd4e0a", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":null,"outputTokens":null,"totalTokens":null,"lastTokens":0}}]
	}`)

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 0 || result.Quarantined != 0 || len(result.Issues) != 0 {
		t.Fatalf("empty usage rows must be skipped silently, got %#v", result)
	}
}

// TestLoadRecordsQuarantinesRequestsWithoutTimestamp pins the removal of the
// message-file mtime fallback: a modification time is a transport artifact
// (backup restores and copies rewrite it), so a turn that records no valid
// startedAt is isolated instead of dated by guesswork.
func TestLoadRecordsQuarantinesRequestsWithoutTimestamp(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "e006e7ae", "eedd4e0a", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":true}],
	  "requests": [
	    {"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete",
	     "usage":{"inputTokens":87760,"outputTokens":783,"totalTokens":88543,"cacheTokens":0,"cachedWriteTokens":0,"cachedMissTokens":0}},
	    {"id":"r2","type":"craft","messages":["m2"],"state":"complete","startedAt":-1,
	     "usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":0,"cachedWriteTokens":0,"cachedMissTokens":100}}
	  ]
	}`)
	messageFixture(t, indexPath, "m1", "user", "")
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy3"))
	start := time.Date(2026, 2, 8, 11, 47, 30, 0, time.UTC)
	for _, id := range []string{"m1", "m2"} {
		if err := os.Chtimes(filepath.Join(filepath.Dir(indexPath), messagesDirName, id+".json"), start, start); err != nil {
			t.Fatal(err)
		}
	}

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 0 {
		t.Fatalf("no record may be dated from a file mtime: %#v", result.Records)
	}
	if result.Quarantined != 2 {
		t.Fatalf("expected both undated requests quarantined, got %d", result.Quarantined)
	}
}

func TestLoadRecordsQuarantinesContradictoryUsage(t *testing.T) {
	tests := []struct {
		name  string
		index string
	}{
		{
			name:  "cache exceeds prompt",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":200,"cachedMissTokens":0}}]}`,
		},
		{
			name:  "uncached share disagrees with prompt",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":40,"cachedMissTokens":20}}]}`,
		},
		{
			name:  "total disagrees with prompt plus output",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":999,"cacheTokens":0,"cachedWriteTokens":0}}]}`,
		},
		{
			name:  "negative counter",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":-5,"outputTokens":10,"totalTokens":5}}]}`,
		},
		{
			name:  "fractional counter",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100.5,"outputTokens":10,"totalTokens":110.5}}]}`,
		},
		{
			name:  "missing output counter",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"cacheTokens":0}}]}`,
		},
		{
			name:  "missing cache split",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110}}]}`,
		},
		{
			name:  "missing cache write counter",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":0}}]}`,
		},
		{
			name:  "missing timestamp",
			index: `{"requests":[{"id":"r1","state":"complete","usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":0,"cachedWriteTokens":0}}]}`,
		},
		{
			name:  "zero timestamp",
			index: `{"requests":[{"id":"r1","state":"complete","startedAt":0,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":0,"cachedWriteTokens":0}}]}`,
		},
		{
			name:  "invalid model identifier",
			index: `{"requests":[{"id":"r1","messages":["m1"],"state":"complete","startedAt":1791014053528,"usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,"cacheTokens":0,"cachedWriteTokens":0}}]}`,
		},
		{
			name:  "invalid conversation index JSON",
			index: `{"requests":[{"id":"r1"`,
		},
		{
			name:  "trailing data after conversation index",
			index: `{"requests":[]} garbage`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			indexPath := conversationFixture(t, root, "e006e7ae", "eedd4e0a", tc.index)
			if tc.name == "invalid model identifier" {
				// A control character inside modelId fails the shared wire
				// validation, so the request is isolated instead of uploaded.
				messageFixture(t, indexPath, "m1", "assistant", extraFixture(t, "r1", "bad\u0000model"))
			}
			result, err := LoadRecords(root)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(result.Records) != 0 {
				t.Fatalf("expected no records, got %#v", result.Records)
			}
			if result.Quarantined != 1 {
				t.Fatalf("expected 1 quarantined request, got %d", result.Quarantined)
			}
			if len(result.Issues) != 1 {
				t.Fatalf("expected 1 issue, got %#v", result.Issues)
			}
		})
	}
}

func TestLoadRecordsMissingRootFailsClosed(t *testing.T) {
	if _, err := LoadRecords(filepath.Join(t.TempDir(), "not-installed")); err == nil {
		t.Fatal("a missing granted path must surface as an error, not an empty result")
	}
	// An empty path is a caller mistake, not an empty install.
	if _, err := LoadRecords("   "); err == nil {
		t.Fatal("expected an error for an empty input path")
	}
}

func TestLoadRecordsAcceptsSingleIndexFile(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "e006e7ae", "eedd4e0a", realIndex)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))

	result, err := LoadRecords(indexPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result.Records))
	}
}

func TestLoadRecordsCancellation(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", realIndex)
	conversationFixture(t, root, "p2", "c2", realIndex)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := loadRecordsContext(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(result.Records) != 0 || result.Quarantined != 0 || len(result.Issues) != 0 {
		t.Fatalf("a canceled scan must not return partial results, got %#v", result)
	}
}

func TestFilterForExportDropsKnownHistory(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", realIndex)
	indexPath := filepath.Join(root, "p1", "c1", indexFileName)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))
	messageFixture(t, indexPath, "m4", "assistant", extraFixture(t, "r2", "hy4-preview-ioa"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	stateDir := t.TempDir()

	fresh, err := filterKnownRecordsContext(context.Background(), stateDir, result.Records)
	if err != nil {
		t.Fatalf("first filter: %v", err)
	}
	if len(fresh) != len(result.Records) {
		t.Fatalf("fresh filter must keep every record, got %d of %d", len(fresh), len(result.Records))
	}

	// Persist the first record as quarantined history, then rescan.
	record := result.Records[0]
	key := adapter.StringField(record, "recordKey")
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	store := quarantine.New(stateDir)
	if err := store.Append([]quarantine.Entry{{
		Source:    adapter.CodeBuddyHistorySource,
		RecordKey: key,
		Record:    raw,
		Reason:    "test",
	}}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	fresh, err = filterKnownRecordsContext(context.Background(), stateDir, result.Records)
	if err != nil {
		t.Fatalf("second filter: %v", err)
	}
	if len(fresh) != len(result.Records)-1 {
		t.Fatalf("known record must be filtered, got %d", len(fresh))
	}
	for _, entry := range fresh {
		if adapter.StringField(entry, "recordKey") == key {
			t.Fatalf("filtered record leaked through")
		}
	}

	// The same key with different counters cannot be replayed over verified
	// history.
	drifted := result.Records[0]
	drifted["output"] = "9999"
	if _, err := filterKnownRecordsContext(context.Background(), stateDir, []adapter.Record{drifted}); err == nil {
		t.Fatal("expected an error for a record that changed after export")
	}
}

// TestFilterForExportKeepsLegacyV1RecordsDeduplicated pins the version
// migration: a codebuddy-history-v1 export of the same request differs only by
// the model this build can now resolve, so it must stay filtered instead of
// failing the immutable-history guard.
func TestFilterForExportKeepsLegacyV1RecordsDeduplicated(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", realIndex)
	indexPath := filepath.Join(root, "p1", "c1", indexFileName)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	stateDir := t.TempDir()
	record := result.Records[0]
	key := adapter.StringField(record, "recordKey")
	if adapter.StringField(record, "model") != "hy4-preview-ioa" {
		t.Fatalf("fixture must resolve a model, got %q", adapter.StringField(record, "model"))
	}

	legacy := adapter.Record{}
	for field, value := range record {
		legacy[field] = value
	}
	legacy["model"] = codebuddyUnknownModel
	legacy["adapterVersion"] = codebuddyLegacyAdapterVersion
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	store := quarantine.New(stateDir)
	if err := store.Append([]quarantine.Entry{{
		Source:    adapter.CodeBuddyHistorySource,
		RecordKey: key,
		Record:    raw,
		Reason:    "test",
	}}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}

	fresh, err := filterKnownRecordsContext(context.Background(), stateDir, result.Records)
	if err != nil {
		t.Fatalf("a legacy v1 export of the same request must not fail the filter: %v", err)
	}
	for _, entry := range fresh {
		if adapter.StringField(entry, "recordKey") == key {
			t.Fatalf("legacy v1 record must stay deduplicated")
		}
	}
}

// seedKnown stores one record as already exported history.
func seedKnown(t *testing.T, stateDir string, record adapter.Record) {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := quarantine.New(stateDir).Append([]quarantine.Entry{{
		Source:    adapter.CodeBuddyHistorySource,
		RecordKey: adapter.StringField(record, "recordKey"),
		Record:    raw,
		Reason:    "test",
	}}); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
}

// TestFilterForExportDeduplicatesModelMetadataUpdates pins the v2 migration:
// a record exported while the model was still unknown, and a record exported
// with a resolved model that a later rescan can no longer resolve, both keep
// the first stored configuration instead of failing the immutable guard.
func TestFilterForExportDeduplicatesModelMetadataUpdates(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", realIndex)
	indexPath := filepath.Join(root, "p1", "c1", indexFileName)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	record := result.Records[0]
	if adapter.StringField(record, "model") != "hy4-preview-ioa" {
		t.Fatalf("fixture must resolve a model, got %q", adapter.StringField(record, "model"))
	}
	unresolved := adapter.Record{}
	for field, value := range record {
		unresolved[field] = value
	}
	unresolved["model"] = codebuddyUnknownModel

	// unknown stored, resolved on rescan.
	stateDir := t.TempDir()
	seedKnown(t, stateDir, unresolved)
	fresh, err := filterKnownRecordsContext(context.Background(), stateDir, []adapter.Record{record})
	if err != nil {
		t.Fatalf("unknown -> resolved model must stay deduplicated: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("expected the already exported record to be filtered, got %d", len(fresh))
	}

	// resolved stored, unknown on rescan.
	otherState := t.TempDir()
	seedKnown(t, otherState, record)
	fresh, err = filterKnownRecordsContext(context.Background(), otherState, []adapter.Record{unresolved})
	if err != nil {
		t.Fatalf("resolved -> unknown model must stay deduplicated: %v", err)
	}
	if len(fresh) != 0 {
		t.Fatalf("expected the already exported record to be filtered, got %d", len(fresh))
	}

	// Counters still cannot be replayed over verified history.
	drifted := adapter.Record{}
	for field, value := range unresolved {
		drifted[field] = value
	}
	drifted["output"] = "9999"
	if _, err := filterKnownRecordsContext(context.Background(), otherState, []adapter.Record{drifted}); err == nil {
		t.Fatal("a counter change must still fail the immutable-history guard")
	}

	// A genuinely new request still exports.
	added := adapter.Record{}
	for field, value := range record {
		added[field] = value
	}
	added["recordKey"] = "codebuddy-history:new-request"
	fresh, err = filterKnownRecordsContext(context.Background(), otherState, []adapter.Record{added})
	if err != nil {
		t.Fatalf("new request must export: %v", err)
	}
	if len(fresh) != 1 || adapter.StringField(fresh[0], "recordKey") != "codebuddy-history:new-request" {
		t.Fatalf("new request was not exported: %#v", fresh)
	}
}

// TestLoadRecordsSingleFileGrantDoesNotReadSiblings pins the grant boundary:
// naming one index.json file authorizes that file alone, so the sibling message
// files that would resolve a model are never read.
func TestLoadRecordsSingleFileGrantDoesNotReadSiblings(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "p1", "c1", realIndex)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "hy4-preview-ioa"))

	result, err := LoadRecords(indexPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result.Records))
	}
	for _, record := range result.Records {
		if got := adapter.StringField(record, "model"); got != codebuddyUnknownModel {
			t.Fatalf("single-file grant read a sibling message file: model = %q", got)
		}
	}

	// The same tree scanned through a directory grant still resolves it.
	result, err = LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := adapter.StringField(result.Records[0], "model"); got != "hy4-preview-ioa" {
		t.Fatalf("directory grant must resolve the model, got %q", got)
	}
}

// TestLoadRecordsRejectsMessageLinksOutsideGrant pins the containment check:
// a message file reached through a link that leaves the granted tree is not
// read, and the request falls back to an unknown model.
func TestLoadRecordsRejectsMessageLinksOutsideGrant(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "p1", "c1", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":false}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)

	// A message body outside the granted tree, reachable only through a link.
	outside := filepath.Join(t.TempDir(), "m2.json")
	body, err := json.Marshal(map[string]any{
		"role":    "assistant",
		"message": `{"role":"assistant"}`,
		"id":      "m2",
		"extra":   extraFixture(t, "r1", "hy4-preview-ioa"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(indexPath), messagesDirName, "m2.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are unavailable on this host: %v", err)
	}

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
		t.Fatalf("message file outside the grant was read: model = %q", got)
	}
}

// TestLoadRecordsMultiModelRequestReportsUnknown pins the attribution rule: a
// turn whose attributable assistant messages name different models cannot be
// split across them, so the whole turn reports an unknown model.
func TestLoadRecordsMultiModelRequestReportsUnknown(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "p1", "c1", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":false},{"id":"m3","type":"text","role":"assistant","isComplete":false}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1","m2","m3"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "model-a"))
	messageFixture(t, indexPath, "m3", "assistant", extraFixture(t, "r1", "model-b"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
		t.Fatalf("mixed models must not be attributed: model = %q", got)
	}
	if result.Quarantined != 0 {
		t.Fatalf("an unattributable model must not quarantine the usage: %d", result.Quarantined)
	}
}

// TestLoadRecordsRequiresConsistentModelAcrossTurn pins the complementary rule:
// one model repeated by every attributable assistant message is attributed.
func TestLoadRecordsRequiresConsistentModelAcrossTurn(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "p1", "c1", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":false},{"id":"m3","type":"text","role":"assistant","isComplete":false}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1","m2","m3"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r1", "model-a"))
	messageFixture(t, indexPath, "m3", "assistant", extraFixture(t, "r1", "model-a"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := adapter.StringField(result.Records[0], "model"); got != "model-a" {
		t.Fatalf("consistent models must be attributed, got %q", got)
	}
}

// TestLoadRecordsIgnoresMessagesWithoutRequestID pins the strict attribution
// rule: a message that does not name the request is not attributable, so its
// model cannot be borrowed by the turn.
func TestLoadRecordsIgnoresMessagesWithoutRequestID(t *testing.T) {
	root := t.TempDir()
	indexPath := conversationFixture(t, root, "p1", "c1", `{
	  "messages": [{"id":"m1","type":"text","role":"user","isComplete":true},{"id":"m2","type":"text","role":"assistant","isComplete":false}],
	  "requests": [{"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	body, err := json.Marshal(map[string]any{
		"role":    "assistant",
		"message": `{"role":"assistant"}`,
		"id":      "m2",
		"extra":   `{"modelId":"model-a"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(filepath.Dir(indexPath), messagesDirName, "m2.json"), string(body))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
		t.Fatalf("a message without requestId must not be attributed, model = %q", got)
	}
}

func TestFilterForExportWithoutStateDirKeepsRecords(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", realIndex)
	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	fresh, err := Adapter().FilterForExport(adapter.Options{Source: adapter.CodeBuddyHistorySource, Input: root}, result.Records)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(fresh) != len(result.Records) {
		t.Fatalf("stateless filter must keep every record, got %d", len(fresh))
	}
}

// A turn that stores no assistant message records the model on its single user
// message instead (verified on recorded data). Reporting those turns as
// "unknown" threw away a model the client had plainly recorded.
func TestLoadRecordsAttributesModelFromRequestMatchingUserMessage(t *testing.T) {
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", `{
	  "requests": [{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	indexPath := filepath.Join(root, "p1", "c1", indexFileName)
	messageFixture(t, indexPath, "m1", "user", extraFixture(t, "r1", "glm-5.2"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	if got := adapter.StringField(result.Records[0], "model"); got != "glm-5.2" {
		t.Fatalf("model = %q want the modelId recorded on the user message", got)
	}
	if result.Quarantined != 0 {
		t.Fatalf("a user-message attribution must not quarantine, got %d", result.Quarantined)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("a resolved model must not report an issue, got %#v", result.Issues)
	}
}

// The user-message fallback is never by proximity: without a matching
// extra.requestId the model stays unknown, because borrowing a neighbouring
// turn's model is worse than reporting "unknown".
func TestLoadRecordsNeverBorrowsUserMessageModelWithoutRequestMatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requestID string
	}{
		{"foreign request id", "r0"},
		{"absent request id", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			conversationFixture(t, root, "p1", "c1", `{
			  "requests": [{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,
			    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
			}`)
			indexPath := filepath.Join(root, "p1", "c1", indexFileName)
			messageFixture(t, indexPath, "m1", "user", extraFixture(t, tc.requestID, "other-model"))

			result, err := LoadRecords(root)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(result.Records) != 1 {
				t.Fatalf("expected 1 record, got %d", len(result.Records))
			}
			if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
				t.Fatalf("model = %q want unknown", got)
			}
			if result.Quarantined != 0 {
				t.Fatalf("an unusable user-message model must not quarantine, got %d", result.Quarantined)
			}
		})
	}
}

// TestLoadRecordsUserFallbackAcceptsOnlyVerifiedSingleMessageShape pins the
// fallback's exact shape: the turn's ORIGINAL message list must hold exactly
// one file, that file must record the user role, its extra.requestId must
// match the request, and its model must be legal. Multi-message turns, other
// roles, or turns whose assistant side is merely model-less report unknown —
// the usage still exports and nothing quarantines.
func TestLoadRecordsUserFallbackAcceptsOnlyVerifiedSingleMessageShape(t *testing.T) {
	usage := `"usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}`
	cases := []struct {
		name     string
		index    string
		fixtures func(t *testing.T, indexPath string)
	}{
		{
			name:  "two user messages with conflicting models",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "user", extraFixture(t, "r1", "model-a"))
				messageFixture(t, indexPath, "m2", "user", extraFixture(t, "r1", "model-b"))
			},
		},
		{
			name:  "single tool message is not the verified shape",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "tool", extraFixture(t, "r1", "model-a"))
			},
		},
		{
			name:  "single system message is not the verified shape",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "system", extraFixture(t, "r1", "model-a"))
			},
		},
		{
			name:  "single message without a role is not the verified shape",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				body, err := json.Marshal(map[string]any{
					"id":    "m1",
					"extra": extraFixture(t, "r1", "model-a"),
				})
				if err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(filepath.Dir(indexPath), messagesDirName, "m1.json"), string(body))
			},
		},
		{
			name:  "user model never covers a model-less assistant message",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "user", extraFixture(t, "r1", "model-a"))
				// The assistant message carries the request id but no
				// modelId at all: an empty modelId would be an invalid
				// identifier, so the field is omitted instead.
				body, err := json.Marshal(map[string]any{
					"role":      "assistant",
					"message":   `{"role":"assistant"}`,
					"id":        "m2",
					"extra":     `{"requestId":"r1","modelName":"Hy4 preview"}`,
					"createdAt": "2026-10-03T07:54:16.230Z",
				})
				if err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(filepath.Dir(indexPath), messagesDirName, "m2.json"), string(body))
			},
		},
		{
			name:  "the original message count decides, not the readable remainder",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1","../escape"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "user", extraFixture(t, "r1", "model-a"))
			},
		},
		{
			name:  "a single user message with an illegal model stays unknown",
			index: `{"requests":[{"id":"r1","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,` + usage + `}]}`,
			fixtures: func(t *testing.T, indexPath string) {
				messageFixture(t, indexPath, "m1", "user", extraFixture(t, "r1", "bad\u0000model"))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			indexPath := conversationFixture(t, root, "p1", "c1", tc.index)
			tc.fixtures(t, indexPath)

			result, err := LoadRecords(root)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(result.Records) != 1 {
				t.Fatalf("expected 1 record, got %d", len(result.Records))
			}
			if got := adapter.StringField(result.Records[0], "model"); got != codebuddyUnknownModel {
				t.Fatalf("model = %q want unknown", got)
			}
			if result.Quarantined != 0 {
				t.Fatalf("an unattributable model must not quarantine the usage, got %d", result.Quarantined)
			}
		})
	}
}

// legacyCountingRecord rebuilds the record the v2 layout exported for the
// same request: the old counting subtracted only the cache-read share from
// the prompt, so its input differs from the v3 one.
func legacyCountingRecord(t *testing.T, fresh adapter.Record, legacyInput, model string) adapter.Record {
	t.Helper()
	legacy := adapter.Record{}
	for field, value := range fresh {
		legacy[field] = value
	}
	legacy["adapterVersion"] = codebuddyLegacyCountingVersion
	legacy["input"] = legacyInput
	if model != "" {
		legacy["model"] = model
	}
	return legacy
}

// seedOutboxBatch writes one batch file holding records and registers it in
// the outbox ledger with the given status.
func seedOutboxBatch(t *testing.T, stateDir, batchID, status string, records ...adapter.Record) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"batchId": batchID, "records": records})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, batchID+".json")
	writeFixture(t, path, string(payload))
	store := outbox.New(stateDir)
	if _, err := store.AddPending(outbox.AddBatchOptions{
		BatchID:     batchID,
		File:        path,
		Source:      adapter.CodeBuddyHistorySource,
		RecordCount: len(records),
	}); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}
	if status == outbox.StatusSynced {
		if err := store.MarkSynced(outbox.Receipt{BatchID: batchID, Status: "accepted", AcceptedRecords: len(records), ReceivedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("mark synced: %v", err)
		}
	}
	return path
}

// TestFilterForExportUpgradesLegacyV2CountingHistory pins the v3 upgrade
// path: a request already exported under the v2 counting layout (input
// subtracted only the cache-read share) stays deduplicated when the v3
// three-way split changes its uploaded input, in every store that holds
// immutable history. The stored copy is never rewritten, genuinely new
// requests of the same scan still export, and a counter difference the
// upgrade does not explain still fails the guard.
func TestFilterForExportUpgradesLegacyV2CountingHistory(t *testing.T) {
	// r-write records a non-zero cache-write share: the v2 layout exported
	// input=100 for it (inputTokens minus the cache-read share), the v3
	// layout exports input=0. r-new is a genuinely new request.
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", `{
	  "messages": [{"id":"m1","type":"text","role":"assistant","isComplete":false},{"id":"m2","type":"text","role":"assistant","isComplete":false}],
	  "requests": [
	    {"id":"r-write","type":"craft","messages":["m1"],"state":"complete","startedAt":1791014053528,
	     "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":900,"cachedWriteTokens":100,"cachedMissTokens":0}},
	    {"id":"r-new","type":"craft","messages":["m2"],"state":"complete","startedAt":1791014424445,
	     "usage":{"inputTokens":500,"outputTokens":20,"totalTokens":520,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":100}}
	  ]
	}`)
	indexPath := filepath.Join(root, "p1", "c1", indexFileName)
	messageFixture(t, indexPath, "m1", "assistant", extraFixture(t, "r-write", "model-a"))
	messageFixture(t, indexPath, "m2", "assistant", extraFixture(t, "r-new", "model-b"))

	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var legacyExported, newRequest adapter.Record
	for _, record := range result.Records {
		switch adapter.StringField(record, "occurredAt") {
		case "2026-10-03T07:54:13Z":
			legacyExported = record
		case "2026-10-03T08:00:24Z":
			newRequest = record
		}
	}
	if legacyExported == nil || newRequest == nil {
		t.Fatalf("expected both requests to load, got %d records", len(result.Records))
	}
	if got := adapter.StringField(legacyExported, "input"); got != "0" {
		t.Fatalf("the v3 layout must subtract the cache-write share, input = %q", got)
	}
	if got := adapter.StringField(legacyExported, "adapterVersion"); got != codebuddyAdapterVersion {
		t.Fatalf("adapterVersion = %q", got)
	}
	legacy := legacyCountingRecord(t, legacyExported, "100", "")

	stores := []struct {
		name   string
		outbox bool
		status string
	}{
		{"pending outbox", true, outbox.StatusPending},
		{"synced outbox", true, outbox.StatusSynced},
		{"quarantine store", false, ""},
	}
	for _, tc := range stores {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			var storedPath string
			if tc.outbox {
				storedPath = seedOutboxBatch(t, stateDir, "batch-v2", tc.status, legacy)
			} else {
				seedKnown(t, stateDir, legacy)
			}
			before, readErr := os.ReadFile(storedPath)
			if tc.outbox && readErr != nil {
				t.Fatalf("read seeded batch: %v", readErr)
			}

			filtered, err := filterKnownRecordsContext(context.Background(), stateDir, result.Records)
			if err != nil {
				t.Fatalf("the v2 counting upgrade must not fail the filter: %v", err)
			}
			if len(filtered) != 1 || adapter.StringField(filtered[0], "recordKey") != adapter.StringField(newRequest, "recordKey") {
				t.Fatalf("only the genuinely new request may export, got %#v", filtered)
			}
			if tc.outbox {
				after, readErr := os.ReadFile(storedPath)
				if readErr != nil {
					t.Fatalf("re-read seeded batch: %v", readErr)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("stored history must not be rewritten by the upgrade")
				}
			} else {
				entries, loadErr := quarantine.New(stateDir).Load()
				if loadErr != nil {
					t.Fatalf("load quarantine: %v", loadErr)
				}
				if len(entries) != 1 {
					t.Fatalf("expected the seeded entry to survive, got %d entries", len(entries))
				}
				var stored adapter.Record
				if err := json.Unmarshal(entries[0].Record, &stored); err != nil {
					t.Fatalf("decode quarantined record: %v", err)
				}
				if !sameRecord(stored, legacy) {
					t.Fatalf("the quarantined history must keep the stored copy, got %s", entries[0].Record)
				}
			}
		})
	}

	// Combined upgrade: the stored v2 export predates model resolution too.
	combined := legacyCountingRecord(t, legacyExported, "100", codebuddyUnknownModel)
	stateDir := t.TempDir()
	seedKnown(t, stateDir, combined)
	filtered, err := filterKnownRecordsContext(context.Background(), stateDir, []adapter.Record{legacyExported})
	if err != nil {
		t.Fatalf("legacy counting plus unknown -> resolved model must stay deduplicated: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatalf("the upgraded request must not re-upload, got %#v", filtered)
	}

	// A counter difference the v3 upgrade does not explain still fails.
	drifted := legacyCountingRecord(t, legacyExported, "50", "")
	driftedState := t.TempDir()
	seedKnown(t, driftedState, drifted)
	if _, err := filterKnownRecordsContext(context.Background(), driftedState, []adapter.Record{legacyExported}); err == nil {
		t.Fatal("an input difference the v3 upgrade does not explain must stay a conflict")
	}
}

// TestFilterForExportAbsorbsLayoutVersionLabelChange pins the baseline
// follow-up: a stored record that matches the fresh one byte for byte except
// for the layout version stays deduplicated no matter which side resolved a
// model, so a pure layout relabel never re-uploads history. Identity or
// timestamp differences still fail the guard.
func TestFilterForExportAbsorbsLayoutVersionLabelChange(t *testing.T) {
	// A request whose model stays unknown on both sides.
	root := t.TempDir()
	conversationFixture(t, root, "p1", "c1", `{
	  "requests": [{"id":"r1","type":"craft","messages":[],"state":"complete","startedAt":1791014053528,
	    "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}}]
	}`)
	result, err := LoadRecords(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result.Records))
	}
	fresh := result.Records[0]

	for _, stored := range []struct {
		version string
		label   string
	}{
		{codebuddyLegacyAdapterVersion, "v1"},
		{codebuddyLegacyCountingVersion, "v2"},
	} {
		t.Run("stored "+stored.label+" with identical payload", func(t *testing.T) {
			relabeled := adapter.Record{}
			for field, value := range fresh {
				relabeled[field] = value
			}
			relabeled["adapterVersion"] = stored.version
			stateDir := t.TempDir()
			seedKnown(t, stateDir, relabeled)
			filtered, err := filterKnownRecordsContext(context.Background(), stateDir, []adapter.Record{fresh})
			if err != nil {
				t.Fatalf("a pure layout relabel must stay deduplicated: %v", err)
			}
			if len(filtered) != 0 {
				t.Fatalf("the relabeled request must not re-upload, got %#v", filtered)
			}
		})
	}

	// An identity difference is never absorbed by a version change.
	relabeled := adapter.Record{}
	for field, value := range fresh {
		relabeled[field] = value
	}
	relabeled["adapterVersion"] = codebuddyLegacyAdapterVersion
	relabeled["occurredAt"] = "2020-01-01T00:00:00Z"
	driftedState := t.TempDir()
	seedKnown(t, driftedState, relabeled)
	if _, err := filterKnownRecordsContext(context.Background(), driftedState, []adapter.Record{fresh}); err == nil {
		t.Fatal("a timestamp difference must still fail the immutable-history guard")
	}
}
