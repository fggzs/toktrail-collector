// Package codebuddyjson reads CodeBuddy IDE conversation indexes and emits
// per-request token usage delta records.
//
// Storage layout (verified against CodeBuddy IDE on 2026-11-08):
//
//	<root>/<project>/<conversationId>/index.json
//	<root>/<project>/<conversationId>/messages/<messageId>.json
//
// index.json holds {"messages":[...],"requests":[...]}. Every request is one
// user turn and carries the counters the client recorded for that turn:
//
//	{"id":"...","type":"craft","messages":["<messageId>",...],
//	 "state":"complete","startedAt":1791014053528,
//	 "usage":{"inputTokens":322180,"outputTokens":5538,"totalTokens":327718,
//	          "lastTokens":84468,"cacheTokens":240576,"cachedWriteTokens":0,
//	          "cachedMissTokens":81604,"credit":0}}
//
// Counter semantics (verified against recorded indexes):
//
//   - inputTokens is the TOTAL prompt size of the turn: across every model
//     call the turn made, cached and uncached prompt bytes alike.
//   - cacheTokens is the cached (cache-read) share, cachedWriteTokens the
//     cache-write share, and cachedMissTokens the uncached share. The client
//     writes 0 for cachedMissTokens on turns whose usage was not broken down
//     (the first turn of a conversation records inputTokens=98927 with
//     cacheTokens=0 / cachedMissTokens=0), so a ZERO cachedMissTokens is read
//     as "not reported", never as "the whole prompt is uncached".
//   - totalTokens is inputTokens + outputTokens when present.
//
// The record therefore uploads the uncached prompt as "input", the cached
// share as "cacheRead" and the cache-write share as "cacheWrite" (the same
// disjoint-bucket convention the Claude Code and WorkBuddy adapters use).
//
// Per-request usage is a delta: repeated turns record their own consumption,
// so the loader emits kind="delta". A request in an unrecognized (non
// terminal) state is skipped entirely, because its usage may still be growing
// and exporting a partial counter set would poison the immutable history.
//
// Timestamps: recent indexes record startedAt in epoch milliseconds. Older
// conversations record none and no message file carries a createdAt either,
// so the loader falls back to the modification time of the turn's first
// message file — the client writes that file when the turn starts, and the
// sampled indexes match the recorded startedAt to the second. A turn with
// neither is quarantined rather than uploaded with an invented time.
//
// Usage rows whose counters are all null ({inputTokens:null,...}) are old
// placeholders for turns that never recorded counts: they account for nothing
// and are skipped, not quarantined.
//
// The model identifier is not recorded in index.json. It lives in the
// per-message files as extra.modelId (extra is itself a JSON string), so the
// loader resolves one recorded model per request by reading the first
// attributable assistant message that belongs to that request. Message files
// are bounded and probing is capped; when nothing is attributable the record
// reports "unknown" and a value-free local issue, never a guess.
//
// The scan is stateless: every Load re-emits the full history with stable keys
// and FilterForExport drops what the outbox or quarantine already hold.
package codebuddyjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/source/adapter"
)

const (
	// cbTool must match the canonical tool name in registry.SupportedTools.
	cbTool = "CodeBuddy"
	// cbAdapterVersion identifies the record layout produced here.
	cbAdapterVersion = "codebuddy-json-v1"
	// cbRecordKeyDomain prefixes every stable record key.
	cbRecordKeyDomain = "codebuddy-json"
	// cbGroupKeyDomain prefixes every per-conversation group key.
	cbGroupKeyDomain = "codebuddy-conversation"
	// indexFileName is the only conversation file the loader reads counters
	// from. Other JSON files in the directory tree (workspace conversation
	// lists, current.json, recent.json, .index_bak.json) are never scanned.
	indexFileName = "index.json"
	// messagesDirName marks a conversation directory: workspace-level
	// index.json files sit beside no messages directory, so the loader never
	// mistakes a conversation list for usage.
	messagesDirName = "messages"
	// maxIssues caps the reported issue list; every anomaly still increments
	// Quarantined so counts stay complete.
	maxIssues = 50
	// maxIndexBytes bounds the conversation index the loader decodes.
	maxIndexBytes = 16 << 20
	// maxMessageBytes bounds one message file probed for model attribution;
	// tool-output-heavy messages above this size contribute no model.
	maxMessageBytes = 2 << 20
	// maxModelProbes bounds how many message files one request may probe.
	maxModelProbes = 8
	// safeIntegerLimit separates second and millisecond startedAt values.
	safeIntegerLimit = 10000000000
)

// conversationIndex is the decoded conversation index. Requests are the only
// part the collector reads.
type conversationIndex struct {
	Requests []indexRequest `json:"requests"`
}

type indexRequest struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"`
	State     string        `json:"state"`
	Messages  []string      `json:"messages"`
	StartedAt *json.Number  `json:"startedAt"`
	Usage     *requestUsage `json:"usage"`
}

// requestUsage keeps the recorded counters as json.Number so a fractional,
// signed or exponent value is rejected instead of rounded through float64.
type requestUsage struct {
	InputTokens       *json.Number `json:"inputTokens"`
	OutputTokens      *json.Number `json:"outputTokens"`
	TotalTokens       *json.Number `json:"totalTokens"`
	CacheTokens       *json.Number `json:"cacheTokens"`
	CachedWriteTokens *json.Number `json:"cachedWriteTokens"`
	CachedMissTokens  *json.Number `json:"cachedMissTokens"`
}

// usageCounts is the validated, uploadable bucket set of one request.
type usageCounts struct {
	// totalInput is the recorded inputTokens (cached + uncached prompt).
	totalInput uint64
	// input is the uncached prompt share (uploaded as "input").
	input      uint64
	cacheRead  uint64
	cacheWrite uint64
	output     uint64
}

// LoadRecords scans a CodeBuddy data root (for example
// ~/AppData/Local/CodeBuddyExtension/Data) and returns every per-request
// usage record found in a conversation index. It keeps the historical
// uncancellable signature for direct callers; the adapter's Load passes its
// cancellation scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per conversation index, and once per request.
// On cancellation it returns ctx.Err() (matchable with
// errors.Is(err, context.Canceled) or errors.Is(err, context.DeadlineExceeded))
// and no partial result — records, issues, and quarantine counts accumulated
// so far are discarded, so a scan cut short never exports half of a
// conversation.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	clean := strings.TrimSpace(root)
	if clean == "" {
		return result, errors.New("missing input path")
	}
	files, err := collectConversationIndexes(ctx, clean)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	records := make(map[string]adapter.Record)
	diagnostics := make(map[string]adapter.LineIssue)
	conflicts := make(map[string]bool)
	issue := func(file, reason string) {
		result.Quarantined++
		if len(result.Issues) < maxIssues {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Reason: reason})
		}
	}
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		idx, reason := readIndex(path)
		if reason != "" {
			issue(path, reason)
			continue
		}
		conversationID := filepath.Base(filepath.Dir(path))
		lookup := &modelLookup{dir: filepath.Dir(path), messages: map[string]modelInfo{}, modTimes: map[string]time.Time{}}
		for _, req := range idx.Requests {
			if err := ctx.Err(); err != nil {
				return adapter.LoadResult{}, err
			}
			rec, reason, diag := parseRequest(req, conversationID, lookup)
			if reason != "" {
				issue(path, reason)
				continue
			}
			if rec == nil {
				continue
			}
			key := adapter.StringField(rec, "recordKey")
			if diag != "" {
				if _, exists := diagnostics[key]; !exists {
					diagnostics[key] = adapter.LineIssue{File: "file:" + adapter.ShortHash(path), Reason: diag}
				}
			}
			if conflicts[key] {
				continue
			}
			if old, exists := records[key]; exists {
				if !sameRecord(old, rec) {
					// Two conversations carrying different usage for the
					// same request cannot both be right: isolate it rather
					// than silently preferring one side.
					delete(records, key)
					delete(diagnostics, key)
					conflicts[key] = true
					issue(path, "conflicting usage for same request")
				}
				continue
			}
			records[key] = rec
		}
	}
	result.Records = make([]adapter.Record, 0, len(records))
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
	for _, record := range result.Records {
		key := adapter.StringField(record, "recordKey")
		entry, exists := diagnostics[key]
		if !exists || len(result.Issues) >= maxIssues {
			continue
		}
		// Local, value-free diagnostic for an emitted record whose model is
		// unattributable: the usage still exports (nothing is quarantined).
		result.Issues = append(result.Issues, entry)
	}
	return result, nil
}

// collectConversationIndexes walks the granted root and returns the sorted
// conversation index files. A missing root is a normal not-installed state and
// yields no files, no error. A workspace-level index.json (a conversation list
// with no messages directory beside it) is not a conversation and is skipped
// without being decoded. The context is checked once per walked entry,
// mirroring jsonl.FilesContext's coarse boundary.
func collectConversationIndexes(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() && strings.EqualFold(filepath.Base(root), indexFileName) {
			return []string{root}, nil
		}
		return nil, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != indexFileName {
			return nil
		}
		if !conversationDir(filepath.Dir(path)) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// conversationDir reports whether dir is a conversation directory, proven by
// the messages directory every conversation carries.
func conversationDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, messagesDirName))
	return err == nil && info.IsDir()
}

// readIndex reads and strictly decodes one conversation index. A
// non-empty reason quarantines the file and skips it.
func readIndex(path string) (conversationIndex, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return conversationIndex{}, "conversation index is not readable"
	}
	if !info.Mode().IsRegular() {
		return conversationIndex{}, "conversation index is not a regular file"
	}
	if info.Size() > maxIndexBytes {
		return conversationIndex{}, "conversation index exceeds size limit"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return conversationIndex{}, "conversation index is not readable"
	}
	var idx conversationIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&idx); err != nil {
		return conversationIndex{}, "invalid conversation index JSON"
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return conversationIndex{}, "trailing data after conversation index"
	}
	return idx, ""
}

// parseRequest builds one delta record, or returns an issue reason. A nil
// record with an empty reason means the request carries nothing to account.
func parseRequest(req indexRequest, conversationID string, models *modelLookup) (adapter.Record, string, string) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		return nil, "missing stable request identity", ""
	}
	if !terminalRequestState(req.State) {
		// In-flight, or a state this adapter does not know: the recorded
		// counters may still grow, so the request is accounted only once a
		// later scan sees it in a terminal state.
		return nil, "", ""
	}
	if req.Usage == nil {
		// A canceled turn that never reached a model records no usage.
		return nil, "", ""
	}
	if req.Usage.InputTokens == nil && req.Usage.OutputTokens == nil && req.Usage.TotalTokens == nil {
		// Older conversations keep an empty usage row
		// ({"inputTokens":null,...}) for turns whose counts were never
		// recorded. Nothing was consumed, so nothing is quarantined.
		return nil, "", ""
	}
	counts, reason := normalizeUsage(req.Usage)
	if reason != "" {
		return nil, reason, ""
	}
	if counts.totalInput == 0 && counts.output == 0 {
		return nil, "", ""
	}
	occurred, ok := requestTime(req.StartedAt)
	if !ok {
		// Conversations written by older clients record no per-turn
		// timestamp; the client writes the turn's first message file when
		// the turn starts, so its modification time is the recorded clock
		// value (verified against startedAt on sampled indexes).
		occurred, ok = models.turnTime(req)
	}
	if !ok {
		return nil, "missing request timestamp", ""
	}
	model, reason, diag := models.attribute(req)
	if reason != "" {
		return nil, reason, ""
	}
	return adapter.Record{
		"recordKey":      cbRecordKeyDomain + ":" + adapter.ShortHash(conversationID+"\x00"+id),
		"groupKey":       cbGroupKeyDomain + ":" + adapter.ShortHash(conversationID),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     occurred.Format(time.RFC3339),
		"tool":           cbTool,
		"model":          model,
		"input":          strconv.FormatUint(counts.input, 10),
		"cacheRead":      strconv.FormatUint(counts.cacheRead, 10),
		"cacheWrite":     strconv.FormatUint(counts.cacheWrite, 10),
		"output":         strconv.FormatUint(counts.output, 10),
		"adapterVersion": cbAdapterVersion,
		"sourceType":     adapter.CodeBuddyJSONSource,
	}, "", diag
}

// terminalRequestState reports whether the recorded state is final. A state
// outside this set is treated as still running (fail closed, never export a
// partial counter set).
func terminalRequestState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "complete", "completed", "canceled", "cancelled", "error", "failed":
		return true
	}
	return false
}

// normalizeUsage validates one request's counters and derives the uncached
// prompt share. It returns a non-empty reason instead of partial counts when
// the recorded numbers contradict each other.
func normalizeUsage(u *requestUsage) (usageCounts, string) {
	var counts usageCounts
	totalInput, present, ok := countValue(u.InputTokens)
	if !present || !ok {
		return counts, "invalid input tokens"
	}
	counts.totalInput = totalInput
	output, present, ok := countValue(u.OutputTokens)
	if !present || !ok {
		return counts, "invalid completion tokens"
	}
	counts.output = output
	cacheRead, _, ok := countValue(u.CacheTokens)
	if !ok {
		return counts, "invalid cache read tokens"
	}
	cacheWrite, _, ok := countValue(u.CachedWriteTokens)
	if !ok {
		return counts, "invalid cache write tokens"
	}
	cacheMiss, _, ok := countValue(u.CachedMissTokens)
	if !ok {
		return counts, "invalid cache miss tokens"
	}
	cached, addOK := adapter.AddUint64Checked(cacheRead, cacheWrite)
	if !addOK || cached > totalInput {
		return counts, "cache exceeds prompt tokens"
	}
	uncached := totalInput - cached
	if cacheMiss > 0 && cacheMiss != uncached {
		// The recorded uncached share contradicts the recorded total:
		// neither side may be silently preferred.
		return counts, "inconsistent prompt token components"
	}
	if totals, present, ok := countValue(u.TotalTokens); present {
		if !ok {
			return counts, "invalid total tokens"
		}
		combined, addOK := adapter.AddUint64Checked(totalInput, output)
		if !addOK || combined != totals {
			return counts, "inconsistent total tokens"
		}
	}
	counts.input = uncached
	counts.cacheRead = cacheRead
	counts.cacheWrite = cacheWrite
	return counts, ""
}

// countValue reads one counter as a non-negative decimal integer. present is
// false for an absent or null field, and ok is false for a present value that
// is not a valid uint64 (fraction, sign, exponent, quoted garbage).
func countValue(n *json.Number) (value uint64, present bool, ok bool) {
	if n == nil {
		return 0, false, true
	}
	v, parsed := adapter.UintAny(*n)
	if !parsed {
		return 0, true, false
	}
	return v, true, true
}

// requestTime converts the recorded epoch timestamp. Values below the
// second/millisecond boundary are treated as seconds so a schema change does
// not produce 1970 dates; anything else is a millisecond timestamp.
func requestTime(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	value, err := n.Int64()
	if err != nil || value <= 0 {
		return time.Time{}, false
	}
	if value < safeIntegerLimit {
		return time.Unix(value, 0).UTC(), true
	}
	return time.UnixMilli(value).UTC(), true
}

func sameRecord(a, b adapter.Record) bool {
	ca, errA := json.Marshal(a)
	cb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

// modelLookup resolves a request's recorded model from the message files of
// the conversation. Files are probed lazily and memoized, so one conversation
// reads at most one small file per request it can attribute.
type modelLookup struct {
	dir      string
	messages map[string]modelInfo
	// modTimes memoizes message file modification times; a zero value means
	// the file is absent and must not be probed again.
	modTimes map[string]time.Time
}

// modelInfo is the collector's view of one message file.
type modelInfo struct {
	// parsed is false when the file is missing, unreadable, oversized, torn
	// or not a JSON object: the probe then carries no attribution.
	parsed bool
	// role is the recorded message role.
	role string
	// request is extra.requestId, empty when the file records none.
	request string
	// model is extra.modelId, kept verbatim.
	model string
	// invalid marks a present modelId that fails the shared wire validation.
	invalid bool
}

// attribute returns the model recorded for the request. A non-empty reason
// quarantines the request (a present but illegal model identifier); an empty
// model with a diagnostic means "unknown" (the usage still exports).
func (l *modelLookup) attribute(req indexRequest) (string, string, string) {
	if l == nil {
		return "unknown", "", "request model not recorded; model reported unknown"
	}
	probes := 0
	for _, id := range req.Messages {
		if probes >= maxModelProbes {
			break
		}
		id = strings.TrimSpace(id)
		// A message id is a file name, so it must never carry a path.
		if id == "" || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			continue
		}
		probes++
		info := l.message(id)
		if !info.parsed || !strings.EqualFold(info.role, "assistant") {
			continue
		}
		if info.request != "" && info.request != strings.TrimSpace(req.ID) {
			// The file says it belongs to another request: never borrow
			// another turn's model.
			continue
		}
		if info.invalid {
			return "", "invalid request model identifier", ""
		}
		if info.model == "" {
			continue
		}
		return info.model, "", ""
	}
	return "unknown", "", "request model not recorded; model reported unknown"
}

// turnTime returns the modification time of the turn's first message file.
// Older clients record no per-turn timestamp but still write each message file
// when its message is created, so this filesystem clock value is the only
// recorded time left; it is never used when startedAt exists.
func (l *modelLookup) turnTime(req indexRequest) (time.Time, bool) {
	for _, raw := range req.Messages {
		id := strings.TrimSpace(raw)
		if id == "" || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			continue
		}
		if cached, seen := l.modTimes[id]; seen {
			if cached.IsZero() {
				continue
			}
			return cached, true
		}
		info, err := os.Lstat(filepath.Join(l.dir, messagesDirName, id+".json"))
		if err != nil || !info.Mode().IsRegular() || info.ModTime().IsZero() {
			l.modTimes[id] = time.Time{}
			continue
		}
		stamp := info.ModTime().UTC()
		l.modTimes[id] = stamp
		return stamp, true
	}
	return time.Time{}, false
}

// message returns the memoized view of one message file.
func (l *modelLookup) message(id string) modelInfo {
	if cached, ok := l.messages[id]; ok {
		return cached
	}
	info := modelInfo{}
	l.messages[id] = info
	path := filepath.Join(l.dir, messagesDirName, id+".json")
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > maxMessageBytes {
		return info
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return info
	}
	decoded, ok := decodeMessage(data)
	if !ok {
		return info
	}
	l.messages[id] = decoded
	return decoded
}

// decodeMessage extracts role and the extra string of one message file. The
// message body itself is never interpreted, retained, or exported.
func decodeMessage(data []byte) (modelInfo, bool) {
	var row struct {
		Role  string          `json:"role"`
		Extra json.RawMessage `json:"extra"`
	}
	if err := json.Unmarshal(data, &row); err != nil {
		return modelInfo{}, false
	}
	info := modelInfo{parsed: true, role: strings.TrimSpace(row.Role)}
	extra := bytes.TrimSpace(row.Extra)
	if len(extra) == 0 || bytes.Equal(extra, []byte("null")) {
		return info, true
	}
	if extra[0] == '"' {
		// Recorded shape: extra is a JSON-encoded string.
		var encoded string
		if err := json.Unmarshal(extra, &encoded); err != nil {
			return info, true
		}
		extra = bytes.TrimSpace([]byte(encoded))
		if len(extra) == 0 || extra[0] != '{' {
			return info, true
		}
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(extra))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return info, true
	}
	info.request = adapter.StringAny(fields["requestId"])
	value, exists := fields["modelId"]
	if !exists || value == nil {
		return info, true
	}
	if err := adapter.ValidateModel(value); err != nil {
		info.invalid = true
		return info, true
	}
	info.model = value.(string)
	return info, true
}
