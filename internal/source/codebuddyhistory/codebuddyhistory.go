// Package codebuddyhistory collects token usage from local CodeBuddy IDE
// (CodeBuddy CN) session history. CodeBuddy stores one index.json per
// conversation under the extension data directory, in the same relative layout
// on every platform:
//
//	<data>/<userId>/CodeBuddyIDE/<userId>/history/<workspace>/<conversation>/index.json
//
// where <data> is the XDG data directory on POSIX hosts
// ($XDG_DATA_HOME/CodeBuddyExtension/Data, default
// ~/.local/share/CodeBuddyExtension/Data) and
// ~/AppData/Local/CodeBuddyExtension/Data on Windows. The loader takes whatever
// ancestor the grant names, so it is layout-agnostic; the registry decides
// which layout is probed for the managed default directory.
//
// whose `requests[]` entries carry per-request usage counters. The adapter
// is passive: it only reads index.json files (plus the small per-message
// files needed for model attribution and turn timestamps) and never writes
// to the CodeBuddy directory. Conversation bodies are never interpreted,
// retained, or exported.
//
// Counter semantics, verified against recorded indexes:
//
//	{"id":"...","type":"craft","messages":["<messageId>",...],
//	 "state":"complete","startedAt":1791014053528,
//	 "usage":{"inputTokens":322180,"outputTokens":5538,"totalTokens":327718,
//	          "lastTokens":84468,"cacheTokens":240576,"cachedWriteTokens":0,
//	          "cachedMissTokens":81604,"credit":0}}
//
//   - inputTokens is the total prompt size of the turn, cached and uncached
//     prompt bytes alike.
//   - cacheTokens is the cached (cache-read) share and cachedMissTokens the
//     uncached share. The client writes 0 for cachedMissTokens on turns whose
//     usage was not broken down (the first turn of a conversation records
//     inputTokens=98927 with cacheTokens=0 / cachedMissTokens=0), so a ZERO
//     cachedMissTokens is read as "not reported", never as "the whole prompt
//     is uncached".
//   - cachedWriteTokens is carried as the cache-write share and is never
//     subtracted from the prompt: recorded turns report it beside the split
//     rather than inside it.
//   - totalTokens is inputTokens + outputTokens when present.
//
// The record uploads the uncached prompt as "input", the cached share as
// "cacheRead" and the cache-write share as "cacheWrite" (the same
// disjoint-bucket convention the Claude Code and WorkBuddy adapters use).
//
// Only completed requests are collected: running requests publish partial
// usage snapshots that would double count once the request completes, and
// canceled requests lack a startedAt timestamp. Per-request usage is a
// delta: repeated turns record their own consumption, so the loader emits
// kind="delta".
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
// attributable assistant message that belongs to that request. Turns that never
// store a separate assistant message record the model on their single user
// message instead; that message is used as a fallback, and only when its own
// extra.requestId proves it belongs to this request. Message files are bounded
// and probing is capped; when nothing is attributable the record reports
// "unknown" and a value-free local issue, never a guess.
//
// Record identity is unchanged from codebuddy-history-v1: recordKey and
// groupKey keep hashing "<conversation>/<request>" so records exported by
// earlier builds keep deduplicating. codebuddy-history-v2 only enriches the
// record with a resolved model; a stored v1 record whose counters match is
// treated as already exported instead of failing the immutable-history
// guard.
//
// The scan is stateless: every Load re-emits the full history with stable keys
// and FilterForExport drops what the outbox or quarantine already hold.
package codebuddyhistory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/source/adapter"
)

const (
	// codebuddyTool must match the canonical tool name in registry.SupportedTools.
	codebuddyTool = "CodeBuddy"
	// codebuddyAdapterVersion identifies the record layout produced here.
	codebuddyAdapterVersion = "codebuddy-history-v2"
	// codebuddyLegacyAdapterVersion is the layout that never resolved a
	// model. Stored records carrying it stay deduplicated when the only
	// difference is the newly resolved model.
	codebuddyLegacyAdapterVersion = "codebuddy-history-v1"
	// codebuddyUnknownModel marks a record whose model is not attributable.
	codebuddyUnknownModel = "unknown"
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
// Pointers keep "field absent" distinct from "field is zero": the loader
// fails closed on absent core counters instead of coercing them to zero.
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

// LoadRecords reads CodeBuddy session usage from an explicitly granted path.
// The path may be any ancestor of the history tree (typically
// ~/AppData/Local/CodeBuddyExtension/Data) or a single index.json file.
// It keeps the historical uncancellable signature for direct callers; the
// adapter's Load passes its cancellation scope through loadRecordsContext.
func LoadRecords(root string) (adapter.LoadResult, error) {
	return loadRecordsContext(context.Background(), root)
}

// loadRecordsContext scans with cancellation support: the context is checked
// during discovery, once per file, and once per request. On cancellation it
// returns ctx.Err() (matchable with errors.Is) and no partial result, so a
// scan cut short never exports half of the CodeBuddy usage.
func loadRecordsContext(ctx context.Context, root string) (adapter.LoadResult, error) {
	var result adapter.LoadResult
	clean := strings.TrimSpace(root)
	if clean == "" {
		return result, errors.New("missing input path")
	}
	files, err := discoverSessionIndexes(ctx, clean)
	if err != nil {
		return adapter.LoadResult{}, err
	}
	records := make(map[string]adapter.Record)
	diagnostics := make(map[string]adapter.LineIssue)
	conflicts := make(map[string]bool)
	issue := func(file, reason string) {
		result.Quarantined++
		if len(result.Issues) < maxIssues {
			result.Issues = append(result.Issues, adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: 0, Reason: reason})
		}
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		idx, reason := readIndex(file)
		if reason != "" {
			issue(file, reason)
			continue
		}
		conversationID := filepath.Base(filepath.Dir(file))
		models := &modelLookup{dir: filepath.Dir(file), messages: map[string]modelInfo{}, modTimes: map[string]time.Time{}}
		for _, req := range idx.Requests {
			if err := ctx.Err(); err != nil {
				return adapter.LoadResult{}, err
			}
			rec, reason, diag := parseRequest(req, conversationID, models)
			if reason != "" {
				issue(file, reason)
				continue
			}
			if rec == nil {
				continue
			}
			key := adapter.StringField(rec, "recordKey")
			if diag != "" {
				if _, exists := diagnostics[key]; !exists {
					diagnostics[key] = adapter.LineIssue{File: "file:" + adapter.ShortHash(file), Line: 0, Reason: diag}
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
					issue(file, "conflicting usage for the same CodeBuddy request")
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

// discoverSessionIndexes returns every index.json that is proven to be a
// conversation index: either it sits at <any ancestor>/history/<workspace>/
// <conversation>/index.json (the recorded layout), or its directory carries
// the messages directory every conversation writes. A workspace-level
// conversation list satisfies neither proof and is never decoded. Hidden
// directories are skipped. A root that names a single index.json file is
// accepted directly. A missing root returns an error, matching the shared
// jsonl discovery behavior.
func discoverSessionIndexes(ctx context.Context, root string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if filepath.Base(root) != indexFileName {
			return nil, fmt.Errorf("codebuddy-history input must be a directory or an index.json file")
		}
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != indexFileName || !d.Type().IsRegular() {
			return nil
		}
		if !conversationIndexPath(p) {
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

// conversationIndexPath reports whether path is structurally a conversation
// index rather than a workspace-level conversation list.
func conversationIndexPath(path string) bool {
	dir := filepath.Dir(path)
	if filepath.Base(filepath.Dir(filepath.Dir(dir))) == "history" {
		return true
	}
	return conversationDir(dir)
}

// conversationDir reports whether dir is a conversation directory, proven by
// the messages directory every conversation carries.
func conversationDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, messagesDirName))
	return err == nil && info.IsDir()
}

// readIndex reads and strictly decodes one conversation index. A non-empty
// reason quarantines the file and skips it.
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
		return nil, "completed request without id", ""
	}
	if req.State != "complete" {
		// Only completed requests carry final usage: running requests
		// publish partial snapshots (collecting them would double count
		// once the request completes) and canceled requests lack the
		// startedAt timestamp.
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
		return nil, "completed request without startedAt", ""
	}
	model, reason, diag := models.attribute(req)
	if reason != "" {
		return nil, reason, ""
	}
	return codebuddyRecord(conversationID, id, occurred, counts, model), "", diag
}

// codebuddyRecord builds the wire record. Record identity is fixed by the
// conversation and request ids so exports stay stable across rescans and
// across adapter versions.
func codebuddyRecord(conversationID, requestID string, occurred time.Time, counts usageCounts, model string) adapter.Record {
	identity := conversationID + "/" + requestID
	return adapter.Record{
		"recordKey":      "codebuddy-history:" + adapter.ShortHash(identity),
		"groupKey":       "codebuddy-request:" + adapter.ShortHash(identity),
		"resetKey":       nil,
		"kind":           "delta",
		"occurredAt":     occurred.UTC().Format(time.RFC3339),
		"tool":           codebuddyTool,
		"model":          model,
		"input":          strconv.FormatUint(counts.input, 10),
		"cacheRead":      strconv.FormatUint(counts.cacheRead, 10),
		"cacheWrite":     strconv.FormatUint(counts.cacheWrite, 10),
		"output":         strconv.FormatUint(counts.output, 10),
		"adapterVersion": codebuddyAdapterVersion,
		"sourceType":     adapter.CodeBuddyHistorySource,
	}
}

// normalizeUsage validates one request's counters and derives the uncached
// prompt share. It returns a non-empty reason instead of partial counts when
// the recorded numbers contradict each other.
func normalizeUsage(u *requestUsage) (usageCounts, string) {
	var counts usageCounts
	totalInput, present, ok := countValue(u.InputTokens)
	if !present || !ok {
		return counts, "completed request without complete token counters"
	}
	counts.totalInput = totalInput
	output, present, ok := countValue(u.OutputTokens)
	if !present || !ok {
		return counts, "completed request without complete token counters"
	}
	counts.output = output
	cacheRead, _, ok := countValue(u.CacheTokens)
	if !ok {
		return counts, "invalid cacheTokens"
	}
	cacheWrite, _, ok := countValue(u.CachedWriteTokens)
	if !ok {
		return counts, "invalid cachedWriteTokens"
	}
	cacheMiss, missPresent, ok := countValue(u.CachedMissTokens)
	if !ok {
		return counts, "invalid cachedMissTokens"
	}
	if cacheRead > totalInput {
		return counts, "cacheTokens exceeds inputTokens"
	}
	uncached := totalInput - cacheRead
	if missPresent && cacheMiss > 0 && cacheMiss != uncached {
		// The recorded uncached share contradicts the recorded total:
		// neither side may be silently preferred.
		return counts, "CodeBuddy usage cache split does not sum to inputTokens"
	}
	if totals, present, ok := countValue(u.TotalTokens); present {
		if !ok {
			return counts, "invalid totalTokens"
		}
		combined, addOK := adapter.AddUint64Checked(totalInput, output)
		if !addOK || combined != totals {
			return counts, "CodeBuddy usage totalTokens does not match known counters"
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

// modelLookup resolves a request's recorded model and turn timestamp from the
// message files of the conversation. Files are probed lazily and memoized, so
// one conversation reads at most one small file per request it can attribute.
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
//
// The assistant message is the primary source. Some turns never store a
// separate assistant message: the request carries exactly one user message
// whose extra already names the model (verified against recorded data, where a
// single-message request records modelId/modelName/requestId on the user
// message). Those turns were reported as "unknown" although the client had
// recorded the model. Such a message is accepted ONLY when its recorded
// requestId equals this request's id — the user message never grants
// attribution by proximity, because borrowing a neighbouring turn's model is
// worse than reporting "unknown".
func (l *modelLookup) attribute(req indexRequest) (string, string, string) {
	if l == nil {
		return codebuddyUnknownModel, "", "request model not recorded; model reported unknown"
	}
	requestID := strings.TrimSpace(req.ID)
	fallbackModel := ""
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
		if !info.parsed {
			continue
		}
		if info.request != "" && info.request != requestID {
			// The file says it belongs to another request: never borrow
			// another turn's model.
			continue
		}
		if strings.EqualFold(info.role, "assistant") {
			if info.invalid {
				return "", "invalid request model identifier", ""
			}
			if info.model == "" {
				continue
			}
			return info.model, "", ""
		}
		if info.request == requestID && !info.invalid && info.model != "" && fallbackModel == "" {
			// A non-assistant message that PROVES it belongs to this request.
			fallbackModel = info.model
		}
	}
	if fallbackModel != "" {
		return fallbackModel, "", ""
	}
	return codebuddyUnknownModel, "", "request model not recorded; model reported unknown"
}

// turnTime returns the modification time of the turn's first message file.
// Older clients record no per-turn timestamp but still write each message file
// when its message is created, so this filesystem clock value is the only
// recorded time left; it is never used when startedAt exists.
func (l *modelLookup) turnTime(req indexRequest) (time.Time, bool) {
	if l == nil {
		return time.Time{}, false
	}
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
				if unknownModelEquivalent(previous, record) {
					// A stored export of the same request differs only by
					// the model it could not resolve: the request is
					// already in the immutable history, so it stays
					// deduplicated.
					continue
				}
				return nil, fmt.Errorf("CodeBuddy record %s changed after export; refusing to overwrite immutable history", key)
			}
			continue
		}
		fresh = append(fresh, record)
	}
	return fresh, nil
}

// unknownModelEquivalent reports whether a stored record describes exactly the
// same request as fresh, apart from a model the stored export could not
// resolve. Both versions qualify: codebuddy-history-v1 never resolved a model,
// and codebuddy-history-v2 leaves requests whose message files are gone
// unattributable. A build that later CAN resolve the model must not fail the
// immutable-history guard, because the usage is identical and only the
// attribution improved. A stored record whose model was already resolved is
// never equivalent to a different one: that would be a rewrite, not an
// enrichment.
func unknownModelEquivalent(stored []byte, fresh adapter.Record) bool {
	decoder := json.NewDecoder(bytes.NewReader(stored))
	decoder.UseNumber()
	var old adapter.Record
	if err := decoder.Decode(&old); err != nil {
		return false
	}
	switch adapter.StringField(old, "adapterVersion") {
	case codebuddyAdapterVersion, codebuddyLegacyAdapterVersion:
	default:
		return false
	}
	if adapter.StringField(old, "model") != codebuddyUnknownModel {
		return false
	}
	if len(old) != len(fresh) {
		return false
	}
	for key, value := range fresh {
		if key == "model" || key == "adapterVersion" {
			continue
		}
		previous, exists := old[key]
		if !exists {
			return false
		}
		left, errLeft := json.Marshal(previous)
		right, errRight := json.Marshal(value)
		if errLeft != nil || errRight != nil || !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}
