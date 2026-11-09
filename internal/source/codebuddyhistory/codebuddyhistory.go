// Package codebuddyhistory collects token usage from local CodeBuddy IDE
// (CodeBuddy CN) session history. CodeBuddy stores one index.json per
// conversation under
//
//	~/AppData/Local/CodeBuddyExtension/Data/<userId>/CodeBuddyIDE/<userId>/history/<workspace>/<conversation>/index.json
//
// whose requests[] entries carry per-request usage counters. The adapter is
// passive: it reads index.json files and, only when the grant covers a
// directory, the small per-message files needed for model attribution. It
// never writes to the CodeBuddy directory, and conversation bodies are never
// interpreted, retained, or exported.
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
//   - cacheTokens is the recorded cached (cache-read) share,
//     cachedWriteTokens the cache-write share and cachedMissTokens the uncached
//     share. The split is three-way and sums to the prompt: real histories
//     satisfy inputTokens = cacheTokens + cachedWriteTokens + cachedMissTokens
//     in 1289 of 1370 rows that record all four counters, and no row satisfies
//     a read+miss form. The uncached share is therefore inputTokens minus the
//     cache-read AND cache-write shares.
//   - The client writes 0 for all three cache counters on turns whose usage was
//     not broken down (the first turn of a conversation records
//     inputTokens=98927 with cacheTokens=0 / cachedMissTokens=0), so a ZERO
//     cachedMissTokens is read as "not reported", never as "the whole prompt is
//     uncached"; no recorded row reports cache reads with a zero miss count.
//   - totalTokens is inputTokens + outputTokens when present.
//   - A row that records the prompt but omits cacheTokens or
//     cachedWriteTokens only proves the total prompt: it does not prove those
//     shares were zero, so the request is quarantined instead of exported
//     with an invented split.
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
// Timestamps: startedAt (epoch milliseconds, seconds tolerated) is the only
// accepted clock value. Older conversations record none, their message files
// carry no createdAt, and a file modification time is a transport artifact
// (backup restores and plain copies rewrite it), so a request without a valid
// startedAt is quarantined rather than uploaded with a derived time.
//
// Usage rows whose counters are all null ({inputTokens:null,...}) are old
// placeholders for turns that never recorded counts: they account for nothing
// and are skipped, not quarantined.
//
// Model attribution: the model identifier is not recorded in index.json. It
// lives in the per-message files as extra.modelId (extra is itself a JSON
// string). A request is attributed only when every attributable assistant
// message of the turn records the same model and names that request in
// extra.requestId; the fallback is the exact one-message shape seen in real
// data — the turn's original message list holds one file whose role is
// "user", whose own extra.requestId matches and whose model is legal.
// Anything else — mixed models, unnamed or unparsable messages, other roles,
// multi-message turns, or an assistant side that is merely model-less —
// reports "unknown" with a value-free local issue and still exports its
// counters. Probing stays inside the granted directory: a single-file grant
// never reads the sibling message files.
//
// Record identity is unchanged from codebuddy-history-v1: recordKey and
// groupKey keep hashing "<conversation>/<request>" so records exported by
// earlier builds keep deduplicating. codebuddy-history-v3 differs from the
// stored history only in ways the upgrades explain:
//
//   - v2 resolved the model; a stored record whose only difference is the
//     model metadata (unknown on one side, a recorded model on the other)
//     stays deduplicated.
//   - v3 subtracts the cache-write share from the uploaded input too, so a
//     stored v2 record stays deduplicated when its input differs by exactly
//     that upgrade (or not at all) and every other field matches byte for
//     byte.
//
// Counter drift beyond the upgrade, identity and timestamp changes still
// fail the immutable-history guard, and stored history is never rewritten:
// correcting historical counts is an explicit, auditable migration.
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
	// codebuddyAdapterVersion identifies the record layout produced here:
	// the three-way cache split (inputTokens = cache-read + cache-write +
	// uncached, so the uploaded input subtracts the cache-write share too)
	// and the single-user-message model fallback.
	codebuddyAdapterVersion = "codebuddy-history-v3"
	// codebuddyLegacyCountingVersion is the layout that subtracted only
	// the cache-read share from the prompt. Stored records carrying it
	// stay deduplicated across the v3 counting upgrade when the only
	// differences are the ones that upgrade explains.
	codebuddyLegacyCountingVersion = "codebuddy-history-v2"
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
	scope, err := discoverSessionIndexes(ctx, clean)
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
	for _, file := range scope.files {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		idx, reason := readIndex(file)
		if reason != "" {
			issue(file, reason)
			continue
		}
		conversationID := filepath.Base(filepath.Dir(file))
		// Metadata probing needs a directory grant: naming one index.json
		// file authorizes that file alone, so sibling message files stay
		// unread and every request reports an unknown model.
		var models *modelLookup
		if scope.dir != "" && scope.rootResolved != "" {
			models = &modelLookup{root: scope.dir, rootResolved: scope.rootResolved, dir: filepath.Dir(file), messages: map[string]modelInfo{}}
		}
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

// scanScope is what one granted input authorizes the loader to read.
type scanScope struct {
	// dir is the granted directory, empty when the grant names a single
	// index.json file. Message probing requires it.
	dir string
	// rootResolved is the granted directory with links resolved, so a
	// message reached through a linked directory outside the grant is
	// rejected instead of read. Empty when the grant is a single file or
	// the directory cannot be resolved.
	rootResolved string
	// files are the conversation indexes proven below dir (or the single
	// granted file).
	files []string
}

// discoverSessionIndexes returns every index.json that is proven to be a
// conversation index: either it sits at <any ancestor>/history/<workspace>/
// <conversation>/index.json (the recorded layout), or its directory carries
// the messages directory every conversation writes. A workspace-level
// conversation list satisfies neither proof and is never decoded. Hidden
// directories are skipped. A root that names a single index.json file is
// accepted directly, with no directory scope. A missing root returns an error,
// matching the shared jsonl discovery behavior.
func discoverSessionIndexes(ctx context.Context, root string) (scanScope, error) {
	scope := scanScope{}
	if err := ctx.Err(); err != nil {
		return scope, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return scope, err
	}
	if !info.IsDir() {
		if filepath.Base(root) != indexFileName {
			return scope, fmt.Errorf("codebuddy-history input must be a directory or an index.json file")
		}
		return scanScope{files: []string{root}}, nil
	}
	scope.dir = root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		scope.rootResolved = resolved
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
		return scope, err
	}
	sort.Strings(files)
	scope.files = files
	return scope, nil
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
	if zeroUsage(req.Usage) {
		// The client writes all-zero rows for turns that recorded no
		// consumption; there is no split to reason about.
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
		// startedAt is the only recorded clock value. A message file
		// modification time is a transport artifact (restores and copies
		// rewrite it) and would also make an unchanged request look
		// different after export, so a turn without a valid startedAt is
		// isolated instead of dated by guesswork.
		return nil, "completed request without valid startedAt", ""
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
	cacheRead, cachePresent, ok := countValue(u.CacheTokens)
	if !ok {
		return counts, "invalid cacheTokens"
	}
	cacheWrite, writePresent, ok := countValue(u.CachedWriteTokens)
	if !ok {
		return counts, "invalid cachedWriteTokens"
	}
	if !cachePresent || !writePresent {
		// A row that records the prompt but omits the split only proves
		// totalTokens worth of prompt: exporting cacheRead=0/cacheWrite=0
		// would invent a breakdown nobody recorded.
		return counts, "completed request without a recorded cache split"
	}
	cacheMiss, missPresent, ok := countValue(u.CachedMissTokens)
	if !ok {
		return counts, "invalid cachedMissTokens"
	}
	// The recorded split is three-way: inputTokens is the cache-read share plus
	// the cache-write share plus the uncached share. Verified against real
	// histories (1289 of 1370 rows with all four counters satisfy it, and no row
	// satisfies a read+miss form), so cachedWriteTokens belongs INSIDE the
	// prompt: subtracting only cacheTokens would count the write share twice in
	// the uploaded "input".
	splitSum, addOK := adapter.AddUint64Checked(cacheRead, cacheWrite)
	if !addOK || splitSum > totalInput {
		return counts, "CodeBuddy usage cache split exceeds inputTokens"
	}
	if missPresent && cacheMiss > 0 {
		if sum, sumOK := adapter.AddUint64Checked(splitSum, cacheMiss); !sumOK || sum != totalInput {
			// The recorded uncached share contradicts the recorded total:
			// neither side may be silently preferred.
			return counts, "CodeBuddy usage cache split does not sum to inputTokens"
		}
	}
	uncached := totalInput - splitSum
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

// zeroUsage reports whether every recorded counter is zero. Such a row records
// no consumption, so it needs no cache split and accounts for nothing.
func zeroUsage(u *requestUsage) bool {
	fields := []*json.Number{u.InputTokens, u.OutputTokens, u.TotalTokens, u.CacheTokens, u.CachedWriteTokens, u.CachedMissTokens}
	recorded := false
	for _, field := range fields {
		if field == nil {
			continue
		}
		value, present, ok := countValue(field)
		if !present {
			continue
		}
		if !ok || value != 0 {
			return false
		}
		recorded = true
	}
	return recorded
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

// modelLookup resolves a request's recorded model from the message files of
// one conversation. Files are probed lazily and memoized, so a conversation
// reads each attributable message file at most once. Probes never leave the
// granted directory: root is the authorized root, dir the conversation.
type modelLookup struct {
	root         string
	rootResolved string
	dir          string
	messages     map[string]modelInfo
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
// model with a diagnostic means "unknown" (the usage still exports). Only a
// turn whose attributable assistant messages all name the same recorded model
// is attributed: a turn that mixed models, lost its request attribution, or
// lists more messages than can be inspected reports unknown, because splitting
// one turn's counters across models would be a guess.
//
// The user-message fallback is accepted ONLY for the exact shape recorded in
// real data: the turn's ORIGINAL message list names exactly one file and that
// file is the user message carrying this request's model metadata
// (modelId/requestId on the user message of a one-message turn). The
// original list length decides — a multi-message turn whose extra ids
// happen to be unreadable is still multi-message — and the role must be
// explicitly "user" with an exact requestId match and a legal model.
// Tool, system or empty roles, multi-message turns and turns whose
// assistant side is merely model-less stay unknown: a user message never
// grants attribution by proximity, and borrowing a neighbouring turn's
// model is worse than reporting "unknown".
func (l *modelLookup) attribute(req indexRequest) (string, string, string) {
	if l == nil {
		return codebuddyUnknownModel, "", "request model not recorded; model reported unknown"
	}
	requestID := strings.TrimSpace(req.ID)
	ids := make([]string, 0, len(req.Messages))
	for _, raw := range req.Messages {
		id := strings.TrimSpace(raw)
		// A message id is a file name, so it must never carry a path.
		if id == "" || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return codebuddyUnknownModel, "", "request model not recorded; model reported unknown"
	}
	if len(ids) > maxModelProbes {
		return codebuddyUnknownModel, "", "request lists more messages than can be inspected; model reported unknown"
	}
	resolved := ""
	for _, id := range ids {
		info := l.message(id)
		if !info.parsed || !strings.EqualFold(info.role, "assistant") {
			continue
		}
		if info.request != requestID {
			// The file names another request (or none at all): never
			// borrow its model for this turn.
			continue
		}
		if info.invalid {
			return "", "invalid request model identifier", ""
		}
		if info.model == "" {
			continue
		}
		if resolved != "" && resolved != info.model {
			return codebuddyUnknownModel, "", "request recorded more than one model; model reported unknown"
		}
		resolved = info.model
	}
	if resolved != "" {
		return resolved, "", ""
	}
	if len(req.Messages) == 1 {
		// The verified fallback shape: the turn stores only this user
		// message and the client recorded the model on it. info.parsed
		// guarantees ids[0] == this file, so its own extra.requestId and
		// modelId carry the turn's metadata.
		info := l.message(ids[0])
		if info.parsed && strings.EqualFold(info.role, "user") && info.request == requestID && !info.invalid && info.model != "" {
			return info.model, "", ""
		}
	}
	return codebuddyUnknownModel, "", "request model not recorded; model reported unknown"
}

// insideRoot reports whether path stays inside root once cleaned. Both are
// absolute-or-relative to the same base, so a sibling or parent path is
// rejected instead of read.
func insideRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// messagePath resolves one message file inside the granted root. The
// conversation directory must stay below the authorized root, the path must
// resolve below the granted directory once every link is followed (so a linked
// messages directory pointing elsewhere cannot widen the grant), and the file
// must be a regular file reached without a link of its own.
func (l *modelLookup) messagePath(id string) (string, bool) {
	if !insideRoot(l.root, l.dir) {
		return "", false
	}
	candidate := filepath.Join(l.dir, messagesDirName, id+".json")
	if !insideRoot(l.root, candidate) {
		return "", false
	}
	stat, err := os.Lstat(candidate)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > maxMessageBytes {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || !insideRoot(l.rootResolved, resolved) {
		return "", false
	}
	return resolved, true
}

// message returns the memoized view of one message file. A probe outside the
// granted root, or any unreadable or oversized file, contributes no
// attribution.
func (l *modelLookup) message(id string) modelInfo {
	if cached, ok := l.messages[id]; ok {
		return cached
	}
	info := modelInfo{}
	l.messages[id] = info
	path, ok := l.messagePath(id)
	if !ok {
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
				if modelMetadataEquivalent(previous, record) {
					// The same request already sits in the immutable
					// history and differs only by model metadata: the
					// stored copy keeps the first configuration, so
					// the request stays deduplicated.
					continue
				}
				if legacyCountingEquivalent(previous, record) {
					// The same request already sits in the immutable
					// history exported with the v2 counting layout and
					// differs only by what the v3 upgrade explains.
					// The stored copy keeps the first configuration:
					// correcting historical counts is an explicit,
					// auditable migration, never this filter. The
					// request stays deduplicated and never re-uploads
					// under new counters.
					continue
				}
				if layoutVersionEquivalent(previous, record) {
					// The same request already sits in the immutable
					// history with byte-identical counters, identity,
					// model and timestamps; only the layout label
					// moved on. Re-uploading it under the new label
					// would duplicate history, so the stored copy
					// stays.
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

// modelMetadataEquivalent reports whether a stored record describes exactly
// the same request as fresh apart from model metadata: one side reports an
// unknown model while the other carries a resolved one. The stored record may
// come from any layout of this source (v1 never resolved a model, v2 starts
// with unknown until message metadata resolves).
//
// Only the model and the layout version may differ; counters, identity and
// the recorded time are compared byte for byte, so a usage or timestamp change
// still fails the immutable-history guard instead of being absorbed here.
func modelMetadataEquivalent(stored []byte, fresh adapter.Record) bool {
	decoder := json.NewDecoder(bytes.NewReader(stored))
	decoder.UseNumber()
	var old adapter.Record
	if err := decoder.Decode(&old); err != nil {
		return false
	}
	if !codebuddyVersion(adapter.StringField(old, "adapterVersion")) {
		return false
	}
	if adapter.StringField(fresh, "adapterVersion") != codebuddyAdapterVersion {
		return false
	}
	oldModel := adapter.StringField(old, "model")
	freshModel := adapter.StringField(fresh, "model")
	if oldModel == freshModel {
		return false
	}
	if oldModel != codebuddyUnknownModel && freshModel != codebuddyUnknownModel {
		// Both sides name a model and they disagree: that is a
		// re-attribution, not missing metadata, so it stays a conflict.
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

// codebuddyVersion reports whether version is a layout this source produced.
func codebuddyVersion(version string) bool {
	return version == codebuddyLegacyAdapterVersion || version == codebuddyLegacyCountingVersion || version == codebuddyAdapterVersion
}

// layoutVersionEquivalent reports whether a stored record and a fresh record
// describe the same request and differ ONLY by the layout version: identity,
// counters, model and timestamps are byte for byte equal. Re-emitting an
// unchanged request under a new layout label would duplicate history, so the
// stored copy stays and the request remains deduplicated. Any other
// difference, however small, still fails the immutable-history guard.
func layoutVersionEquivalent(stored []byte, fresh adapter.Record) bool {
	decoder := json.NewDecoder(bytes.NewReader(stored))
	decoder.UseNumber()
	var old adapter.Record
	if err := decoder.Decode(&old); err != nil {
		return false
	}
	storedVersion := adapter.StringField(old, "adapterVersion")
	if !codebuddyVersion(storedVersion) {
		return false
	}
	if storedVersion == adapter.StringField(fresh, "adapterVersion") {
		// Same layout: byte-equality would have short-circuited the
		// caller, so this is not a version difference at all.
		return false
	}
	if adapter.StringField(fresh, "adapterVersion") != codebuddyAdapterVersion {
		return false
	}
	if len(old) != len(fresh) {
		return false
	}
	for key, value := range fresh {
		if key == "adapterVersion" {
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

// legacyCountingEquivalent reports whether a stored codebuddy-history-v2
// record and a fresh v3 record describe the same request across the v3
// counting upgrade, so already-exported history stays deduplicated instead of
// blocking the source behind the immutable-history guard.
//
// The v3 upgrade changed exactly two recorded values relative to v2:
//
//   - input: the v2 layout subtracted only the cache-read share from the
//     prompt (input = inputTokens - cacheTokens); v3 subtracts the
//     cache-write share as well (input = inputTokens - cacheTokens -
//     cachedWriteTokens). The pair is accepted when fresh.input equals
//     stored.input (this request recorded no cache-write share, or was
//     exported with the new counting under the old version label) or when
//     fresh.input + cacheWrite equals stored.input exactly. Any other input
//     difference is real counter drift and still conflicts.
//   - model: a v2 record whose model was unknown can resolve under v3 (the
//     single-user-message fallback), so unknown -> recorded is accepted; a
//     model recorded on both sides must agree byte for byte.
//
// Every other field — identity, timestamps, cacheRead, cacheWrite, output
// and the rest of the payload — is compared byte for byte, so a record that
// changed anything else still fails the guard. Old history is never
// overwritten: the stored copy keeps the first configuration.
func legacyCountingEquivalent(stored []byte, fresh adapter.Record) bool {
	decoder := json.NewDecoder(bytes.NewReader(stored))
	decoder.UseNumber()
	var old adapter.Record
	if err := decoder.Decode(&old); err != nil {
		return false
	}
	if adapter.StringField(old, "adapterVersion") != codebuddyLegacyCountingVersion {
		return false
	}
	if adapter.StringField(fresh, "adapterVersion") != codebuddyAdapterVersion {
		return false
	}
	oldModel := adapter.StringField(old, "model")
	freshModel := adapter.StringField(fresh, "model")
	if oldModel != freshModel {
		if oldModel != codebuddyUnknownModel && freshModel != codebuddyUnknownModel {
			// Both sides resolved a model and they disagree: that is
			// a re-attribution, not an upgrade artifact, so it stays
			// a conflict.
			return false
		}
	}
	if len(old) != len(fresh) {
		return false
	}
	for key, value := range fresh {
		switch key {
		case "adapterVersion", "input", "model":
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
	oldInput, oldOK := recordCount(old, "input")
	freshInput, freshOK := recordCount(fresh, "input")
	freshWrite, writeOK := recordCount(fresh, "cacheWrite")
	if !oldOK || !freshOK || !writeOK {
		return false
	}
	if freshInput == oldInput {
		// No counting change for this request: the difference is the
		// layout version (and possibly the model) alone.
		return true
	}
	upgraded, ok := adapter.AddUint64Checked(freshInput, freshWrite)
	return ok && upgraded == oldInput
}

// recordCount reads one decimal counter field of a record.
func recordCount(record adapter.Record, field string) (uint64, bool) {
	raw, exists := record[field]
	if !exists {
		return 0, false
	}
	text, ok := raw.(string)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
