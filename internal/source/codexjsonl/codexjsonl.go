package codexjsonl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const codexTool = "Codex"

// maxCodexModelIssues caps the model diagnostics for one whole scan (all
// files combined), so pathological inputs cannot grow the issue list
// without bound; every affected record still carries "unknown".
const maxCodexModelIssues = 50

// codexIssueLog collects model diagnostics under one scan-wide cap.
type codexIssueLog struct {
	issues []adapter.LineIssue
}

func (l *codexIssueLog) add(file string, line int, reason string) {
	if len(l.issues) >= maxCodexModelIssues {
		return
	}
	l.issues = append(l.issues, adapter.LineIssue{File: file, Line: line, Reason: reason})
}

type codexUsage struct {
	Input      uint64
	CacheRead  uint64
	CacheWrite uint64
	Output     uint64
}

type codexObservation struct {
	Timestamp time.Time
	Usage     codexUsage
	Line      int
}

// codexTurnContext is one turn_context line: the model Codex recorded for
// the turn that line opens. Model is nil when the line records no model
// (absent key, null, or a payload-less line); such a turn still marks a
// boundary, because tokens consumed inside it cannot be attributed to any
// recorded model.
type codexTurnContext struct {
	Timestamp time.Time
	Line      int
	Model     *string
}

// codexEvent merges token_count observations and turn_context boundaries
// into one stream so that delta intervals and model attribution always
// share a single ordering.
type codexEvent struct {
	Timestamp   time.Time
	Line        int
	Observation *codexObservation
	TurnContext *codexTurnContext
}

// LoadRecords returns every Codex session record under path. It keeps the
// historical records-only signature for direct callers; the adapter's Load
// uses loadRecordsContext so scan also surfaces the local model diagnostics.
func LoadRecords(path string) ([]adapter.Record, error) {
	loaded, err := loadRecordsContext(context.Background(), path)
	if err != nil {
		return nil, err
	}
	return loaded.Records, nil
}

// loadRecordsContext scans with cancellation support: the context is checked
// during file discovery, once per file/line, and between streaming input
// buffers while reading a giant line. On cancellation it
// returns ctx.Err() (matching errors.Is(context.Canceled) or
// errors.Is(context.DeadlineExceeded)) and no partial result, so a scan cut
// short by its deadline never commits half of the records.
func loadRecordsContext(ctx context.Context, path string) (adapter.LoadResult, error) {
	paths, err := jsonl.FilesContext(ctx, path, jsonl.Options{})
	if err != nil {
		return adapter.LoadResult{}, err
	}
	var records []adapter.Record
	log := &codexIssueLog{}
	for _, file := range paths {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		fileRecords, err := loadCodexJSONLFile(ctx, file, log)
		if err != nil {
			return adapter.LoadResult{}, err
		}
		records = append(records, fileRecords...)
	}
	sort.Slice(records, func(i, j int) bool {
		a := adapter.StringField(records[i], "occurredAt")
		b := adapter.StringField(records[j], "occurredAt")
		if a == b {
			return adapter.StringField(records[i], "recordKey") < adapter.StringField(records[j], "recordKey")
		}
		return a < b
	})
	return adapter.LoadResult{Records: records, Issues: log.issues}, nil
}

// loadCodexJSONLFile converts one Codex session file into per-interval delta
// records, reporting model diagnostics into the scan-wide log. Each record's
// model is attributed from the turn_context lines of the same file: a delta
// between two token_count events is attributed to a model only when every
// turn that could have consumed those tokens — the turn active when the
// interval opened plus every turn opened inside it — recorded that same
// single model. Missing models and model switches inside an interval are
// ambiguity and record "unknown"; the interval is never attributed to only
// the model recorded at its end. A turn that literally recorded the model
// "unknown" is exact attribution and is never reported as a diagnostic.
// Unattributed deltas yield one diagnostic each, anchored at the closing
// token_count line; the reason names the cause (missing model, model
// switch) but never includes a recorded model value.
func loadCodexJSONLFile(ctx context.Context, path string, log *codexIssueLog) ([]adapter.Record, error) {
	var events []codexEvent
	if err := walkProjectedCodexLines(ctx, path, func(raw map[string]any, line int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		obs, ok, err := parseCodexObservation(raw, line)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if ok {
			events = append(events, codexEvent{Timestamp: obs.Timestamp, Line: obs.Line, Observation: &obs})
			return nil
		}
		if adapter.StringAny(raw["type"]) == "turn_context" {
			turn, err := parseCodexTurnContext(raw, line)
			if err != nil {
				return fmt.Errorf("%s:%d: %w", path, line, err)
			}
			events = append(events, codexEvent{Timestamp: turn.Timestamp, Line: turn.Line, TurnContext: &turn})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Line < events[j].Line
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	observations := 0
	turnsInFile := 0
	for idx := range events {
		if events[idx].Observation != nil {
			observations++
		}
		if events[idx].TurnContext != nil {
			turnsInFile++
		}
	}
	if observations < 2 {
		return nil, nil
	}
	groupKey := "codex-session:" + adapter.ShortHash(path)
	records := make([]adapter.Record, 0, observations-1)
	// currentModel is the model of the turn open at the current stream
	// position: nil before the first turn_context and for turns that record
	// no model.
	var currentModel *string
	var prev *codexObservation
	// span accumulates every model that may have consumed the tokens of the
	// open interval (prev, next observation].
	var span codexModelSpan
	for idx := range events {
		ev := events[idx]
		if ev.TurnContext != nil {
			currentModel = ev.TurnContext.Model
			if prev != nil {
				span.add(ev.TurnContext.Model)
			}
			continue
		}
		if prev != nil {
			if delta, ok := codexDelta(prev.Usage, ev.Observation.Usage); ok {
				if !span.attributable() {
					log.add(path, ev.Observation.Line, span.diagnostic(turnsInFile > 0))
				}
				records = append(records, adapter.Record{
					"recordKey":      fmt.Sprintf("codex-jsonl:%s:%d", adapter.ShortHash(path), ev.Observation.Line),
					"groupKey":       groupKey,
					"resetKey":       nil,
					"kind":           "delta",
					"occurredAt":     ev.Observation.Timestamp.UTC().Format(time.RFC3339),
					"tool":           codexTool,
					"model":          span.resolved(),
					"input":          fmt.Sprintf("%d", delta.Input),
					"cacheRead":      fmt.Sprintf("%d", delta.CacheRead),
					"cacheWrite":     fmt.Sprintf("%d", delta.CacheWrite),
					"output":         fmt.Sprintf("%d", delta.Output),
					"adapterVersion": "codex-jsonl-v1",
					"sourceType":     adapter.CodexJSONLSource,
				})
			}
		}
		prev = ev.Observation
		span = codexModelSpan{}
		span.add(currentModel)
	}
	return records, nil
}

// codexModelSpan accumulates every model that may have consumed the tokens
// of one open delta interval: the turn active when the interval opened plus
// every turn opened inside it. Codex reports cumulative counters, so the
// delta between two token_count events can straddle the tail of one turn
// and the head of the next; the interval is attributable only when every
// contributor recorded the same single model. A missing model or a model
// switch inside the interval is ambiguity: the delta reports "unknown"
// rather than guessing — in particular, the interval is never attributed to
// only the model recorded at its end.
type codexModelSpan struct {
	unknown bool
	models  []string
}

func (s *codexModelSpan) add(model *string) {
	if model == nil {
		s.unknown = true
		return
	}
	for _, seen := range s.models {
		if seen == *model {
			return
		}
	}
	s.models = append(s.models, *model)
}

// attributable reports whether the interval resolved to one exact recorded
// model. A turn that literally recorded the model "unknown" still counts as
// attributable: the attribution is exact, the value merely is "unknown", so
// it must not be misreported as a missing-model or ambiguity diagnostic.
func (s *codexModelSpan) attributable() bool {
	return !s.unknown && len(s.models) == 1
}

// resolved returns the model to record for a closed interval: the single
// recorded model when every contributor agrees, otherwise "unknown".
func (s *codexModelSpan) resolved() string {
	if s.attributable() {
		return s.models[0]
	}
	return "unknown"
}

// diagnostic explains why an interval resolved to "unknown". It names the
// cause — a missing recorded model or a model switch inside the interval —
// but never includes any recorded model value, so the reason stays safe to
// display locally alongside the file and line.
func (s *codexModelSpan) diagnostic(turnsInFile bool) string {
	reasons := make([]string, 0, 2)
	if len(s.models) > 1 {
		reasons = append(reasons, "model switch within interval")
	}
	if s.unknown {
		if turnsInFile {
			reasons = append(reasons, "no recorded model in effect")
		} else {
			reasons = append(reasons, "no turn_context in file")
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "model not attributable")
	}
	return "token_count delta recorded with model unknown: " + strings.Join(reasons, "; ")
}

// parseCodexTurnContext reads the model recorded for the turn one
// turn_context line opens. The recorded value is preserved verbatim: the
// shared adapter.ValidateModel only checks the wire shape (nonempty UTF-8,
// at most 128 bytes, no control characters) and never rewrites it. A
// missing model is not an error — the turn marks a boundary whose tokens
// report "unknown" — while a present but invalid model fails closed so
// nothing is silently remapped.
func parseCodexTurnContext(raw map[string]any, lineNo int) (codexTurnContext, error) {
	timestamp, err := time.Parse(time.RFC3339, adapter.StringAny(raw["timestamp"]))
	if err != nil {
		return codexTurnContext{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	turn := codexTurnContext{Timestamp: timestamp, Line: lineNo}
	payloadVal, hasPayload := raw["payload"]
	if !hasPayload || payloadVal == nil {
		return turn, nil
	}
	payload, ok := payloadVal.(map[string]any)
	if !ok {
		return codexTurnContext{}, errors.New("turn_context malformed payload")
	}
	modelVal, present := payload["model"]
	if !present || modelVal == nil {
		return turn, nil
	}
	if err := adapter.ValidateModel(modelVal); err != nil {
		return codexTurnContext{}, fmt.Errorf("turn_context model: %w", err)
	}
	model, _ := modelVal.(string)
	turn.Model = &model
	return turn, nil
}

func parseCodexObservation(raw map[string]any, lineNo int) (codexObservation, bool, error) {
	payload, _ := raw["payload"].(map[string]any)
	if adapter.StringAny(payload["type"]) != "token_count" {
		return codexObservation{}, false, nil
	}
	infoVal, infoPresent := payload["info"]
	if !infoPresent || infoVal == nil {
		return codexObservation{}, false, nil
	}
	info, ok := infoVal.(map[string]any)
	if !ok {
		return codexObservation{}, false, errors.New("token_count malformed info")
	}
	usageVal, usagePresent := info["total_token_usage"]
	if !usagePresent || usageVal == nil {
		return codexObservation{}, false, errors.New("token_count missing total_token_usage")
	}
	usageRaw, ok := usageVal.(map[string]any)
	if !ok {
		return codexObservation{}, false, errors.New("token_count malformed total_token_usage")
	}
	timestamp, err := time.Parse(time.RFC3339, adapter.StringAny(raw["timestamp"]))
	if err != nil {
		return codexObservation{}, false, fmt.Errorf("invalid timestamp: %w", err)
	}
	rawInput, err := counterField(usageRaw, "input_tokens", true)
	if err != nil {
		return codexObservation{}, false, err
	}
	cacheRead, err := counterField(usageRaw, "cached_input_tokens", false)
	if err != nil {
		return codexObservation{}, false, err
	}
	cacheWrite, err := counterField(usageRaw, "cache_write_input_tokens", false)
	if err != nil {
		return codexObservation{}, false, err
	}
	output, err := counterField(usageRaw, "output_tokens", true)
	if err != nil {
		return codexObservation{}, false, err
	}
	cached, ok := adapter.AddUint64Checked(cacheRead, cacheWrite)
	if !ok {
		return codexObservation{}, false, fmt.Errorf("token_count cached token sum %d + %d exceeds uint64", cacheRead, cacheWrite)
	}
	if rawInput < cached {
		return codexObservation{}, false, fmt.Errorf("token_count cached tokens %d exceed input tokens %d", cached, rawInput)
	}
	return codexObservation{Timestamp: timestamp, Line: lineNo, Usage: codexUsage{Input: rawInput - cached, CacheRead: cacheRead, CacheWrite: cacheWrite, Output: output}}, true, nil
}

func counterField(usage map[string]any, key string, required bool) (uint64, error) {
	v, present := usage[key]
	if !present || v == nil {
		if required {
			return 0, fmt.Errorf("token_count missing %s", key)
		}
		return 0, nil
	}
	n, ok := adapter.UintAny(v)
	if !ok {
		return 0, fmt.Errorf("token_count %s must be a non-negative integer within uint64 range", key)
	}
	return n, nil
}

func codexDelta(prev, cur codexUsage) (codexUsage, bool) {
	if cur.Input < prev.Input || cur.CacheRead < prev.CacheRead || cur.CacheWrite < prev.CacheWrite || cur.Output < prev.Output {
		return codexUsage{}, false
	}
	return codexUsage{Input: cur.Input - prev.Input, CacheRead: cur.CacheRead - prev.CacheRead, CacheWrite: cur.CacheWrite - prev.CacheWrite, Output: cur.Output - prev.Output}, true
}

// loadRecordsResuming is the production loader: it skips files whose
// content is byte-identical to what a previous run already exported.
//
// A real Codex history is gigabytes of JSONL. Re-decoding all of it every
// scheduled run is what made a periodic run expire before it reached an
// export commit, so unchanged files contribute nothing but their state. A
// skip is content-proven (whole-file SHA-256, see internal/local/scanledger)
// and never relies on the modification time; any file whose digest differs,
// or that cannot be digested, is parsed exactly as before.
//
// The returned ScanStates let the caller advance the ledger only after this
// scan's records are committed, so a failed export can never cause a file to
// be skipped with its records still unexported.
func loadRecordsResuming(opt adapter.Options) (adapter.LoadResult, error) {
	ctx := opt.ContextOrBackground()
	paths, err := jsonl.FilesContext(ctx, opt.Input, jsonl.Options{})
	if err != nil {
		return adapter.LoadResult{}, err
	}
	var prior map[string]scanledger.FileState
	if strings.TrimSpace(opt.StateDir) != "" {
		if loaded, _, lerr := scanledger.New(opt.StateDir).Load(adapter.CodexJSONLSource); lerr == nil {
			prior = loaded
		}
	}
	states := make(map[string]scanledger.FileState, len(paths))
	var records []adapter.Record
	log := &codexIssueLog{}
	for _, file := range paths {
		if err := ctx.Err(); err != nil {
			return adapter.LoadResult{}, err
		}
		current, unchanged, derr := scanledger.Inspect(file, prior)
		if derr == nil && unchanged {
			// Already exported, and provably unchanged: no records.
			states[file] = current
			continue
		}
		fileRecords, ferr := loadCodexJSONLFile(ctx, file, log)
		if ferr != nil {
			return adapter.LoadResult{}, ferr
		}
		records = append(records, fileRecords...)
		if derr == nil {
			states[file] = current
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a := adapter.StringField(records[i], "occurredAt")
		b := adapter.StringField(records[j], "occurredAt")
		if a == b {
			return adapter.StringField(records[i], "recordKey") < adapter.StringField(records[j], "recordKey")
		}
		return a < b
	})
	return adapter.LoadResult{Records: records, Issues: log.issues, ScanStates: states}, nil
}

func Adapter() adapter.Adapter {
	return adapter.Adapter{Source: adapter.CodexJSONLSource, Description: "Codex session JSONL", Load: func(opt adapter.Options) (adapter.LoadResult, error) {
		return loadRecordsResuming(opt)
	}, FilterForExport: func(opt adapter.Options, records []adapter.Record) ([]adapter.Record, error) {
		ctx := opt.ContextOrBackground()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(opt.StateDir) == "" {
			return records, nil
		}
		return filterKnownCodexRecordsContext(ctx, opt.StateDir, records)
	}}
}
