package codexjsonl

// Streaming compatibility tests for walkProjectedCodexLines.
//
// The walker replaced the per-line jsonl.WalkLinesContext +
// jsonl.DecodeObject decode inside loadCodexJSONLFile, so every observable
// decode decision must stay identical for the lines the shared reader could
// already handle (the legacy reader caps one line at jsonl.MaxLineBytes; the
// walker lifts that cap, which the streaming integration tests cover
// separately at 17/64 MiB). These tests use jsonl.DecodeObject as the
// oracle.
//
// Compared per line is exactly what loadCodexJSONLFile consumes:
// parseCodexObservation always runs (an error fails the line, a success
// records the observation and skips the turn), and parseCodexTurnContext
// runs only when the observation declined without an error and the
// top-level type gate matches "turn_context". The gate compares the branch
// decision, not the string, so a giant non-matching type may project to any
// sentinel that also fails the comparison; a timestamp on a line whose
// branches never read it (an ignored line) need not be kept at all.
// Successful observations and turns compare exactly, and errors compare by
// category: every parse error except the timestamp one is value-free and
// produced verbatim by the same shared code, while the timestamp errors
// wrap the offending value, which an illegal or giant timestamp only has to
// keep failing. Walk-level syntax failures only need to agree on failure
// and position, because the walker may word them differently. Visited
// physical line numbers (blank lines skipped) must match, and a failing
// walk must stop on the same line.
//
// Beyond parity, the walker must not materialize values the adapter never
// reads (giant unknown keys/values) while still validating all syntax,
// including duplicates that only appear after a giant body. All fixtures
// are synthetic; failure messages never include line bodies.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/jsonl"
)

const (
	compatTS1 = "2026-11-10T00:00:01Z"
	compatTS2 = "2026-11-10T00:00:02Z"

	// compatFuzzMaxBytes keeps fuzz inputs short; the deterministic giant
	// fixtures below already cover large-value behavior at oracle-safe
	// sizes, and the multi-MiB streaming cases live in the integration
	// tests.
	compatFuzzMaxBytes = 64 << 10
	// compatFuzzMaxDepth keeps fuzz inputs at normal nesting so the oracle
	// decoder itself stays well within stack limits.
	compatFuzzMaxDepth = 192
	// compatMaterializedBound caps any single string a projected raw line
	// may carry. Giant values the adapter never reads must be validated
	// without being materialized, so fixtures that carry them pass a bound
	// far below their size.
	compatMaterializedBound = 64 << 10
)

// compatCount builds one event_msg token_count line. usage is the raw JSON
// member text of total_token_usage, e.g. `"input_tokens":100`.
func compatCount(ts, usage string) string {
	return `{"timestamp":"` + ts + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{` + usage + `}}}}`
}

// compatTurnLine builds one turn_context line. payload is the raw JSON text
// of the payload member, e.g. `{"model":"gpt-5"}` or `null`.
func compatTurnLine(ts, payload string) string {
	return `{"timestamp":"` + ts + `","type":"turn_context","payload":` + payload + `}`
}

// compatLines joins lines with newlines and terminates the file, except
// that zero lines produce a truly empty file.
func compatLines(lines ...string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeCompatFile(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// safeCompat truncates values that leak into failure messages so a failing
// line can never dump a real body through an error text.
func safeCompat(s string) string {
	const limit = 96
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…(truncated)"
}

// compatWalkResult records what one decode path surfaced for a file.
type compatWalkResult struct {
	lines map[int]map[string]any
	order []int
	err   error
	// failLine is the physical line whose decode failed; 0 when the walk
	// failed without a line anchor or succeeded.
	failLine int
}

// oracleWalkLines replays the pre-streaming decode path: the shared
// jsonl.WalkLinesContext reader plus jsonl.DecodeObject per line. It is the
// compatibility oracle for walkProjectedCodexLines.
func oracleWalkLines(t testing.TB, path string) *compatWalkResult {
	t.Helper()
	res := &compatWalkResult{lines: make(map[int]map[string]any)}
	res.err = jsonl.WalkLinesContext(context.Background(), path, func(l jsonl.Line) error {
		raw, err := jsonl.DecodeObject(l.Text)
		if err != nil {
			res.failLine = l.Number
			return err
		}
		res.lines[l.Number] = raw
		res.order = append(res.order, l.Number)
		return nil
	})
	return res
}

func streamWalkLines(t testing.TB, path string) *compatWalkResult {
	t.Helper()
	res := &compatWalkResult{lines: make(map[int]map[string]any)}
	res.err = walkProjectedCodexLines(context.Background(), path, func(raw map[string]any, line int) error {
		if line < 1 {
			t.Fatalf("walkProjectedCodexLines reported non-positive line %d", line)
		}
		if n := len(res.order); n > 0 && line <= res.order[n-1] {
			t.Fatalf("walkProjectedCodexLines line numbers not strictly increasing: %d after %d", line, res.order[n-1])
		}
		res.lines[line] = raw
		res.order = append(res.order, line)
		return nil
	})
	return res
}

// compatDecision records the exact branch loadCodexJSONLFile takes for one
// raw line: parseCodexObservation always runs (an error fails the line, a
// success records the observation and skips the turn), and
// parseCodexTurnContext runs only when the observation declined without an
// error and the top-level type gate matches "turn_context" (a turn error
// fails the line too). kind is one of obs-error, obs-event, ignored,
// turn-error, turn-event.
type compatDecision struct {
	kind   string
	errCat string
	obs    codexObservation
	turn   codexTurnContext
}

func compatEvalDecision(raw map[string]any, line int) compatDecision {
	obs, ok, err := parseCodexObservation(raw, line)
	if err != nil {
		return compatDecision{kind: "obs-error", errCat: compatErrCategory(err)}
	}
	if ok {
		return compatDecision{kind: "obs-event", obs: obs}
	}
	if adapter.StringAny(raw["type"]) != "turn_context" {
		return compatDecision{kind: "ignored"}
	}
	turn, turnErr := parseCodexTurnContext(raw, line)
	if turnErr != nil {
		return compatDecision{kind: "turn-error", errCat: compatErrCategory(turnErr)}
	}
	return compatDecision{kind: "turn-event", turn: turn}
}

// compatErrCategory classifies one parse error. Every parse error except
// the timestamp one is value-free — the shared parsers produce it verbatim
// from shapes and counters — so its text is its own category. The timestamp
// errors wrap the offending value, which the walker need not keep
// verbatim: an illegal or giant timestamp only has to keep failing, so
// only the prefix is compared.
func compatErrCategory(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "invalid timestamp") {
		return "invalid timestamp"
	}
	return msg
}

// diffCompatLine compares the oracle raw and the stream raw of one line as
// production branch decisions. The type gate compares only the decision —
// a giant non-matching type may be projected to any sentinel that also
// fails the comparison — successful observations and turns compare
// exactly, and errors compare by category.
func diffCompatLine(line int, oldRaw, newRaw map[string]any) []string {
	var diffs []string
	oldDec := compatEvalDecision(oldRaw, line)
	newDec := compatEvalDecision(newRaw, line)
	if oldDec.kind != newDec.kind {
		diffs = append(diffs, fmt.Sprintf("branch: oracle %s vs stream %s", oldDec.kind, newDec.kind))
	}
	if oldDec.errCat != newDec.errCat {
		diffs = append(diffs, fmt.Sprintf("%s category: oracle %q vs stream %q", oldDec.kind, safeCompat(oldDec.errCat), safeCompat(newDec.errCat)))
	}
	if oldDec.kind == "obs-event" && newDec.kind == "obs-event" {
		if !oldDec.obs.Timestamp.Equal(newDec.obs.Timestamp) {
			diffs = append(diffs, fmt.Sprintf("observation timestamp: oracle %s vs stream %s", oldDec.obs.Timestamp, newDec.obs.Timestamp))
		}
		if oldDec.obs.Usage != newDec.obs.Usage {
			diffs = append(diffs, fmt.Sprintf("observation usage: oracle %+v vs stream %+v", oldDec.obs.Usage, newDec.obs.Usage))
		}
	}
	if oldDec.kind == "turn-event" && newDec.kind == "turn-event" {
		if !oldDec.turn.Timestamp.Equal(newDec.turn.Timestamp) {
			diffs = append(diffs, fmt.Sprintf("turn timestamp: oracle %s vs stream %s", oldDec.turn.Timestamp, newDec.turn.Timestamp))
		}
		switch {
		case oldDec.turn.Model == nil && newDec.turn.Model == nil:
		case oldDec.turn.Model == nil || newDec.turn.Model == nil:
			diffs = append(diffs, fmt.Sprintf("turn model presence: oracle %v vs stream %v", oldDec.turn.Model != nil, newDec.turn.Model != nil))
		case *oldDec.turn.Model != *newDec.turn.Model:
			diffs = append(diffs, fmt.Sprintf("turn model: oracle %q vs stream %q", safeCompat(*oldDec.turn.Model), safeCompat(*newDec.turn.Model)))
		}
	}
	return diffs
}

type compatOptions struct {
	// maxMaterializedString caps the longest string (object key, string
	// value, or json.Number) a raw line handed to the callback may carry.
	// Zero disables the check.
	maxMaterializedString int
}

// compareWalkCompat asserts that walkProjectedCodexLines behaves exactly
// like the oracle decode path on path: same walk success or failure, same
// visited physical lines, and per-line identical parser and gate outcomes.
// When both walks fail, the stream walk may additionally have surfaced the
// failing line itself (its events are discarded by the error), but no line
// beyond it. It returns the stream walk for follow-up assertions.
func compareWalkCompat(t testing.TB, path string, opt compatOptions) *compatWalkResult {
	t.Helper()
	oracle := oracleWalkLines(t, path)
	stream := streamWalkLines(t, path)
	name := filepath.Base(path)
	if (oracle.err != nil) != (stream.err != nil) {
		t.Fatalf("%s: walk outcome mismatch: oracle error %v, stream error %v; oracle visited %v, stream visited %v", name, oracle.err, stream.err, oracle.order, stream.order)
	}
	if oracle.err == nil {
		if len(oracle.order) != len(stream.order) {
			t.Fatalf("%s: visited lines differ: oracle %v vs stream %v", name, oracle.order, stream.order)
		}
		for idx, ln := range oracle.order {
			if stream.order[idx] != ln {
				t.Fatalf("%s: visited lines differ: oracle %v vs stream %v", name, oracle.order, stream.order)
			}
		}
	} else {
		for _, ln := range oracle.order {
			if _, ok := stream.lines[ln]; !ok {
				t.Fatalf("%s: stream walk skipped oracle-accepted line %d (stream visited %v, oracle visited %v)", name, ln, stream.order, oracle.order)
			}
		}
		for _, ln := range stream.order {
			_, accepted := oracle.lines[ln]
			beyondFailure := oracle.failLine == 0 || ln > oracle.failLine
			if !accepted && beyondFailure {
				t.Fatalf("%s: stream walk visited line %d beyond the oracle failure at line %d (stream visited %v)", name, ln, oracle.failLine, stream.order)
			}
		}
	}
	for _, ln := range oracle.order {
		streamRaw, ok := stream.lines[ln]
		if !ok {
			continue
		}
		for _, diff := range diffCompatLine(ln, oracle.lines[ln], streamRaw) {
			t.Errorf("%s line %d: %s", name, ln, diff)
		}
	}
	if opt.maxMaterializedString > 0 {
		for _, ln := range stream.order {
			compatAssertNoGiantString(t, stream.lines[ln], ln, opt.maxMaterializedString)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	return stream
}

// compatAssertNoGiantString fails when raw carries any string or number
// longer than bound, in keys or values at any depth. The message reports
// only sizes and key paths, never contents.
func compatAssertNoGiantString(t testing.TB, raw map[string]any, line, bound int) {
	t.Helper()
	var check func(v any, where string)
	check = func(v any, where string) {
		switch val := v.(type) {
		case map[string]any:
			for k, item := range val {
				if len(k) > bound {
					t.Fatalf("line %d materialized a %d-byte object key at %s", line, len(k), where)
				}
				check(item, where+"."+safeCompat(k))
			}
		case []any:
			for idx, item := range val {
				check(item, fmt.Sprintf("%s[%d]", where, idx))
			}
		case string:
			if len(val) > bound {
				t.Fatalf("line %d materialized a %d-byte string at %s", line, len(val), where)
			}
		case json.Number:
			if len(string(val)) > bound {
				t.Fatalf("line %d materialized a %d-byte number at %s", line, len(string(val)), where)
			}
		}
	}
	check(raw, "raw")
}

func compatRequireObservation(t testing.TB, res *compatWalkResult, line int) codexObservation {
	t.Helper()
	raw, ok := res.lines[line]
	if !ok {
		t.Fatalf("line %d was not visited (visited %v)", line, res.order)
	}
	obs, isObs, err := parseCodexObservation(raw, line)
	if err != nil {
		t.Fatalf("line %d: parseCodexObservation error: %v", line, err)
	}
	if !isObs {
		t.Fatalf("line %d: expected a token_count observation", line)
	}
	return obs
}

func compatRequireNoObservation(t testing.TB, res *compatWalkResult, line int) {
	t.Helper()
	raw, ok := res.lines[line]
	if !ok {
		t.Fatalf("line %d was not visited (visited %v)", line, res.order)
	}
	_, isObs, err := parseCodexObservation(raw, line)
	if err != nil {
		t.Fatalf("line %d: parseCodexObservation error: %v", line, err)
	}
	if isObs {
		t.Fatalf("line %d: unexpected token_count observation", line)
	}
}

// compatObservationError returns the parseCodexObservation error text for
// one line, failing when the line parses cleanly.
func compatObservationError(t testing.TB, res *compatWalkResult, line int) string {
	t.Helper()
	raw, ok := res.lines[line]
	if !ok {
		t.Fatalf("line %d was not visited (visited %v)", line, res.order)
	}
	_, _, err := parseCodexObservation(raw, line)
	if err == nil {
		t.Fatalf("line %d: expected a parseCodexObservation error", line)
	}
	return err.Error()
}

// compatRequireTurnBranch fails unless production would reach
// parseCodexTurnContext for the line: the observation declined without an
// error and the top-level type gate matches "turn_context".
func compatRequireTurnBranch(t testing.TB, raw map[string]any, line int) {
	t.Helper()
	if _, isObs, err := parseCodexObservation(raw, line); err != nil || isObs {
		t.Fatalf("line %d does not decline the observation branch", line)
	}
	if adapter.StringAny(raw["type"]) != "turn_context" {
		t.Fatalf("line %d is not on the turn_context branch", line)
	}
}

func compatRequireTurn(t testing.TB, res *compatWalkResult, line int) codexTurnContext {
	t.Helper()
	raw, ok := res.lines[line]
	if !ok {
		t.Fatalf("line %d was not visited (visited %v)", line, res.order)
	}
	compatRequireTurnBranch(t, raw, line)
	turn, err := parseCodexTurnContext(raw, line)
	if err != nil {
		t.Fatalf("line %d: parseCodexTurnContext error: %v", line, err)
	}
	return turn
}

// compatTurnError returns the parseCodexTurnContext error text for one
// line on the turn_context branch, failing when the turn parses cleanly.
func compatTurnError(t testing.TB, res *compatWalkResult, line int) string {
	t.Helper()
	raw, ok := res.lines[line]
	if !ok {
		t.Fatalf("line %d was not visited (visited %v)", line, res.order)
	}
	compatRequireTurnBranch(t, raw, line)
	_, err := parseCodexTurnContext(raw, line)
	if err == nil {
		t.Fatalf("line %d: expected a parseCodexTurnContext error", line)
	}
	return err.Error()
}

// TestStreamCompatMatchesOracleForSessionShapes feeds representative valid
// and malformed session lines through both decode paths: token_count and
// turn_context shapes, null and absent members, wrong shapes at every
// level the parsers read, and case sensitivity of the type fields.
func TestStreamCompatMatchesOracleForSessionShapes(t *testing.T) {
	cases := []struct{ name, content string }{
		{"token-count", compatLines(compatCount(compatTS1, `"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":10`))},
		{"token-count-minimal", compatLines(compatCount(compatTS1, `"input_tokens":1,"output_tokens":0`))},
		{"turn-context-model", compatLines(compatTurnLine(compatTS1, `{"model":"gpt-5-codex"}`))},
		{"turn-context-null-payload", compatLines(compatTurnLine(compatTS1, `null`))},
		{"turn-context-absent-payload", compatLines(`{"timestamp":"` + compatTS1 + `","type":"turn_context"}`)},
		{"turn-context-null-model", compatLines(compatTurnLine(compatTS1, `{"model":null}`))},
		{"turn-context-absent-model", compatLines(compatTurnLine(compatTS1, `{}`))},
		{"event-payload-null", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":null}`)},
		{"event-payload-absent", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg"}`)},
		{"info-null", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":null}}`)},
		{"info-absent", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count"}}`)},
		{"info-string", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":"malformed"}}`)},
		{"info-number", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":123}}`)},
		{"info-array", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":[]}}`)},
		{"info-bool", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":true}}`)},
		{"usage-null", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":null}}}`)},
		{"usage-absent", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{}}}`)},
		{"usage-string", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":"bad"}}}`)},
		{"usage-number", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":123}}}`)},
		{"usage-array", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":[]}}}`)},
		{"usage-bool", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":true}}}`)},
		{"input-null", compatLines(compatCount(compatTS1, `"input_tokens":null,"output_tokens":1`))},
		{"output-null", compatLines(compatCount(compatTS1, `"input_tokens":1,"output_tokens":null`))},
		{"cached-null", compatLines(compatCount(compatTS1, `"input_tokens":5,"cached_input_tokens":null,"output_tokens":1`))},
		{"cache-write-null", compatLines(compatCount(compatTS1, `"input_tokens":5,"cache_write_input_tokens":null,"output_tokens":1`))},
		{"timestamp-null", compatLines(`{"timestamp":null,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`)},
		{"timestamp-number", compatLines(`{"timestamp":123,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`)},
		{"timestamp-absent", compatLines(`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`)},
		{"timestamp-garbage", compatLines(compatCount("not-a-timestamp", `"input_tokens":1,"output_tokens":1`))},
		{"model-number", compatLines(compatTurnLine(compatTS1, `{"model":123}`))},
		{"model-bool", compatLines(compatTurnLine(compatTS1, `{"model":true}`))},
		{"model-object", compatLines(compatTurnLine(compatTS1, `{"model":{"id":"gpt-5"}}`))},
		{"model-array", compatLines(compatTurnLine(compatTS1, `{"model":[]}`))},
		{"model-empty", compatLines(compatTurnLine(compatTS1, `{"model":""}`))},
		{"model-whitespace-only", compatLines(compatTurnLine(compatTS1, `{"model":"   "}`))},
		{"model-nbsp-only", compatLines(compatTurnLine(compatTS1, `{"model":"\u00a0"}`))},
		{"model-too-long", compatLines(compatTurnLine(compatTS1, `{"model":"`+strings.Repeat("m", 129)+`"}`))},
		{"model-control-escape", compatLines(compatTurnLine(compatTS1, `{"model":"gpt-5\u0001"}`))},
		{"model-tab-escape", compatLines(compatTurnLine(compatTS1, `{"model":"gpt\t5"}`))},
		{"top-type-null-token-count", compatLines(`{"timestamp":"` + compatTS1 + `","type":null,"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`)},
		{"top-type-array", compatLines(`{"timestamp":"` + compatTS1 + `","type":[],"payload":{"model":"gpt-5"}}`)},
		{"top-type-number", compatLines(`{"timestamp":"` + compatTS1 + `","type":12}`)},
		{"payload-string-turn", compatLines(compatTurnLine(compatTS1, `"not-an-object"`))},
		{"payload-number-turn", compatLines(compatTurnLine(compatTS1, `123`))},
		{"payload-array-turn", compatLines(compatTurnLine(compatTS1, `[]`))},
		{"payload-bool-turn", compatLines(compatTurnLine(compatTS1, `true`))},
		{"payload-string-event", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":"not-an-object"}`)},
		{"payload-array-event", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":[]}`)},
		{"type-case-sensitive", compatLines(`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"Token_Count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`)},
		{"gate-case-sensitive", compatLines(`{"timestamp":"` + compatTS1 + `","type":"Turn_Context","payload":{"model":"gpt-5"}}`)},
		{"mixed-session", compatLines(
			`{"timestamp":"`+compatTS1+`","type":"session_meta","payload":{"id":"synthetic-session"}}`,
			``,
			`   `,
			compatTurnLine(compatTS1, `{"model":"gpt-5"}`),
			compatCount(compatTS1, `"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":10`),
			`{"timestamp":"`+compatTS2+`","type":"response_item","payload":{"type":"message","content":"synthetic text"}}`,
			compatCount(compatTS2, `"input_tokens":160,"cached_input_tokens":30,"cache_write_input_tokens":8,"output_tokens":80`),
			compatTurnLine(compatTS2, `{"model":"gpt-5-mini"}`),
		)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, tc.content), compatOptions{})
		})
	}
}

// TestStreamCompatRootShapes pins the root-value shapes: the JSON literal
// null decodes to an empty (nil) raw line that the old path accepted
// silently, while every other non-object root value is a syntax rejection.
func TestStreamCompatRootShapes(t *testing.T) {
	errorCases := []struct{ name, content string }{
		{"root-array", "[1,2]\n"},
		{"root-bool", "true\n"},
		{"root-number", "123\n"},
		{"root-string", "\"seed\"\n"},
		{"root-null-trailing-garbage", "null x\n"},
		{"root-object-trailing-garbage", "{} x\n"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, tc.content), compatOptions{})
		})
	}
	accepted := []struct {
		name    string
		content string
		visited []int
	}{
		{"root-null", "null\n", []int{1}},
		{"root-whitespace-null", " null \n", []int{1}},
		{"root-null-crlf", "null\r\n", []int{1}},
		{"root-empty-object", "{}\n", []int{1}},
		{"root-null-between-lines", compatLines(compatCount(compatTS1, `"input_tokens":1,"output_tokens":1`), "null", compatCount(compatTS2, `"input_tokens":2,"output_tokens":1`)), []int{1, 2, 3}},
		{"root-nested-unknown", "{\"unrelated\":[1,[2,{\"deep\":true}]]}\n", []int{1}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, tc.content), compatOptions{})
			if len(res.order) != len(tc.visited) {
				t.Fatalf("visited %v, want %v", res.order, tc.visited)
			}
			for idx, ln := range tc.visited {
				if res.order[idx] != ln {
					t.Fatalf("visited %v, want %v", res.order, tc.visited)
				}
			}
		})
	}
	// The root-null line itself must surface a raw that reads as no keys.
	res := compareWalkCompat(t, writeCompatFile(t, "null\n"), compatOptions{})
	if raw := res.lines[1]; raw != nil && len(raw) != 0 {
		t.Fatalf("root null surfaced %d keys", len(raw))
	}
}

// TestStreamCompatDuplicateKeysLastWins pins duplicate-key resolution:
// every duplicated member is replaced wholesale by its last occurrence, at
// every level (including escaped spellings of the same key), and never
// merged. Duplicates that only appear after a giant unrelated body must
// still win; the giant-body variants live in the giant tests below.
func TestStreamCompatDuplicateKeysLastWins(t *testing.T) {
	t.Run("top-type", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"type":"event_msg","type":"turn_context","timestamp":"`+compatTS1+`","payload":{"model":"gpt-5"}}`)), compatOptions{})
		if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "gpt-5" {
			t.Fatalf("model = %v, want gpt-5", turn.Model)
		}
	})
	t.Run("top-type-reverse", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"type":"turn_context","type":"event_msg","timestamp":"`+compatTS1+`","payload":{"model":"gpt-5"}}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
		if adapter.StringAny(res.lines[1]["type"]) == "turn_context" {
			t.Fatalf("turn branch taken for non-matching type")
		}
	})
	t.Run("timestamp-last-valid", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"garbage","timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":4,"output_tokens":1}}}}`)), compatOptions{})
		obs := compatRequireObservation(t, res, 1)
		if want, _ := time.Parse(time.RFC3339, compatTS1); !obs.Timestamp.Equal(want) {
			t.Fatalf("timestamp = %s, want %s", obs.Timestamp, compatTS1)
		}
	})
	t.Run("timestamp-last-invalid", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","timestamp":"garbage","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":4,"output_tokens":1}}}}`)), compatOptions{})
		if err := compatObservationError(t, res, 1); !strings.Contains(err, "invalid timestamp") {
			t.Fatalf("error = %q", err)
		}
	})
	t.Run("payload-object-replacement-not-merge", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"model":"first-model","type":"turn_context"},"timestamp":"`+compatTS1+`","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":5,"output_tokens":1}}},"type":"event_msg"}`)), compatOptions{})
		obs := compatRequireObservation(t, res, 1)
		if obs.Usage != (codexUsage{Input: 5, Output: 1}) {
			t.Fatalf("usage = %+v", obs.Usage)
		}
		// The gate never matches here, so production cannot observe the
		// first payload's model; the reverse case below catches a merge on
		// a line where the turn branch does run.
	})
	t.Run("payload-object-replacement-reverse", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2,"output_tokens":1}}},"payload":{"model":"second-model"},"type":"turn_context","timestamp":"`+compatTS1+`"}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
		if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "second-model" {
			t.Fatalf("model = %v, want second-model", turn.Model)
		}
	})
	t.Run("payload-null-then-object", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":null,"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":6,"output_tokens":1}}},"timestamp":"`+compatTS1+`","type":"event_msg"}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 6 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("payload-object-then-null", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":6,"output_tokens":1}}},"payload":null,"timestamp":"`+compatTS1+`","type":"event_msg"}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
	})
	t.Run("payload-type-inner", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"message","type":"token_count","info":{"total_token_usage":{"input_tokens":7,"output_tokens":1}}}}`)), compatOptions{})
		compatRequireObservation(t, res, 1)
	})
	t.Run("payload-type-inner-reverse", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"token_count","type":"message","info":{"total_token_usage":{"input_tokens":7,"output_tokens":1}}}}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
	})
	t.Run("model-inner", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"model":"first","model":"second"},"type":"turn_context","timestamp":"`+compatTS1+`"}`)), compatOptions{})
		if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "second" {
			t.Fatalf("model = %v, want second", turn.Model)
		}
	})
	t.Run("counters", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			compatCount(compatTS1, `"input_tokens":1,"input_tokens":9,"cached_input_tokens":0,"cached_input_tokens":7,"output_tokens":3,"output_tokens":4`))), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage != (codexUsage{Input: 2, CacheRead: 7, Output: 4}) {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("usage-object-last-valid", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":"bad"},"total_token_usage":{"input_tokens":2,"output_tokens":1}}}}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 2 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("usage-object-last-invalid", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2,"output_tokens":1},"total_token_usage":{"input_tokens":"bad"}}}}`)), compatOptions{})
		if err := compatObservationError(t, res, 1); !strings.Contains(err, "input_tokens") {
			t.Fatalf("error = %q", err)
		}
	})
	t.Run("info-inner-last-valid", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"timestamp":"`+compatTS1+`","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":"bad"}},"info":{"total_token_usage":{"input_tokens":6,"output_tokens":2}}}}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 6 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("escaped-key-resolves-to-duplicate", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"pay\u006coad":{"type":"token_count","info":{"total_token_usage":{"input_tokens":8,"output_tokens":1}}},"payload":{"type":"message"},"timestamp":"`+compatTS1+`"}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
	})
	t.Run("escaped-key-duplicate-reverse", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"type":"message"},"pay\u006coad":{"type":"token_count","info":{"total_token_usage":{"input_tokens":8,"output_tokens":1}}},"timestamp":"`+compatTS1+`"}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 8 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("duplicate-after-midsize-body", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"payload":{"type":"message"},"type":"response_item","body":"`+strings.Repeat("x", 64<<10)+`","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":12,"output_tokens":3}}},"timestamp":"`+compatTS2+`","type":"event_msg"}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage != (codexUsage{Input: 12, Output: 3}) {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
}

// TestStreamCompatFieldOrderIrrelevant checks that permuting member order
// at every level changes nothing.
func TestStreamCompatFieldOrderIrrelevant(t *testing.T) {
	usage := `"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":10`
	scrambled := `"output_tokens":10,"cache_write_input_tokens":5,"cached_input_tokens":20,"input_tokens":100`
	want := codexUsage{Input: 75, CacheRead: 20, CacheWrite: 5, Output: 10}
	wantTS, _ := time.Parse(time.RFC3339, compatTS1)
	orders := []string{
		`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{` + usage + `}}}}`,
		`{"payload":{"info":{"total_token_usage":{` + scrambled + `}},"type":"token_count"},"type":"event_msg","timestamp":"` + compatTS1 + `"}`,
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{` + usage + `}}},"timestamp":"` + compatTS1 + `"}`,
		`{"payload":{"info":{"total_token_usage":{` + usage + `}},"type":"token_count"},"timestamp":"` + compatTS1 + `","type":"event_msg"}`,
	}
	for idx, line := range orders {
		t.Run(fmt.Sprintf("count-order-%d", idx), func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
			obs := compatRequireObservation(t, res, 1)
			if obs.Usage != want || !obs.Timestamp.Equal(wantTS) {
				t.Fatalf("observation = %+v at %s", obs.Usage, obs.Timestamp)
			}
		})
	}
	turnOrders := []string{
		`{"timestamp":"` + compatTS1 + `","type":"turn_context","payload":{"model":"gpt-5"}}`,
		`{"payload":{"model":"gpt-5"},"type":"turn_context","timestamp":"` + compatTS1 + `"}`,
		`{"type":"turn_context","payload":{"model":"gpt-5"},"timestamp":"` + compatTS1 + `"}`,
	}
	for idx, line := range turnOrders {
		t.Run(fmt.Sprintf("turn-order-%d", idx), func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
			turn := compatRequireTurn(t, res, 1)
			if turn.Model == nil || *turn.Model != "gpt-5" || !turn.Timestamp.Equal(wantTS) {
				t.Fatalf("turn = %+v", turn)
			}
		})
	}
}

// TestStreamCompatOuterAndFieldTrim contrasts the line-level outer trim
// with field-level StringAny trimming. Unicode whitespace around the whole
// line is trimmed before decoding (the old reader behavior), while the same
// characters between JSON tokens are syntax errors, and inside string
// values they survive to StringAny, which trims Unicode whitespace when the
// parsers read type, timestamp, and string counters.
func TestStreamCompatOuterAndFieldTrim(t *testing.T) {
	count := compatCount(compatTS1, `"input_tokens":42,"output_tokens":2`)
	outerTrim := []struct {
		name    string
		wrapped string
	}{
		{"ascii", " \t" + count + " \t"},
		{"nbsp-ideographic", "\u00a0" + count + "\u3000"},
		{"nel-lineseparator", "\u0085" + count + "\u2028"},
		{"paragraphseparator-narrow", "\u2029" + count + "\u202f"},
		{"figurespace", "\u2007" + count + "\u2007"},
		{"crlf", count + "\r"},
	}
	for _, tc := range outerTrim {
		t.Run("outer-"+tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, tc.wrapped+"\n"), compatOptions{})
			if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 42 {
				t.Fatalf("usage = %+v", obs.Usage)
			}
		})
	}
	structuralErrors := []struct {
		name, line string
	}{
		{"nbsp-between-tokens", "{\u00a0\"timestamp\":\"" + compatTS1 + "\"}"},
		{"ideographic-after-value", "{\"timestamp\":\"" + compatTS1 + "\"\u3000}"},
		{"nul-between-tokens", "{\"timestamp\":\x00\"" + compatTS1 + "\"}"},
		{"raw-tab-inside-string", "{\"type\":\"a\tb\"}"},
	}
	for _, tc := range structuralErrors {
		t.Run(tc.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, compatLines(tc.line)), compatOptions{})
		})
	}
	fieldTrim := []struct {
		name    string
		line    string
		checkFn func(t *testing.T, res *compatWalkResult)
	}{
		{"type-ascii-space", `{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":" token_count ","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`, func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"type-nbsp-escape", `{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count\u00a0","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`, func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"type-nbsp-raw", "{\"timestamp\":\"" + compatTS1 + "\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\u00a0\",\"info\":{\"total_token_usage\":{\"input_tokens\":3,\"output_tokens\":1}}}}", func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"type-lineseparator", `{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"\u2028token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`, func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"timestamp-ascii-space", `{"timestamp":" ` + compatTS1 + ` ","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`, func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"timestamp-nbsp", `{"timestamp":"\u00a0` + compatTS1 + `\u00a0","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`, func(t *testing.T, res *compatWalkResult) {
			compatRequireObservation(t, res, 1)
		}},
		{"string-counter-spaces", compatCount(compatTS1, `"input_tokens":" 100 ","output_tokens":1`), func(t *testing.T, res *compatWalkResult) {
			if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 100 {
				t.Fatalf("usage = %+v", obs.Usage)
			}
		}},
		{"string-counter-nbsp", compatCount(compatTS1, `"input_tokens":"\u00a0100\u00a0","output_tokens":1`), func(t *testing.T, res *compatWalkResult) {
			if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 100 {
				t.Fatalf("usage = %+v", obs.Usage)
			}
		}},
		{"model-verbatim-inner-spaces", compatTurnLine(compatTS1, `{"model":" my custom route "}`), func(t *testing.T, res *compatWalkResult) {
			if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != " my custom route " {
				t.Fatalf("model = %q", safeCompat(fmt.Sprint(turn.Model)))
			}
		}},
		{"model-verbatim-inner-nbsp", compatTurnLine(compatTS1, `{"model":"gpt\u00a05"}`), func(t *testing.T, res *compatWalkResult) {
			if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "gpt\u00a05" {
				t.Fatalf("model = %q", safeCompat(fmt.Sprint(turn.Model)))
			}
		}},
	}
	for _, tc := range fieldTrim {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(tc.line)), compatOptions{})
			tc.checkFn(t, res)
		})
	}
	t.Run("whitespace-between-tokens", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			"{\"timestamp\" :\t\""+compatTS1+"\" ,\r\"type\" : \"event_msg\",\"payload\" : { \"type\" : \"token_count\",\"info\" : { \"total_token_usage\" : {\"input_tokens\" : 9,\"output_tokens\" : 1} } } }")), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 9 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
}

// TestStreamCompatCounterPrecision pins counter decoding: integers must
// keep full uint64 precision through the projection (json.Number
// semantics, no float64 rounding), string counters are trimmed and parsed
// as strict decimals, and fractions, exponents, signs, and out-of-range
// values are rejected — including around giant uint64-max counters with
// whitespace on either side.
func TestStreamCompatCounterPrecision(t *testing.T) {
	const maxU64 = uint64(18446744073709551615)
	rejected := []struct {
		name, usage string
		substr      string
	}{
		{"uint64-overflow-value", `"input_tokens":18446744073709551616,"output_tokens":1`, "input_tokens"},
		{"exponent", `"input_tokens":1e3,"output_tokens":1`, "input_tokens"},
		{"exponent-huge", `"input_tokens":1e308,"output_tokens":1`, "input_tokens"},
		{"exponent-string", `"input_tokens":"1e3","output_tokens":1`, "input_tokens"},
		{"fraction", `"input_tokens":1.5,"output_tokens":1`, "input_tokens"},
		{"fraction-string", `"input_tokens":"0.5","output_tokens":1`, "input_tokens"},
		{"negative", `"input_tokens":-1,"output_tokens":1`, "input_tokens"},
		{"negative-zero", `"input_tokens":-0,"output_tokens":1`, "input_tokens"},
		{"leading-zero-string", `"input_tokens":"007","output_tokens":1`, "input_tokens"},
		{"plus-string", `"input_tokens":"+1","output_tokens":1`, "input_tokens"},
		{"empty-string", `"input_tokens":"","output_tokens":1`, "input_tokens"},
		{"bool-counter", `"input_tokens":true,"output_tokens":1`, "input_tokens"},
		{"object-counter", `"input_tokens":{},"output_tokens":1`, "input_tokens"},
		{"array-counter", `"input_tokens":[],"output_tokens":1`, "input_tokens"},
		{"cached-exceeds-input", `"input_tokens":5,"cached_input_tokens":6,"output_tokens":1`, "exceed input tokens"},
		{"cached-sum-overflow", `"input_tokens":18446744073709551615,"cached_input_tokens":18446744073709551615,"cache_write_input_tokens":1,"output_tokens":1`, "cached token sum"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(compatCount(compatTS1, tc.usage))), compatOptions{})
			if err := compatObservationError(t, res, 1); !strings.Contains(err, tc.substr) {
				t.Fatalf("error = %q, want substring %q", err, tc.substr)
			}
		})
	}
	accepted := []struct {
		name  string
		usage string
		want  codexUsage
	}{
		{"uint64-max", `"input_tokens":18446744073709551615,"output_tokens":0`, codexUsage{Input: maxU64}},
		{"uint64-max-cached-split", `"input_tokens":18446744073709551615,"cached_input_tokens":18446744073709551614,"cache_write_input_tokens":1,"output_tokens":0`, codexUsage{CacheRead: maxU64 - 1, CacheWrite: 1}},
		{"pow2p53plus1", `"input_tokens":9007199254740993,"output_tokens":1`, codexUsage{Input: 9007199254740993, Output: 1}},
		{"pow2p53plus1-cached", `"input_tokens":9007199254740993,"cached_input_tokens":9007199254740992,"output_tokens":1`, codexUsage{Input: 1, CacheRead: 9007199254740992, Output: 1}},
		{"zero", `"input_tokens":0,"output_tokens":0`, codexUsage{}},
		{"string-counter", `"input_tokens":"100","output_tokens":"3"`, codexUsage{Input: 100, Output: 3}},
		{"string-counter-spaces", `"input_tokens":" 100 ","output_tokens":" 3 "`, codexUsage{Input: 100, Output: 3}},
		{"string-counter-uint64-max", `"input_tokens":" 18446744073709551615 ","output_tokens":0`, codexUsage{Input: maxU64}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(compatCount(compatTS1, tc.usage))), compatOptions{})
			if obs := compatRequireObservation(t, res, 1); obs.Usage != tc.want {
				t.Fatalf("usage = %+v, want %+v", obs.Usage, tc.want)
			}
		})
	}
	t.Run("giant-counter-whitespace-around-tokens", func(t *testing.T) {
		line := `{"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens" : 18446744073709551615 ,"output_tokens" : 0}}},"timestamp":"` + compatTS1 + `","type":"event_msg"}`
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != maxU64 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
}

// TestStreamCompatEscapesSurrogatesAndUTF8 pins escape decoding in known
// keys and values, surrogate handling (valid pairs decode, lone halves
// become U+FFFD exactly like the old decoder, raw surrogate bytes are
// invalid UTF-8), and UTF-8 validation of the whole line including unknown
// values.
func TestStreamCompatEscapesSurrogatesAndUTF8(t *testing.T) {
	t.Run("escaped-known-keys", func(t *testing.T) {
		line := `{"pay\u006coad":{"typ\u0065":"token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}},"tim\u0065stamp":"` + compatTS1 + `"}`
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 3 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("escaped-type-value", func(t *testing.T) {
		line := `{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token\u005fcount","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
		compatRequireObservation(t, res, 1)
	})
	t.Run("escaped-timestamp-value", func(t *testing.T) {
		line := `{"timestamp":"2026\u002d11\u002d10T00:00:01Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
		if want, _ := time.Parse(time.RFC3339, compatTS1); !compatRequireObservation(t, res, 1).Timestamp.Equal(want) {
			t.Fatalf("timestamp mismatch")
		}
	})
	surrogates := []struct {
		name  string
		model string
		want  string
	}{
		{"valid-pair", `\ud83d\ude00`, "\U0001F600"},
		{"lone-high", `\ud83d`, "\uFFFD"},
		{"lone-low", `\udc00`, "\uFFFD"},
		{"pair-then-lone", `\ud83d\ude00\ud83d`, "\U0001F600\uFFFD"},
	}
	for _, tc := range surrogates {
		t.Run("model-"+tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(compatTurnLine(compatTS1, `{"model":"`+tc.model+`"}`))), compatOptions{})
			if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != tc.want {
				t.Fatalf("model rune sequence mismatch for %s", tc.name)
			}
		})
	}
	t.Run("lone-surrogate-in-unknown-value", func(t *testing.T) {
		compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"unrelated":"prefix \ud800 suffix","timestamp":"`+compatTS1+`","type":"event_msg"}`)), compatOptions{})
	})
	t.Run("lone-surrogate-in-key", func(t *testing.T) {
		compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"\ud800k":1,"timestamp":"`+compatTS1+`","type":"event_msg"}`)), compatOptions{})
	})
	t.Run("escaped-delimiters-in-model", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(compatTurnLine(compatTS1, `{"model":"gpt\"5\\codex"}`))), compatOptions{})
		if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "gpt\"5\\codex" {
			t.Fatalf("model = %q", safeCompat(fmt.Sprint(turn.Model)))
		}
	})
	t.Run("raw-lineseparator-in-model", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			"{\"timestamp\":\""+compatTS1+"\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt\u2028five\"}}")), compatOptions{})
		if turn := compatRequireTurn(t, res, 1); turn.Model == nil || *turn.Model != "gpt\u2028five" {
			t.Fatalf("model = %q", safeCompat(fmt.Sprint(turn.Model)))
		}
	})
	// Raw byte-level fixtures; built as byte slices because the invalid
	// sequences cannot appear in a valid Go string literal source.
	byteCases := []struct {
		name string
		line []byte
	}{
		{"raw-0xff-in-known-value", []byte(`{"type":"a` + "\xff" + `b"}`)},
		{"raw-0xff-in-unknown-value", []byte(`{"unrelated":"aaaa` + "\xff" + `aaa","type":"x"}`)},
		{"raw-0xff-outside-value", append([]byte(`{"a":1}`), 0xff)},
		{"raw-surrogate-bytes-in-value", append(append([]byte(`{"type":"`), 0xed, 0xa0, 0xbd), []byte(`"}`)...)},
		{"overlong-utf8-in-value", append(append([]byte(`{"type":"`), 0xc0, 0x80), []byte(`"}`)...)},
		{"truncated-utf8-in-value", append(append([]byte(`{"type":"`), 0xe2, 0x82), []byte(`"}`)...)},
		{"bom-prefix", []byte("\ufeff" + `{"type":"x"}`)},
	}
	for _, tc := range byteCases {
		t.Run(tc.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, string(append(tc.line, '\n'))), compatOptions{})
		})
	}
}

// TestStreamCompatLineFraming pins physical line handling: blank lines
// (including Unicode-whitespace-only lines) are skipped but still counted,
// CRLF and missing final newlines behave as before, and a syntax failure
// stops the walk on that line.
func TestStreamCompatLineFraming(t *testing.T) {
	count1 := compatCount(compatTS1, `"input_tokens":1,"output_tokens":1`)
	count2 := compatCount(compatTS2, `"input_tokens":2,"output_tokens":1`)
	framing := []struct {
		name    string
		content string
		visited []int
	}{
		{"empty-file", "", nil},
		{"only-blank-lines", "\n\n   \n\t\n", nil},
		{"unicode-blank-lines", "\n\u00a0\n\u3000\n\u2028\n\x0b\n\x0c\n", nil},
		{"lone-cr-line", count1 + "\n\r\n" + count2 + "\n", []int{1, 3}},
		{"blanks-between", count1 + "\n\n \n\t\n\u00a0\n" + count2 + "\n", []int{1, 6}},
		{"crlf-endings", count1 + "\r\n" + count2 + "\r\n", []int{1, 2}},
		{"no-trailing-newline", count1 + "\n" + count2, []int{1, 2}},
		{"single-trailing-newline", "\n", nil},
		{"leading-blank-then-valid", "\n\n" + count2, []int{3}},
	}
	for _, tc := range framing {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, tc.content), compatOptions{})
			if len(res.order) != len(tc.visited) {
				t.Fatalf("visited %v, want %v", res.order, tc.visited)
			}
			for idx, ln := range tc.visited {
				if res.order[idx] != ln {
					t.Fatalf("visited %v, want %v", res.order, tc.visited)
				}
			}
		})
	}
	failing := []struct {
		name    string
		content string
		visited []int
	}{
		{"nul-only-line", count1 + "\n\x00\n" + count2 + "\n", []int{1}},
		{"bom-only-line", count1 + "\n\ufeff\n", []int{1}},
		{"garbage-second-line", count1 + "\n{bad\n" + count2 + "\n", []int{1}},
		{"blank-then-garbage", "\n\n{bad", nil},
		{"trailing-garbage-line", count1 + "\n" + count1 + " x\n", []int{1}},
		{"two-values-one-line", count1 + ` {"x":1}` + "\n", nil},
	}
	for _, tc := range failing {
		t.Run(tc.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, tc.content), compatOptions{})
			for idx, ln := range tc.visited {
				if res.order[idx] != ln {
					t.Fatalf("visited %v, want %v", res.order, tc.visited)
				}
			}
		})
	}
}

// compatGiantFixtures returns giant-value lines at oracle-safe sizes: far
// above compatMaterializedBound, far below the legacy 16 MiB per-line
// ceiling, so the oracle reader can decode the same line byte-for-byte.
func compatGiantFixtures() []struct {
	name    string
	line    string
	input   uint64
	output  uint64
	unknown bool
} {
	body := strings.Repeat("x", 1<<20)
	return []struct {
		name    string
		line    string
		input   uint64
		output  uint64
		unknown bool
	}{
		{
			name:    "giant-string-value-first",
			line:    `{"unrelated":"` + body + `","timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":11,"output_tokens":2}}}}`,
			input:   11,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-string-value-last",
			line:    `{"timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":12,"output_tokens":2}}},"unrelated":"` + body + `"}`,
			input:   12,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-key",
			line:    `{"` + strings.Repeat("k", 256<<10) + `":"v","timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":13,"output_tokens":2}}}}`,
			input:   13,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-number",
			line:    `{"unrelated":` + strings.Repeat("9", 512<<10) + `,"timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":14,"output_tokens":2}}}}`,
			input:   14,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-escaped-string",
			line:    `{"unrelated":"` + strings.Repeat(`\u0041`, 128<<10) + `","timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":15,"output_tokens":2}}}}`,
			input:   15,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-lone-surrogate-escapes",
			line:    `{"unrelated":"` + strings.Repeat(`\ud800`, 40960) + `","timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":16,"output_tokens":2}}}}`,
			input:   16,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-nested-arrays",
			line:    `{"unrelated":` + strings.Repeat("[", 64) + `"` + body + `"` + strings.Repeat("]", 64) + `,"timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":17,"output_tokens":2}}}}`,
			input:   17,
			output:  2,
			unknown: true,
		},
		{
			name:    "giant-payload-content",
			line:    `{"timestamp":"` + compatTS2 + `","type":"response_item","payload":{"content":"` + body + `","type":"token_count","info":{"total_token_usage":{"input_tokens":18,"output_tokens":2}}}}`,
			input:   18,
			output:  2,
			unknown: true,
		},
		{
			name:    "counters-and-duplicate-after-giant",
			line:    `{"payload":{"type":"message"},"type":"response_item","body":"` + body + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":200,"cached_input_tokens":30,"output_tokens":50}}},"timestamp":"` + compatTS2 + `","type":"event_msg"}`,
			input:   170,
			output:  50,
			unknown: true,
		},
		{
			name:    "giant-wrong-shape-payload",
			line:    `{"timestamp":"` + compatTS2 + `","type":"turn_context","payload":"` + strings.Repeat("p", 256<<10) + `"}`,
			unknown: false,
		},
		{
			name:    "giant-model-value",
			line:    `{"timestamp":"` + compatTS2 + `","type":"turn_context","payload":{"model":"` + strings.Repeat("m", 4096) + `"}}`,
			unknown: false,
		},
	}
}

// TestStreamCompatGiantValuesMatchOracle checks oracle parity for lines
// carrying giant values the adapter never reads, including counters and
// duplicate keys that only appear after the giant body, plus known-key
// giant values whose shape the parsers must still judge.
func TestStreamCompatGiantValuesMatchOracle(t *testing.T) {
	for _, fx := range compatGiantFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			res := compareWalkCompat(t, writeCompatFile(t, compatLines(fx.line)), compatOptions{})
			switch fx.name {
			case "giant-wrong-shape-payload":
				if err := compatTurnError(t, res, 1); !strings.Contains(err, "turn_context malformed payload") {
					t.Fatalf("error = %q", err)
				}
			case "giant-model-value":
				if err := compatTurnError(t, res, 1); !strings.Contains(err, "turn_context model") {
					t.Fatalf("error = %q", err)
				}
			default:
				obs := compatRequireObservation(t, res, 1)
				if obs.Usage.Input != fx.input || obs.Usage.Output != fx.output {
					t.Fatalf("usage = %+v, want input %d output %d", obs.Usage, fx.input, fx.output)
				}
			}
		})
	}
	t.Run("giant-wide-array", func(t *testing.T) {
		line := `{"unrelated":[` + strings.Repeat(`"synthetic",`, 8192) + `"end"],"timestamp":"` + compatTS2 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":19,"output_tokens":2}}}}`
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(line)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 19 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
}

// TestStreamCompatUnknownGiantValuesNotMaterialized re-runs the
// unknown-value giant fixtures with a materialization cap: the walker must
// validate every byte of a giant value it never reads without surfacing it
// in the raw line. (Known-key giant values — the wrong-shape payload and
// the oversized model — are exempt: the parsers must judge their shape and
// length, so the walker may keep what it needs there. So are the giant
// branch values of the test below, which only have to keep failing their
// comparison.)
func TestStreamCompatUnknownGiantValuesNotMaterialized(t *testing.T) {
	for _, fx := range compatGiantFixtures() {
		if !fx.unknown {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, compatLines(fx.line)), compatOptions{maxMaterializedString: compatMaterializedBound})
		})
	}
}

// TestStreamCompatUnconsumedGiantBranchValues pins the relaxation for
// branch values production never reads: a giant top-level type only has to
// keep failing the "turn_context" comparison (kept verbatim, truncated, or
// replaced by a non-matching sentinel are all fine), and a timestamp on a
// line that is neither a token_count nor a turn_context is never parsed at
// all. These lines stay out of the materialization test on purpose.
func TestStreamCompatUnconsumedGiantBranchValues(t *testing.T) {
	giantType := strings.Repeat("t", 1<<20)
	hugeTimestamp := strings.Repeat("9", 1<<20)
	t.Run("giant-type-ignored-line", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"type":"`+giantType+`","timestamp":"`+compatTS1+`","payload":{"type":"message"}}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
	})
	t.Run("giant-type-beside-token-count", func(t *testing.T) {
		// A successful observation never consults the top-level type.
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"type":"`+giantType+`","timestamp":"`+compatTS1+`","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":21,"output_tokens":2}}}}`)), compatOptions{})
		if obs := compatRequireObservation(t, res, 1); obs.Usage.Input != 21 {
			t.Fatalf("usage = %+v", obs.Usage)
		}
	})
	t.Run("huge-timestamp-on-ignored-line", func(t *testing.T) {
		res := compareWalkCompat(t, writeCompatFile(t, compatLines(
			`{"type":"event_msg","timestamp":"`+hugeTimestamp+`","payload":{"type":"message"}}`)), compatOptions{})
		compatRequireNoObservation(t, res, 1)
	})
}

// TestStreamCompatGiantValueSyntaxStillValidated checks that syntax inside
// and after giant unknown values is fully validated: broken escapes,
// truncated unicode escapes, torn strings, invalid UTF-8 bytes, and
// trailing garbage after the closed value must all fail the walk exactly
// like the oracle. These complement the multi-MiB boundary tests at
// oracle-safe sizes.
func TestStreamCompatGiantValueSyntaxStillValidated(t *testing.T) {
	body := strings.Repeat("x", 1<<20)
	count := compatCount(compatTS1, `"input_tokens":1,"output_tokens":1`)
	cases := []struct {
		name string
		line string
	}{
		{"bad-escape-inside-giant", `{"unrelated":"` + body[:512<<10] + `\q` + body[512<<10:] + `","timestamp":"` + compatTS1 + `","type":"event_msg"}`},
		{"truncated-unicode-escape-inside-giant", `{"unrelated":"` + body + `\u12","timestamp":"` + compatTS1 + `","type":"event_msg"}`},
		{"unterminated-giant-string", `{"unrelated":"` + body},
		{"trailing-garbage-after-giant", `{"unrelated":"` + body + `","timestamp":"` + compatTS1 + `"} x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, compatLines(tc.line)), compatOptions{})
		})
	}
	t.Run("invalid-utf8-inside-giant", func(t *testing.T) {
		compareWalkCompat(t, writeCompatFile(t, string([]byte(`{"unrelated":"`+body[:512<<10]+"\xff"+body[512<<10:]+`","timestamp":"`+compatTS1+`","type":"event_msg"}`+"\n"))), compatOptions{})
	})
	t.Run("valid-giant-then-bad-second-line", func(t *testing.T) {
		compareWalkCompat(t, writeCompatFile(t, `{"unrelated":"`+body+`","timestamp":"`+compatTS1+`","type":"event_msg"}`+"\n"+count+" x\n"), compatOptions{})
	})
}

// TestStreamCompatWalkIsDeterministic runs the walker twice over one file
// mixing duplicates, blank lines, and escaped values; the two runs must
// surface identical raws, so projection cannot depend on map iteration
// order.
func TestStreamCompatWalkIsDeterministic(t *testing.T) {
	content := compatLines(
		`{"payload":{"type":"message"},"type":"response_item","body":"filler","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":9,"output_tokens":1}}},"timestamp":"`+compatTS1+`","type":"event_msg"}`,
		``,
		"\u00a0",
		`{"timestamp":"`+compatTS2+`","type":"turn_context","payload":{"model":"gpt\u00a05"}}`,
		`{"\ud800k":1,"nested":{"deep":["values",true,null]}}`,
	)
	path := writeCompatFile(t, content)
	first := compareWalkCompat(t, path, compatOptions{})
	second := streamWalkLines(t, path)
	if second.err != nil {
		t.Fatalf("second walk failed: %v", second.err)
	}
	if len(first.order) != len(second.order) {
		t.Fatalf("visited %v vs %v", first.order, second.order)
	}
	for _, ln := range first.order {
		for _, diff := range diffCompatLine(ln, first.lines[ln], second.lines[ln]) {
			t.Errorf("nondeterministic line %d: %s", ln, diff)
		}
	}
}

// compatMaxJSONDepth returns the maximum bracket nesting outside strings,
// used only to keep fuzz inputs at normal depth.
func compatMaxJSONDepth(data []byte) int {
	depth, max := 0, 0
	inString, escaped := false, false
	for _, b := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			depth--
		}
	}
	return max
}

// FuzzWalkProjectedCodexLinesCompat feeds short fuzz inputs through both
// decode paths and requires the same walk validity, the same visited
// lines, and identical parser and gate outcomes per line. Inputs are
// capped at 64 KiB and normal nesting depth.
func FuzzWalkProjectedCodexLinesCompat(f *testing.F) {
	seeds := []string{
		compatCount(compatTS1, `"input_tokens":100,"cached_input_tokens":20,"output_tokens":10`),
		compatTurnLine(compatTS1, `{"model":"gpt-5"}`),
		compatLines(
			`{"timestamp":"`+compatTS1+`","type":"session_meta","payload":{"id":"synthetic-session"}}`,
			``,
			"\u00a0",
			compatCount(compatTS2, `"input_tokens":9007199254740993,"output_tokens":1`),
			compatTurnLine(compatTS2, `{"model":"\ud83d\ude00"}`),
		),
		"null\n",
		"[1,2]\n",
		"true\n{}\n",
		`{"payload":{"type":"message"},"body":"x","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":5,"output_tokens":1}}},"timestamp":"` + compatTS1 + `","type":"event_msg"}`,
		`{"pay\u006coad":{"type":"token_count","info":{"total_token_usage":{"input_tokens":" 7 ","output_tokens":0}}},"timestamp":"` + compatTS1 + `"}`,
		"\u00a0" + compatCount(compatTS1, `"input_tokens":1,"output_tokens":1`) + "\u3000",
		compatCount(compatTS1, `"input_tokens":18446744073709551616,"output_tokens":1`),
		compatCount(compatTS1, `"input_tokens":1e3,"output_tokens":1`),
		compatCount(compatTS1, `"input_tokens":" 100 ","output_tokens":1`),
		`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}} x`,
		`{"timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}`,
		"{\u00a0\"a\":1}",
		"\x00\n",
		"\ufeff{}\n",
		"\r\n \t\n",
		"{}",
		`{"a":"\ud83d"}`,
		compatTurnLine(compatTS1, `{"model":"\ud800\u0041"}`),
		compatTurnLine(compatTS1, `{"model":"\ud800\ud801\udc00"}`),
		compatTurnLine("2026-11-10T00:00:00.123456789012345678901Z", `{"model":"gpt-test"}`),
		compatTurnLine(compatTS1, `{"model":"`+strings.Repeat("m", 129)+`"}`),
		strings.Repeat("[", 100) + strings.Repeat("]", 100),
		`{"unrelated":"` + strings.Repeat("x", 8192) + `","timestamp":"` + compatTS1 + `","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":3,"output_tokens":1}}}}`,
		`{"timestamp":"` + compatTS1 + `","type":"turn_context","payload":{"model":"gpt\u00a05"}}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Add([]byte(`{"type":"a` + "\xff" + `b"}`))
	f.Add([]byte(`{"unrelated":"` + "\xed\xa0\xbd" + `"}`))
	f.Add(append(append([]byte(`{"type":"a`), 0xc0, 0x80), []byte(`"}`)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > compatFuzzMaxBytes {
			t.Skip("input above fuzz budget")
		}
		if compatMaxJSONDepth(data) > compatFuzzMaxDepth {
			t.Skip("nesting above normal depth")
		}
		path := filepath.Join(t.TempDir(), "fuzz.jsonl")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		compareWalkCompat(t, path, compatOptions{})
	})
}
