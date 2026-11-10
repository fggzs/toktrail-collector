package codexjsonl

// Unit tests for walkProjectedCodexLines.
//
// stream_compat_test.go pins behavioral parity with the old
// jsonl.DecodeObject decode path against a differential oracle, and the
// codexjsonl_test integration/boundary files cover the production
// pipeline at multi-MiB sizes. These tests cover the walker itself:
// the exact shape of the projected raw maps, duplicate-key last-wins
// resolution, tokens straddling the fixed 64 KiB window boundary
// (UTF-8 runes, \u escapes, surrogate pairs, numbers, literals, keys),
// giant irrelevant fields that must be validated but not materialized,
// illegal syntax with safe path:line:byte errors, retention bounds,
// nesting depth, cancellation, and callback error propagation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// streamTestCollect walks one in-memory file content and returns the
// visited (line, raw) pairs in order plus the walk error.
func streamTestCollect(t testing.TB, content string) ([]struct {
	line int
	raw  map[string]any
}, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []struct {
		line int
		raw  map[string]any
	}
	err := walkProjectedCodexLines(context.Background(), path, func(raw map[string]any, line int) error {
		got = append(got, struct {
			line int
			raw  map[string]any
		}{line, raw})
		return nil
	})
	return got, err
}

// streamTestWalkFile walks an existing file with a plain collector.
func streamTestWalkFile(t testing.TB, path string) ([]struct {
	line int
	raw  map[string]any
}, error) {
	t.Helper()
	var got []struct {
		line int
		raw  map[string]any
	}
	err := walkProjectedCodexLines(context.Background(), path, func(raw map[string]any, line int) error {
		got = append(got, struct {
			line int
			raw  map[string]any
		}{line, raw})
		return nil
	})
	return got, err
}

// streamTestWrite writes content to a fresh temp file and returns its
// path.
func streamTestWrite(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const streamTestTS = "2026-11-10T00:00:01Z"

// TestWalkProjectedLinesProjection pins the projected raw map: only
// timestamp, type and payload{type,model,info{total_token_usage{four
// counters}}} survive, values are decoded (escapes resolved, numbers as
// json.Number, type/timestamp pre-trimmed the way adapter.StringAny
// trims them), and null stays distinct from an absent key.
func TestWalkProjectedLinesProjection(t *testing.T) {
	line := `{"timestamp":" ` + streamTestTS + ` ","type":" event_msg ","session_id":"drop-me","payload":{"type":" token_count ","content":"drop-me","model":"gpt-5","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":10},"extra":"drop-me"}}}`
	got, err := streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].line != 1 {
		t.Fatalf("visited %+v", got)
	}
	want := map[string]any{
		"timestamp": streamTestTS,
		"type":      "event_msg",
		"payload": map[string]any{
			"type":  "token_count",
			"model": "gpt-5",
			"info": map[string]any{
				"total_token_usage": map[string]any{
					"input_tokens":             json.Number("100"),
					"cached_input_tokens":      json.Number("20"),
					"cache_write_input_tokens": json.Number("5"),
					"output_tokens":            json.Number("10"),
				},
			},
		},
	}
	if !reflect.DeepEqual(got[0].raw, want) {
		t.Fatalf("projection mismatch:\n got %#v\nwant %#v", got[0].raw, want)
	}
	obs, ok, perr := parseCodexObservation(got[0].raw, 1)
	if perr != nil || !ok {
		t.Fatalf("parseCodexObservation ok=%v err=%v", ok, perr)
	}
	if obs.Usage != (codexUsage{Input: 75, CacheRead: 20, CacheWrite: 5, Output: 10}) {
		t.Fatalf("usage = %+v", obs.Usage)
	}

	// Null members stay present-but-nil; absent members stay absent,
	// and both root shapes decode without error.
	nulls, err := streamTestCollect(t, `{"timestamp":null,"type":null,"payload":null}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(nulls) != 1 {
		t.Fatalf("visited %+v", nulls)
	}
	for _, key := range []string{"timestamp", "type", "payload"} {
		v, present := nulls[0].raw[key]
		if !present || v != nil {
			t.Fatalf("null member %q = %v (present=%v)", key, v, present)
		}
	}
	empty, err := streamTestCollect(t, "{}\n")
	if err != nil || len(empty) != 1 || len(empty[0].raw) != 0 {
		t.Fatalf("empty object: got %+v err=%v", empty, err)
	}
	rootNull, err := streamTestCollect(t, " null \n")
	if err != nil || len(rootNull) != 1 || rootNull[0].raw != nil {
		t.Fatalf("root null: got %+v err=%v", rootNull, err)
	}
}

// TestWalkProjectedLinesDuplicateLastWins pins last-wins duplicates at
// every level, including escaped spellings of the same key and
// wholesale replacement between objects and null.
func TestWalkProjectedLinesDuplicateLastWins(t *testing.T) {
	line := `{"type":"turn_context","type":"event_msg","timestamp":"garbage","timestamp":"` + streamTestTS + `","payload":{"model":"first","model":"second"},"ty\u0070e":"turn_context","payload":{"type":"token_count","model":"final","info":{"total_token_usage":{"input_tokens":1,"input_tokens":9,"output_tokens":2}}}}`
	got, err := streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("visited %+v", got)
	}
	raw := got[0].raw
	if raw["type"] != "turn_context" {
		t.Fatalf("type = %#v, want turn_context (escaped duplicate last)", raw["type"])
	}
	payload := raw["payload"].(map[string]any)
	if payload["model"] != "final" {
		t.Fatalf("model = %#v, want final", payload["model"])
	}
	usage := payload["info"].(map[string]any)["total_token_usage"].(map[string]any)
	if usage["input_tokens"] != json.Number("9") {
		t.Fatalf("input_tokens = %#v, want 9", usage["input_tokens"])
	}
	obs, ok, perr := parseCodexObservation(raw, 1)
	if perr != nil || !ok || obs.Usage.Input != 9 || obs.Usage.Output != 2 {
		t.Fatalf("observation ok=%v err=%v usage=%+v", ok, perr, obs.Usage)
	}

	// An object replaced by null drops every earlier member; null
	// replaced by an object keeps only the later one.
	replaced, err := streamTestCollect(t, `{"payload":{"model":"gone","type":"keep"},"payload":null,"type":"turn_context","timestamp":"`+streamTestTS+`"}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if v, present := replaced[0].raw["payload"]; !present || v != nil {
		t.Fatalf("payload = %#v (present=%v), want present nil", v, present)
	}
	turn, terr := parseCodexTurnContext(replaced[0].raw, 1)
	if terr != nil || turn.Model != nil {
		t.Fatalf("turn = %+v err=%v, want nil model", turn, terr)
	}
}

// streamTestPlaceAt builds one single-line file whose target token
// starts at the given 1-based byte offset within the line. The offset
// is reached by padding with a long string under an unknown key, so
// the target really sits at the requested distance into the file.
func streamTestPlaceAt(t testing.TB, pre, mid, target, post string, startByte int) string {
	t.Helper()
	n := startByte - len(pre) - len(mid) - 1
	if n < 0 {
		t.Fatalf("cannot place target at byte %d with prefix %d", startByte, len(pre)+len(mid))
	}
	return streamTestWrite(t, pre+strings.Repeat("x", n)+mid+target+post+"\n")
}

// TestWalkProjectedLinesWindowBoundaryTokens sweeps target tokens
// across the fixed 64 KiB window boundary: multi-byte UTF-8 runes,
// \u escapes (including surrogate pairs), long numbers, literals and
// projected keys must all decode byte-identically no matter where the
// refill splits them.
func TestWalkProjectedLinesWindowBoundaryTokens(t *testing.T) {
	// The buffer boundary after the first fill lies between file bytes
	// 65536 and 65537; the sweep makes every target straddle it at every
	// possible split for up to 6-byte tokens.
	sweep := []int{65533, 65534, 65535, 65536, 65537, 65538, 65539, 65540, 65541, 65542}
	modelPost := `"},"timestamp":"` + streamTestTS + `","type":"turn_context"}`

	models := []struct {
		name   string
		target string
		want   string
	}{
		{"raw-rune", "méx", "méx"},
		{"escaped-rune", `m\u00e9x`, "méx"},
		{"escaped-ascii", `m\u0067x`, "mgx"},
		{"surrogate-pair", `m\ud83d\ude00x`, "m\U0001F600x"},
		{"escaped-quote", `m\"'x`, "m\"'x"},
	}
	for _, m := range models {
		for _, start := range sweep {
			t.Run(fmt.Sprintf("%s-at-%d", m.name, start), func(t *testing.T) {
				path := streamTestPlaceAt(t, `{"pad":"`, `","payload":{"model":"`, m.target, modelPost, start)
				got, err := streamTestWalkFile(t, path)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 {
					t.Fatalf("visited %+v", got)
				}
				turn, terr := parseCodexTurnContext(got[0].raw, 1)
				if terr != nil {
					t.Fatal(terr)
				}
				if turn.Model == nil || *turn.Model != m.want {
					t.Fatalf("model = %v, want %q", turn.Model, m.want)
				}
			})
		}
	}

	// A projected key written with escapes must still match when the
	// escape straddles the boundary.
	keyPost := `":"gpt-5"},"timestamp":"` + streamTestTS + `","type":"turn_context"}`
	for _, start := range sweep {
		t.Run(fmt.Sprintf("escaped-key-at-%d", start), func(t *testing.T) {
			path := streamTestPlaceAt(t, `{"pad":"`, `","payload":{"`, `mod\u0065l`, keyPost, start)
			got, err := streamTestWalkFile(t, path)
			if err != nil {
				t.Fatal(err)
			}
			turn, terr := parseCodexTurnContext(got[0].raw, 1)
			if terr != nil {
				t.Fatal(terr)
			}
			if turn.Model == nil || *turn.Model != "gpt-5" {
				t.Fatalf("model = %v, want gpt-5", turn.Model)
			}
		})
	}

	// A full-precision uint64 counter and the null literal straddling
	// the boundary.
	const maxU64 = "18446744073709551615"
	countMid := `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":`
	countPost := `,"output_tokens":1}}},"timestamp":"` + streamTestTS + `","type":"event_msg"}`
	for _, start := range sweep {
		t.Run(fmt.Sprintf("counter-at-%d", start), func(t *testing.T) {
			path := streamTestPlaceAt(t, `{"pad":"`, countMid, maxU64, countPost, start)
			got, err := streamTestWalkFile(t, path)
			if err != nil {
				t.Fatal(err)
			}
			obs, ok, perr := parseCodexObservation(got[0].raw, 1)
			if perr != nil || !ok || obs.Usage.Input != 18446744073709551615 {
				t.Fatalf("ok=%v err=%v usage=%+v", ok, perr, obs.Usage)
			}
		})
	}
	for _, start := range sweep {
		t.Run(fmt.Sprintf("null-literal-at-%d", start), func(t *testing.T) {
			path := streamTestPlaceAt(t, `{"pad":"`, `","junk":`, `null`, `,"type":"event_msg"}`, start)
			if _, err := streamTestWalkFile(t, path); err != nil {
				t.Fatal(err)
			}
		})
	}

	// Lines sized around the buffer boundary itself stay valid.
	for _, size := range []int{65535, 65536, 65537, 65538} {
		t.Run(fmt.Sprintf("line-%d", size), func(t *testing.T) {
			line := `{"pad":"` + strings.Repeat("x", size-len(`{"pad":"","type":"event_msg"}`)) + `","type":"event_msg"}`
			if len(line) != size {
				t.Fatalf("line built at %d bytes, want %d", len(line), size)
			}
			if _, err := streamTestCollect(t, line+"\n"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestWalkProjectedLinesMultiWindowGiantStrings drives strings many
// buffers long, mixing plain bytes, raw multi-byte runes and \u
// escapes, under both unknown keys and (bounded) projected keys.
func TestWalkProjectedLinesMultiWindowGiantStrings(t *testing.T) {
	segment := strings.Repeat("x", 4096) + strings.Repeat("é", 1024) + strings.Repeat(`\u0041`, 1024) + strings.Repeat("y", 4096)
	giant := strings.Repeat(segment, 12) // ~2.5 MiB, dozens of refills
	line := `{"unrelated":"` + giant + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":7,"output_tokens":3}}},"timestamp":"` + streamTestTS + `","type":"event_msg"}`
	got, err := streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	obs, ok, perr := parseCodexObservation(got[0].raw, 1)
	if perr != nil || !ok || obs.Usage.Input != 7 || obs.Usage.Output != 3 {
		t.Fatalf("ok=%v err=%v usage=%+v", ok, perr, obs.Usage)
	}
}

// streamTestAssertBounded fails when raw carries any string or number
// longer than bound, in keys or values at any depth.
func streamTestAssertBounded(t testing.TB, raw map[string]any, bound int) {
	t.Helper()
	var check func(v any)
	check = func(v any) {
		switch val := v.(type) {
		case map[string]any:
			for k, item := range val {
				if len(k) > bound {
					t.Fatalf("materialized a %d-byte key", len(k))
				}
				check(item)
			}
		case []any:
			for _, item := range val {
				check(item)
			}
		case string:
			if len(val) > bound {
				t.Fatalf("materialized a %d-byte string", len(val))
			}
		case json.Number:
			if len(string(val)) > bound {
				t.Fatalf("materialized a %d-byte number", len(string(val)))
			}
		}
	}
	check(raw)
}

// TestWalkProjectedLinesGiantIrrelevantFieldsNotMaterialized feeds a
// multi-MiB line whose bulk lives under keys the adapter never reads:
// the whole line is validated, the counters after the giant bodies are
// still projected exactly, and nothing giant reaches the raw map.
func TestWalkProjectedLinesGiantIrrelevantFieldsNotMaterialized(t *testing.T) {
	body := strings.Repeat("x", 1<<20)
	line := `{"unrelated":"` + body + `","also":["` + body + `",` + strings.Repeat("9", 100<<10) + `,{"deep":{"deeper":"` + body + `"}}],"payload":{"type":"token_count","content":"` + body + `","info":{"total_token_usage":{"input_tokens":42,"output_tokens":6}}},"timestamp":"` + streamTestTS + `","type":"event_msg"}`
	got, err := streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("visited %+v", got)
	}
	streamTestAssertBounded(t, got[0].raw, 4096)
	obs, ok, perr := parseCodexObservation(got[0].raw, 1)
	if perr != nil || !ok || obs.Usage.Input != 42 || obs.Usage.Output != 6 {
		t.Fatalf("ok=%v err=%v usage=%+v", ok, perr, obs.Usage)
	}
}

// TestWalkProjectedLinesIllegalSyntax walks malformed lines and checks
// that every failure is a path:line:byte-anchored streamError that
// never echoes line content, with the right physical line number.
func TestWalkProjectedLinesIllegalSyntax(t *testing.T) {
	const secret = "STREAMSECRET"
	cases := []struct {
		name     string
		content  string
		wantLine int
		reason   string
	}{
		{"unterminated-string", "{\"type\":\"" + secret, 1, reasonUnexpected},
		{"trailing-data", `{"type":"ok"} ` + secret, 1, reasonTrailing},
		{"bad-escape", `{"type":"a\q` + secret + `"}`, 1, reasonInEscape},
		{"bad-hex-escape", `{"type":"a\uZZ` + secret + `"}`, 1, reasonInHexEscape},
		{"raw-tab-in-string", "{\"type\":\"a\t" + secret + "\"}", 1, reasonInString},
		{"missing-colon", `{"a" ` + secret + `}`, 1, reasonAfterKey},
		{"after-pair", `{"a":1"x":2}`, 1, reasonAfterPair},
		{"after-zero", `{"a":01}`, 1, reasonAfterZero},
		{"after-decimal-point", `{"a":1.` + secret[0:1] + `}`, 1, reasonAfterPoint},
		{"in-exponent", `{"a":1e` + secret[0:1] + `}`, 1, reasonInExponent},
		{"object-trailing-comma", `{"a":1,}`, 1, reasonObjectKey},
		{"array-trailing-comma", `{"a":[1,]}`, 1, reasonBeginValue},
		{"torn-literal", "nul", 1, reasonUnexpected},
		{"root-array", "[1,2]\n", 1, "cannot unmarshal array"},
		{"root-number", "123\n", 1, "cannot unmarshal number"},
		{"root-bool", "true\n", 1, "cannot unmarshal bool"},
		{"root-string", `"seed"` + "\n", 1, "cannot unmarshal string"},
		{"line-three", "{\"type\":\"ok\"}\n\r\n\n{bad", 4, reasonObjectKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := streamTestWrite(t, tc.content)
			_, err := streamTestWalkFile(t, path)
			if err == nil {
				t.Fatal("walk accepted malformed input")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked line content: %v", err)
			}
			var serr *streamError
			if !errors.As(err, &serr) {
				t.Fatalf("error is %T, want *streamError: %v", err, err)
			}
			if serr.Path != path || serr.Line != tc.wantLine || serr.Byte < 1 {
				t.Fatalf("error location = %s:%d:%d, want %s:%d:>=1", serr.Path, serr.Line, serr.Byte, path, tc.wantLine)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error %q does not contain reason %q", err, tc.reason)
			}
			wantForm := regexp.MustCompile(`^.+:\d+:\d+: .+$`)
			if !wantForm.MatchString(err.Error()) {
				t.Fatalf("error not in path:line:byte form: %q", err)
			}
		})
	}
	// Invalid UTF-8 and torn runes inside strings are UTF-8 failures
	// wherever they appear, including under unknown keys.
	byteCases := []struct {
		name string
		line []byte
	}{
		{"invalid-utf8-known", []byte(`{"type":"a` + "\xff" + `b"}`)},
		{"invalid-utf8-unknown", []byte(`{"unrelated":"a` + "\xff" + `b","type":"x"}`)},
		{"torn-rune", append(append([]byte(`{"type":"a`), 0xe2, 0x82), []byte(`"}`)...)},
		{"surrogate-bytes", append(append([]byte(`{"type":"a`), 0xed, 0xa0, 0xbd), []byte(`"}`)...)},
	}
	for _, tc := range byteCases {
		t.Run(tc.name, func(t *testing.T) {
			path := streamTestWrite(t, string(append(tc.line, '\n')))
			_, err := streamTestWalkFile(t, path)
			if err == nil || !strings.Contains(err.Error(), reasonUTF8) {
				t.Fatalf("err = %v, want %q", err, reasonUTF8)
			}
		})
	}
	// A raw newline inside a JSON string is illegal and never crosses
	// lines: the failure anchors at the line the string started on.
	path := streamTestWrite(t, "{\"type\":\"a\n"+secret+"\"}\n")
	_, err := streamTestWalkFile(t, path)
	if err == nil || !strings.Contains(err.Error(), path+":1") || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
}

// TestWalkProjectedLinesRetentionBounds pins the semantic limits: an
// oversized model keeps 129 bytes (still over the 128-byte wire limit),
// oversized counters keep a prefix that can never parse as uint64, and
// projected strings past the 64 KiB bound become the empty string,
// which no type gate matches and no timestamp parse accepts.
func TestWalkProjectedLinesRetentionBounds(t *testing.T) {
	// Model: 5000 bytes retained as 129, still rejected by the wire
	// check with the same message the full value produced.
	line := `{"type":"turn_context","timestamp":"` + streamTestTS + `","payload":{"model":"` + strings.Repeat("m", 5000) + `"}}`
	got, err := streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	model := got[0].raw["payload"].(map[string]any)["model"].(string)
	if len(model) != 129 {
		t.Fatalf("retained model is %d bytes, want 129", len(model))
	}
	_, terr := parseCodexTurnContext(got[0].raw, 1)
	if terr == nil || !strings.Contains(terr.Error(), "at most 128 bytes") {
		t.Fatalf("turn error = %v", terr)
	}

	// Counter: a 40-digit number keeps a 32-byte prefix that can never
	// parse, with the same strict-decimal error as the full literal.
	line = `{"type":"event_msg","timestamp":"` + streamTestTS + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":` + strings.Repeat("9", 40) + `,"output_tokens":1}}}}`
	got, err = streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	number := got[0].raw["payload"].(map[string]any)["info"].(map[string]any)["total_token_usage"].(map[string]any)["input_tokens"].(json.Number)
	if len(string(number)) != 32 {
		t.Fatalf("retained counter number is %d bytes, want 32", len(string(number)))
	}
	_, _, perr := parseCodexObservation(got[0].raw, 1)
	if perr == nil || !strings.Contains(perr.Error(), "non-negative integer") {
		t.Fatalf("observation error = %v", perr)
	}

	// Timestamps that are invalid regardless of size must fail the
	// existing validation both within and past the retention bound; the
	// exact over-bound retention policy (empty stand-in or bounded
	// prefix) is allowed to evolve, the rejection is not.
	inBound := strings.Repeat("t", 100)
	line = `{"type":"event_msg","timestamp":"` + inBound + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`
	got, err = streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if ts := got[0].raw["timestamp"].(string); ts != inBound {
		t.Fatalf("in-bound timestamp = %q, want exact retention", ts)
	}
	_, _, perr = parseCodexObservation(got[0].raw, 1)
	if perr == nil || !strings.Contains(perr.Error(), "invalid timestamp") {
		t.Fatalf("in-bound timestamp error = %v", perr)
	}
	line = `{"type":"event_msg","timestamp":"` + strings.Repeat("t", 70000) + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`
	got, err = streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if ts, ok := got[0].raw["timestamp"].(string); !ok || len(ts) > 70000 {
		t.Fatalf("over-bound timestamp retained %d bytes", len(ts))
	}
	_, _, perr = parseCodexObservation(got[0].raw, 1)
	if perr == nil || !strings.Contains(perr.Error(), "invalid timestamp") {
		t.Fatalf("over-bound timestamp error = %v", perr)
	}

	// A type value past the retention bound can never match a gate
	// constant, so the line is skipped exactly like any other
	// unmatched type, without failing the walk.
	line = `{"type":"` + strings.Repeat("t", 70000) + `","timestamp":"` + streamTestTS + `","payload":{"model":"gpt-5"}}`
	got, err = streamTestCollect(t, line+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if typ, ok := got[0].raw["type"].(string); !ok || len(typ) > 70000 {
		t.Fatalf("over-bound type retained %d bytes", len(typ))
	}
	if typ := got[0].raw["type"].(string); typ == "turn_context" || typ == "event_msg" {
		t.Fatalf("over-bound type matched a gate: %q", typ)
	}
}

// TestWalkProjectedLinesNestingDepth pins the encoding/json depth
// budget: 10000 nested containers parse, 10001 fail, and the failure
// names the depth.
func TestWalkProjectedLinesNestingDepth(t *testing.T) {
	build := func(depth int) string {
		return `{"unrelated":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `,"type":"event_msg"}`
	}
	atLimit := build(9999) // root object + 9999 arrays = 10000 containers
	got, err := streamTestCollect(t, atLimit+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].raw["type"] != "event_msg" {
		t.Fatalf("type = %#v", got[0].raw["type"])
	}
	var legacy any
	if err := json.Unmarshal([]byte(atLimit), &legacy); err != nil {
		t.Fatalf("encoding/json disagrees on the 10000 limit: %v", err)
	}
	overLimit := build(10000) // 10001 containers
	_, err = streamTestCollect(t, overLimit+"\n")
	if err == nil || !strings.Contains(err.Error(), reasonMaxDepth) {
		t.Fatalf("err = %v, want %q", err, reasonMaxDepth)
	}
	var legacyOver any
	if err := json.Unmarshal([]byte(overLimit), &legacyOver); err == nil {
		t.Fatal("encoding/json accepts 10001 containers")
	}
}

// streamCancelProbe counts Err calls and reports context.Canceled from
// the cancelAfter-th call onward, so a test can cancel at a chosen
// point of a walk (the walker checks once per line and once per 64 KiB
// refill).
type streamCancelProbe struct {
	context.Context
	cancelAfter int
	calls       int
}

func (c *streamCancelProbe) Err() error {
	c.calls++
	if c.cancelAfter > 0 && c.calls >= c.cancelAfter {
		return context.Canceled
	}
	return nil
}

// TestWalkProjectedLinesCancellation checks that an already-cancelled
// context fails fast, that a giant line can be cancelled between
// buffer refills, and that the returned error keeps errors.Is matching
// context.Canceled.
func TestWalkProjectedLinesCancellation(t *testing.T) {
	// One small line, one giant line (>1 MiB, many refills), one small
	// line.
	small := `{"type":"turn_context","timestamp":"` + streamTestTS + `","payload":{"model":"gpt-5"}}`
	giant := `{"unrelated":"` + strings.Repeat("x", 1<<20) + `","type":"event_msg","timestamp":"` + streamTestTS + `"}`
	content := small + "\n" + giant + "\n" + small + "\n"
	path := streamTestWrite(t, content)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err := walkProjectedCodexLines(canceled, path, func(map[string]any, int) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled err = %v", err)
	}

	probe := &streamCancelProbe{Context: context.Background()}
	if _, err := streamTestWalkProbe(path, probe); err != nil {
		t.Fatal(err)
	}
	if probe.calls < 16 { // 1 MiB line: ~16 refills plus per-line checks
		t.Fatalf("giant line lacks refill cancellation checks: %d", probe.calls)
	}
	mid := &streamCancelProbe{Context: context.Background(), cancelAfter: probe.calls / 2}
	if _, err := streamTestWalkProbe(path, mid); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-walk err = %v, want context.Canceled", err)
	}
}

func streamTestWalkProbe(path string, ctx context.Context) ([]int, error) {
	var lines []int
	err := walkProjectedCodexLines(ctx, path, func(raw map[string]any, line int) error {
		lines = append(lines, line)
		return nil
	})
	return lines, err
}

// TestWalkProjectedLinesFnErrorStopsWalk checks that a callback error
// is returned verbatim and stops the walk.
func TestWalkProjectedLinesFnErrorStopsWalk(t *testing.T) {
	sentinel := errors.New("stream-test-sentinel")
	path := streamTestWrite(t, `{"type":"x"}`+"\n"+`{"type":"y"}`+"\n")
	var visited int
	err := walkProjectedCodexLines(context.Background(), path, func(raw map[string]any, line int) error {
		visited++
		if line == 1 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) || visited != 1 {
		t.Fatalf("err = %v visited = %d, want sentinel after line 1", err, visited)
	}
}

// TestWalkProjectedLinesFraming pins physical line numbering: blank
// lines (including CRLF and whitespace-only lines) are skipped but
// counted, and a final line without a newline still surfaces.
func TestWalkProjectedLinesFraming(t *testing.T) {
	count := `{"type":"event_msg","timestamp":"` + streamTestTS + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1,"output_tokens":1}}}}`
	content := "\n\r\n\u00a0\n" + count + "\r\n\n" + count // no final newline
	got, err := streamTestCollect(t, content)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].line != 4 || got[1].line != 6 {
		t.Fatalf("visited %+v, want lines 4 and 6", got)
	}
	for idx, g := range got {
		if _, ok, perr := parseCodexObservation(g.raw, g.line); perr != nil || !ok {
			t.Fatalf("line %d: ok=%v err=%v", idx, ok, perr)
		}
	}
}

// TestWalkProjectedLinesMissingFile surfaces os.Open errors unchanged.
func TestWalkProjectedLinesMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	err := walkProjectedCodexLines(context.Background(), missing, func(map[string]any, int) error { return nil })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want not-exist", err)
	}
}

// BenchmarkWalkProjectedCodexLines measures the pure walker over a
// mixed corpus (ordinary session lines plus one giant discarded body)
// so the streaming scan cost is visible without pipeline overhead.
func BenchmarkWalkProjectedCodexLines(b *testing.B) {
	turn := `{"type":"turn_context","timestamp":"` + streamTestTS + `","payload":{"model":"gpt-5-codex"}}`
	count := `{"type":"event_msg","timestamp":"` + streamTestTS + `","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":10}}}}`
	var body strings.Builder
	body.WriteString(turn + "\n")
	for i := 0; i < 500; i++ {
		body.WriteString(count + "\n")
	}
	body.WriteString(`{"type":"response_item","payload":{"content":"` + strings.Repeat("x", 512<<10) + `","type":"message"}}` + "\n")
	for i := 0; i < 500; i++ {
		body.WriteString(count + "\n")
	}
	content := body.String()
	path := streamTestWrite(b, content)
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		visited := 0
		if err := walkProjectedCodexLines(context.Background(), path, func(raw map[string]any, line int) error {
			visited++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		if visited != 1002 {
			b.Fatalf("visited %d lines", visited)
		}
	}
}
