package codexjsonl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStreamingSurrogateLookaheadAndLongTimestampParity(t *testing.T) {
	for name, text := range map[string]string{
		"surrogate-before-ascii": `{"type":"turn_context","timestamp":"2026-11-10T00:00:00Z","payload":{"model":"\ud800\u0041"}}`,
		"surrogate-before-high":  `{"type":"turn_context","timestamp":"2026-11-10T00:00:00Z","payload":{"model":"\ud800\ud801"}}`,
		"surrogate-before-pair":  `{"type":"turn_context","timestamp":"2026-11-10T00:00:00Z","payload":{"model":"\ud800\ud801\udc00"}}`,
		"long-fraction":          `{"type":"turn_context","timestamp":"2026-11-10T00:00:00.` + strings.Repeat("1", 100000) + `Z","payload":{"model":"test"}}`,
		"long-fraction-offset":   `{"type":"turn_context","timestamp":" 2026-11-10T00:00:00,123456789` + strings.Repeat("0", 100000) + `+08:00 ","payload":{"model":"test"}}`,
		"long-invalid-time":      `{"type":"turn_context","timestamp":"2026-11-10T00:00:00.` + strings.Repeat("1", 100000) + `X","payload":{"model":"test"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			compareWalkCompat(t, writeCompatFile(t, text), compatOptions{})
		})
	}
}

func TestStreamingControlErrorAnchorsOriginalByte(t *testing.T) {
	prefix := `{"body":"abc`
	path := writeCompatFile(t, prefix+"\v \t"+`suffix"}`)
	err := walkProjectedCodexLines(context.Background(), path, func(map[string]any, int) error { return nil })
	var located *streamError
	if !errors.As(err, &located) || located.Byte != len(prefix)+1 || located.Reason != reasonInString {
		t.Fatalf("control error location: %v", err)
	}
}

func TestStreamingDepthLimitMatchesJSONDecoder(t *testing.T) {
	for _, depth := range []int{9999, 10000, 10001} {
		text := `{"ignored":` + strings.Repeat("[", depth-1) + `0` + strings.Repeat("]", depth-1) + `}`
		compareWalkCompat(t, writeCompatFile(t, text), compatOptions{})
	}
}

func TestStreamingUTF8AndEscapeAcrossBufferEdges(t *testing.T) {
	for _, payload := range []string{"中", "😀", `\ud83d\ude00`, `\ud800\u0041`, `\u0061`} {
		for offset := -8; offset <= 4; offset++ {
			text := `{"body":"` + strings.Repeat("x", streamBufferSize+offset) + payload + `","payload":{"model":"` + payload + `"},"type":"turn_context","timestamp":"2026-11-10T00:00:00Z"}`
			compareWalkCompat(t, writeCompatFile(t, text), compatOptions{})
		}
	}
}

// Differential fuzz coverage can also use encoding/json-generated arbitrary
// trees, without assuming a particular projected-key order or scalar shape.
func TestStreamingGeneratedTreeParity(t *testing.T) {
	values := []any{nil, true, false, "", "token_count", "turn_context", "2026-11-10T00:00:00Z", "gpt-test", json.Number("9007199254740993"), []any{1, "body"}, map[string]any{"type": "token_count"}}
	for _, key := range []string{"timestamp", "type", "payload"} {
		for _, value := range values {
			raw := map[string]any{key: value}
			encoded, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			compareWalkCompat(t, writeCompatFile(t, string(encoded)), compatOptions{})
		}
	}
}

func TestStreamingCallbackOnlyAfterWholeLineValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte("{}\n{\"type\":\"turn_context\"} trailing"), 0600); err != nil {
		t.Fatal(err)
	}
	var lines []int
	err := walkProjectedCodexLines(context.Background(), path, func(_ map[string]any, line int) error { lines = append(lines, line); return nil })
	if err == nil || !reflect.DeepEqual(lines, []int{1}) {
		t.Fatalf("callback before validation: lines=%v error=%v", lines, err)
	}
}
