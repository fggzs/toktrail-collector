package codexjsonl_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codexjsonl"
	"toktrail-collector/internal/source/pipeline"
)

// Write large synthetic bodies incrementally: tests must not mask parser
// allocations by building an entire giant JSON line in the test process.
func writeStreamingFixture(t testing.TB, path string, bodyBytes int, brokenTail bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	write := func(s string) {
		if _, err := io.WriteString(f, s); err != nil {
			t.Fatal(err)
		}
	}
	body := func() {
		chunk := strings.Repeat("x", 64*1024)
		remaining := bodyBytes
		for remaining > 0 {
			n := min(len(chunk), remaining)
			write(chunk[:n])
			remaining -= n
		}
	}
	write("\n") // Physical blank lines remain part of record identity.
	write(`{"type":"turn_context","timestamp":"2026-11-10T00:00:00Z","payload":{"content":"`)
	body()
	write(`","model":"synthetic-model"}}` + "\r\n")
	write(`{"timestamp":"2026-11-10T00:00:01Z","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":10}}}}` + "\n")
	write(`{"payload":{"content":"`)
	body()
	write(`","type":"message"},"type":"response_item"}` + "\n")
	// Counters occur after the giant body, and duplicate payload/type keys
	// deliberately replace the harmless values at the beginning of the line.
	write(`{"payload":{"type":"message"},"type":"response_item","body":"`)
	body()
	write(`","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":200,"cached_input_tokens":30,"output_tokens":50}}},"timestamp":"2026-11-10T00:00:02Z","type":"event_msg"}`)
	if brokenTail {
		write(" PRIVATE_SYNTHETIC_TRAILING_GARBAGE")
	}
	// Valid EOF without a final newline must keep the historical behavior.
}

func loadStreamingFixture(t testing.TB, path, state string, ctx context.Context) (adapter.LoadResult, error) {
	t.Helper()
	return codexjsonl.Adapter().Load(adapter.Options{Source: adapter.CodexJSONLSource, Input: path, StateDir: state, Context: ctx})
}

func TestCodexStreamingGiantBodiesKeepRecordIdentityAndUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	writeStreamingFixture(t, path, 32, false)
	baseline, err := loadStreamingFixture(t, path, "", nil)
	if err != nil || len(baseline.Records) != 1 {
		t.Fatalf("baseline: records=%d err=%v", len(baseline.Records), err)
	}
	record := baseline.Records[0]
	if record["recordKey"] != "codex-jsonl:"+adapter.ShortHash(path)+":5" || record["model"] != "synthetic-model" || record["input"] != "90" || record["cacheRead"] != "10" || record["output"] != "40" {
		t.Fatalf("unexpected baseline: %#v", record)
	}
	for _, size := range []int{17 << 20, 64 << 20} {
		t.Run(fmt.Sprintf("body-%d-MiB", size>>20), func(t *testing.T) {
			writeStreamingFixture(t, path, size, false)
			got, err := loadStreamingFixture(t, path, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Records, baseline.Records) || !reflect.DeepEqual(got.Issues, baseline.Issues) {
				t.Fatalf("body size changed output: %#v vs %#v", got, baseline)
			}
		})
	}
}

func TestCodexStreamingFailureReturnsNoPartialResultOrScanState(t *testing.T) {
	input := t.TempDir()
	state := t.TempDir()
	writeStreamingFixture(t, filepath.Join(input, "a-valid.jsonl"), 32, false)
	bad := filepath.Join(input, "b-broken.jsonl")
	writeStreamingFixture(t, bad, 17<<20, true)
	got, err := loadStreamingFixture(t, input, state, nil)
	if err == nil || !strings.Contains(err.Error(), bad+":5") || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("missing safe source location: %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE_SYNTHETIC") {
		t.Fatalf("error leaked transcript text: %v", err)
	}
	if len(got.Records) != 0 || len(got.ScanStates) != 0 || len(got.Issues) != 0 {
		t.Fatalf("failed read returned partial state: %#v", got)
	}
	if _, err := os.Stat(scanledger.New(state).Path(adapter.CodexJSONLSource)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed scan persisted ledger: %v", err)
	}
	writeStreamingFixture(t, bad, 17<<20, false)
	repaired, err := loadStreamingFixture(t, input, state, nil)
	if err != nil || len(repaired.Records) != 2 {
		t.Fatalf("retry after repair: records=%d err=%v", len(repaired.Records), err)
	}
}

func TestCodexStreamingCancellationInsideGiantBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	writeStreamingFixture(t, path, 17<<20, false)
	probe := &cancelAfterContext{Context: context.Background(), cancelAfter: math.MaxInt}
	if _, err := loadStreamingFixture(t, path, "", probe); err != nil {
		t.Fatal(err)
	}
	if probe.calls < 100 {
		t.Fatalf("giant body lacks chunk cancellation checks: %d", probe.calls)
	}
	ctx := &cancelAfterContext{Context: context.Background(), cancelAfter: probe.calls / 2}
	got, err := loadStreamingFixture(t, path, "", ctx)
	if !errors.Is(err, context.Canceled) || len(got.Records) != 0 || len(got.ScanStates) != 0 {
		t.Fatalf("cancelled giant body returned partial state: %#v err=%v", got, err)
	}
}

func TestCodexStreamingGiantFileExportDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	state := t.TempDir()
	writeStreamingFixture(t, path, 17<<20, false)
	opt := adapter.Options{Source: adapter.CodexJSONLSource, Input: path, StateDir: state, Output: filepath.Join(state, "first.json"), BatchID: "stream-first"}
	first, err := pipeline.PrepareExport(opt)
	if err != nil || first.Records != 1 {
		t.Fatalf("first export: %#v err=%v", first, err)
	}
	if _, err := exportcommit.CommitExport(exportcommit.ExportOptions{StateDir: state, Prepared: first, Source: opt.Source, Input: path}); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not save ScanStates yet: the immutable outbox baseline
	// alone must exclude the re-parsed record, even after a body-only rewrite.
	writeStreamingFixture(t, path, (17<<20)+1, false)
	opt.Output = filepath.Join(state, "second.json")
	opt.BatchID = "stream-second"
	second, err := pipeline.PrepareExport(opt)
	if err != nil || second.Records != 0 {
		t.Fatalf("second export duplicated records: %#v err=%v", second, err)
	}
	if err := scanledger.New(state).Save(opt.Source, second.ScanStates); err != nil {
		t.Fatal(err)
	}
	unchanged, err := loadStreamingFixture(t, path, state, nil)
	if err != nil || len(unchanged.Records) != 0 || len(unchanged.ScanStates) != 1 {
		t.Fatalf("unchanged file was not resumed: %#v err=%v", unchanged, err)
	}
}

func BenchmarkCodexStreamingBody(b *testing.B) {
	for _, size := range []int{1 << 10, 17 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%d-KiB", size>>10), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "rollout.jsonl")
			writeStreamingFixture(b, path, size, false)
			b.SetBytes(int64(3 * size))
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				got, err := loadStreamingFixture(b, path, "", nil)
				if err != nil || len(got.Records) != 1 {
					b.Fatalf("records=%d err=%v", len(got.Records), err)
				}
			}
		})
	}
}
