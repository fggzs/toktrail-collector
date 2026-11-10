package codexjsonl_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexStreamingValidatesDiscardedGiantBodies(t *testing.T) {
	for _, tail := range []struct {
		name string
		text string
	}{
		{"invalid-utf8", string([]byte{0xff}) + `"}}`},
		{"invalid-escape", `\z"}}`},
		{"torn-string", ""},
		{"physical-newline-in-string", "\n" + `"}}`},
		{"trailing-json", `"}} {}`},
	} {
		t.Run(tail.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rollout.jsonl")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			write := func(s string) {
				if _, err := io.WriteString(f, s); err != nil {
					f.Close()
					t.Fatal(err)
				}
			}
			write("\n\n" + `{"type":"response_item","payload":{"content":"`)
			chunk := strings.Repeat("x", 64<<10)
			for i := 0; i < 272; i++ {
				write(chunk)
			}
			write(tail.text)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := loadStreamingFixture(t, path, "", nil)
			if err == nil || !strings.Contains(err.Error(), path+":3") {
				t.Fatalf("invalid discarded body was accepted or has no physical line: %v", err)
			}
			if len(got.Records) != 0 || len(got.ScanStates) != 0 {
				t.Fatalf("invalid discarded body produced records or states: %#v", got)
			}
		})
	}
}
