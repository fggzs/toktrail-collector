package connect

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/app/collection"
	"toktrail-collector/internal/local/grants"
)

// codeBuddyXDGLayout and codeBuddyAppDataLayout are the two registered
// CodeBuddy extension data layouts, relative to the user home. The same data
// tree exists in both; only the platform decides which one is present.
var (
	codeBuddyXDGLayout     = []string{".local", "share", "CodeBuddyExtension", "Data"}
	codeBuddyAppDataLayout = []string{"AppData", "Local", "CodeBuddyExtension", "Data"}
)

// writeCodeBuddyConversation lays one completed request with one attributable
// assistant message under dataDir, so the adapter has exactly one record.
func writeCodeBuddyConversation(t *testing.T, dataDir string) {
	t.Helper()
	conversation := filepath.Join(dataDir, "user", "CodeBuddyIDE", "user", "history", "workspace-1", "conversation-1")
	messages := filepath.Join(conversation, "messages")
	if err := os.MkdirAll(messages, 0o700); err != nil {
		t.Fatal(err)
	}
	index := `{"requests":[{"id":"req-1","type":"craft","messages":["msg-1"],"state":"complete","startedAt":1780000000000,"usage":{"inputTokens":100,"outputTokens":20,"totalTokens":120,"cacheTokens":40,"cachedWriteTokens":0,"cachedMissTokens":60}}]}`
	if err := os.WriteFile(filepath.Join(conversation, "index.json"), []byte(index), 0o600); err != nil {
		t.Fatal(err)
	}
	message := `{"role":"assistant","extra":"{\"requestId\":\"req-1\",\"modelId\":\"synthetic-model\"}"}`
	if err := os.WriteFile(filepath.Join(messages, "msg-1.json"), []byte(message), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConnectCodeBuddyDirectoryLayouts pins the reported Linux regression: the
// managed grant must land on the layout that actually exists on the host. With
// only the XDG directory present, a probe that looked at the Windows default
// alone reported "not detected", wrote no grant, and silently collected nothing
// while the connect result still said completed.
func TestConnectCodeBuddyDirectoryLayouts(t *testing.T) {
	// Keep the XDG base deterministic: the home-derived default is the
	// layout under test, not whatever this developer's environment says.
	t.Setenv("XDG_DATA_HOME", "")

	for _, tc := range []struct {
		name    string
		layouts [][]string
		want    []string
	}{
		{"xdg only", [][]string{codeBuddyXDGLayout}, codeBuddyXDGLayout},
		{"appdata only", [][]string{codeBuddyAppDataLayout}, codeBuddyAppDataLayout},
		{"both prefer xdg", [][]string{codeBuddyXDGLayout, codeBuddyAppDataLayout}, codeBuddyXDGLayout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir, home := t.TempDir(), t.TempDir()
			mock := startCursorBacklogMock(t)
			cfg := startSyncConfigMock(t, mock.URL, []string{"CodeBuddy"}, nil)
			ticket := strings.Repeat("7", 64)
			seedFirstEnableConnect(t, stateDir, mock, cfg, ticket)
			for _, layout := range tc.layouts {
				writeCodeBuddyConversation(t, filepath.Join(append([]string{home}, layout...)...))
			}
			want := filepath.Join(append([]string{home}, tc.want...)...)

			for attempt := 0; attempt < 2; attempt++ {
				out := &bytes.Buffer{}
				res, err := runCursorConnectWithOptionsOut(t, cfg, stateDir, home, ticket, Options{}, out)
				if err != nil {
					t.Fatalf("connect attempt %d: %v\n%s", attempt, err, out.String())
				}
				if got := SummarizeRun(res, err, nil, 1).StopReason; got != collection.StopComplete {
					t.Fatalf("stop reason = %s", got)
				}
				enabled, err := grants.New(stateDir).Enabled()
				if err != nil {
					t.Fatal(err)
				}
				if len(enabled) != 1 || enabled[0].Source != "codebuddy-history" || enabled[0].Input != want {
					t.Fatalf("grants = %+v, want only %s", enabled, want)
				}
				if !strings.Contains(out.String(), "1 detected") {
					t.Fatalf("CodeBuddy must be detected:\n%s", out.String())
				}
				if attempt == 0 && res.PeriodicResult.SyncedRecords != 1 {
					t.Fatalf("expected the layout under test to supply one record: %+v", res.PeriodicResult)
				}
			}
		})
	}
}
