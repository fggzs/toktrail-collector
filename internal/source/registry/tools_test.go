package registry

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestLookupTool(t *testing.T) {
	tests := []struct {
		input     string
		wantTool  string
		wantSrc   string
		wantFound bool
	}{
		{"Codex", "Codex", "codex-jsonl", true},
		{"codex", "Codex", "codex-jsonl", true},
		{"  CODEX  ", "Codex", "codex-jsonl", true},
		{"Claude Code", "Claude Code", "claude-code-jsonl", true},
		{"claude code", "Claude Code", "claude-code-jsonl", true},
		{"claude-code", "Claude Code", "claude-code-jsonl", true},
		{"claudecode", "Claude Code", "claude-code-jsonl", true},
		{"DeepSeek Harness", "DeepSeek Harness", "deepseek-harness", true},
		{"deepseek harness", "DeepSeek Harness", "deepseek-harness", true},
		{"deepseek-harness", "DeepSeek Harness", "deepseek-harness", true},
		{"deepseekharness", "DeepSeek Harness", "deepseek-harness", true},
		{"dsh", "DeepSeek Harness", "deepseek-harness", true},
		{"  DeepSeek Harness  ", "DeepSeek Harness", "deepseek-harness", true},
		{"WorkBuddy", "WorkBuddy", "workbuddy-jsonl", true},
		{"workbuddy", "WorkBuddy", "workbuddy-jsonl", true},
		{"Work Buddy", "WorkBuddy", "workbuddy-jsonl", true},
		{"work-buddy", "WorkBuddy", "workbuddy-jsonl", true},
		{"workbuddy-ai", "WorkBuddy", "workbuddy-jsonl", true},
		{"  WorkBuddy  ", "WorkBuddy", "workbuddy-jsonl", true},
		{"Qwen Code", "Qwen Code", "qwen-jsonl", true},
		{"qwen", "Qwen Code", "qwen-jsonl", true},
		{"qwen-code", "Qwen Code", "qwen-jsonl", true},
		{"qwen cli", "Qwen Code", "qwen-jsonl", true},
		{"qwencli", "Qwen Code", "qwen-jsonl", true},
		{"  Qwen Code  ", "Qwen Code", "qwen-jsonl", true},
		{"Kimi CLI", "Kimi CLI", "kimi-cli-jsonl", true},
		{"kimi", "Kimi CLI", "kimi-cli-jsonl", true},
		{"kimi-cli", "Kimi CLI", "kimi-cli-jsonl", true},
		{"kimicli", "Kimi CLI", "kimi-cli-jsonl", true},
		{"Kimi Code", "Kimi Code", "kimi-code-jsonl", true},
		{"kimi-code", "Kimi Code", "kimi-code-jsonl", true},
		{"kimicode", "Kimi Code", "kimi-code-jsonl", true},
		{"ZCode", "ZCode", "zcode-sqlite", true},
		{"zcode", "ZCode", "zcode-sqlite", true},
		{"z-code", "ZCode", "zcode-sqlite", true},
		{"智谱 zcode", "ZCode", "zcode-sqlite", true},
		{"Hermes Agent", "Hermes Agent", "hermes-sqlite", true},
		{"hermes", "Hermes Agent", "hermes-sqlite", true},
		{"hermes-agent", "Hermes Agent", "hermes-sqlite", true},
		{"hermesagent", "Hermes Agent", "hermes-sqlite", true},
		{"OpenClaw", "OpenClaw", "openclaw-sqlite", true},
		{"openclaw", "OpenClaw", "openclaw-sqlite", true},
		{"open-claw", "OpenClaw", "openclaw-sqlite", true},
		{"Pi", "Pi", "pi-jsonl", true},
		{"pi", "Pi", "pi-jsonl", true},
		{"pi-mono", "Pi", "pi-jsonl", true},
		{"pi coding agent", "Pi", "pi-jsonl", true},
		{"Oh My Pi", "Oh My Pi", "omp-jsonl", true},
		{"omp", "Oh My Pi", "omp-jsonl", true},
		{"oh-my-pi", "Oh My Pi", "omp-jsonl", true},
		{"ohmypi", "Oh My Pi", "omp-jsonl", true},
		{"  Oh My Pi  ", "Oh My Pi", "omp-jsonl", true},
		{"CodeBuddy", "CodeBuddy", "codebuddy-history", true},
		{"codebuddy", "CodeBuddy", "codebuddy-history", true},
		{"code buddy", "CodeBuddy", "codebuddy-history", true},
		{"codebuddy cn", "CodeBuddy", "codebuddy-history", true},
		{"  CodeBuddy  ", "CodeBuddy", "codebuddy-history", true},
		{"codebuddy-ide", "CodeBuddy", "codebuddy-history", true},
		{"腾讯云代码助手", "CodeBuddy", "codebuddy-history", true},
		{"Cursor", "Cursor", "cursor-dashboard-api", true},
		{"cursor", "Cursor", "cursor-dashboard-api", true},
		{"  cursor  ", "Cursor", "cursor-dashboard-api", true},
		{"Unknown", "", "", false},
		{"", "", "", false},
		{"../../etc", "", "", false},
	}

	for _, tc := range tests {
		spec, found := LookupTool(tc.input)
		if found != tc.wantFound {
			t.Errorf("LookupTool(%q) found=%v, want=%v", tc.input, found, tc.wantFound)
		}
		if found && spec.Tool != tc.wantTool {
			t.Errorf("LookupTool(%q) tool=%q, want=%q", tc.input, spec.Tool, tc.wantTool)
		}
		if found && spec.Source != tc.wantSrc {
			t.Errorf("LookupTool(%q) source=%q, want=%q", tc.input, spec.Source, tc.wantSrc)
		}
	}
}

func TestResolveDefaultInput(t *testing.T) {
	spec, found := LookupTool("Codex")
	if !found {
		t.Fatal("Codex not found")
	}
	home := filepath.Join("test", "home")
	resolved := spec.ResolveDefaultInput(home)
	expected := filepath.Join("test", "home", ".codex", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Claude Code")
	if !found {
		t.Fatal("Claude Code not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".claude", "projects")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("DeepSeek Harness")
	if !found {
		t.Fatal("DeepSeek Harness not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".dsh", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("WorkBuddy")
	if !found {
		t.Fatal("WorkBuddy not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".workbuddy-ai", "projects")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Qwen CLI")
	if !found {
		t.Fatal("Qwen Code not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".qwen", "projects")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Kimi CLI")
	if !found {
		t.Fatal("Kimi CLI not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".kimi", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Kimi Code")
	if !found {
		t.Fatal("Kimi Code not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".kimi-code", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("ZCode")
	if !found {
		t.Fatal("ZCode not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".zcode", "cli", "db")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Hermes")
	if !found {
		t.Fatal("Hermes Agent not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".hermes")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("OpenClaw")
	if !found {
		t.Fatal("OpenClaw not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".openclaw", "agents")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Pi")
	if !found {
		t.Fatal("Pi not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".pi", "agent", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("Oh My Pi")
	if !found {
		t.Fatal("Oh My Pi not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", ".omp", "agent", "sessions")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	spec, found = LookupTool("CodeBuddy")
	if !found {
		t.Fatal("CodeBuddy not found")
	}
	resolved = spec.ResolveDefaultInput(home)
	expected = filepath.Join("test", "home", "AppData", "Local", "CodeBuddyExtension", "Data")
	if resolved != expected {
		t.Errorf("expected %q, got %q", expected, resolved)
	}

	// Account-network tools have no local default input: the empty string
	// tells callers to branch to the account-source flow instead of
	// touching the filesystem.
	spec, found = LookupTool("Cursor")
	if !found {
		t.Fatal("Cursor not found")
	}
	if !spec.IsAccountNetwork() {
		t.Errorf("Cursor must be classified as an account-network tool, got mode %q", spec.Mode)
	}
	if resolved := spec.ResolveDefaultInput(home); resolved != "" {
		t.Errorf("account-network tool must have no default input, got %q", resolved)
	}
}

// CodeBuddy keeps the same data tree in two layouts: the XDG data directory
// POSIX hosts actually use, and the Windows AppData directory. Both must be
// probed, XDG first, otherwise a Linux install is reported as "not detected"
// while the usage is plainly there — the reported bug.
func TestCodeBuddyDefaultCandidatesCoverXDGAndAppData(t *testing.T) {
	home := filepath.Join("test", "home")
	spec, found := LookupTool("CodeBuddy")
	if !found {
		t.Fatal("CodeBuddy not found")
	}

	xdgRelative := []string{"CodeBuddyExtension", "Data"}
	homeXDG := filepath.Join(home, ".local", "share", "CodeBuddyExtension", "Data")
	appData := filepath.Join(home, "AppData", "Local", "CodeBuddyExtension", "Data")

	// An absolute base is platform-specific: filepath.IsAbs rejects the
	// POSIX form on Windows, which is exactly why the environment value is
	// validated instead of trusted.
	absoluteBase := "/synthetic-xdg"
	if runtime.GOOS == "windows" {
		absoluteBase = `C:\synthetic-xdg`
	}

	cases := []struct {
		name  string
		env   string
		first string
	}{
		{"unset uses the XDG home default", "", homeXDG},
		{"absolute XDG_DATA_HOME wins", absoluteBase, filepath.Join(absoluteBase, filepath.Join(xdgRelative...))},
		// The XDG spec makes a relative value invalid: it must be ignored
		// instead of probing a relative path against the process cwd.
		{"relative XDG_DATA_HOME is ignored", "relative-xdg", homeXDG},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tc.env)
			got := spec.DefaultInputCandidates(home)
			want := []string{tc.first, appData}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("candidates = %#v, want %#v", got, want)
			}
			// ResolveDefaultInput keeps naming the Windows default; the
			// XDG layout is a candidate, not the reported default, which is
			// why probe order (not this value) decides detection.
			if resolved := spec.ResolveDefaultInput(home); resolved != appData {
				t.Fatalf("ResolveDefaultInput = %q, want %q", resolved, appData)
			}
		})
	}
}

// Only a spec that declares an XDG layout may gain an environment-dependent
// candidate: every other tool keeps exactly the home-relative paths it had.
func TestHomeRelativeToolsHaveNoXDGCandidate(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/synthetic-xdg")
	home := filepath.Join("test", "home")
	for _, name := range []string{"Codex", "Claude Code", "WorkBuddy", "Qwen Code", "OpenCode"} {
		spec, found := LookupTool(name)
		if !found {
			t.Fatalf("%s not found", name)
		}
		candidates := spec.DefaultInputCandidates(home)
		if candidates[0] != spec.ResolveDefaultInput(home) {
			t.Fatalf("%s: candidates[0] = %q, want the home-relative default %q", name, candidates[0], spec.ResolveDefaultInput(home))
		}
		seen := map[string]bool{}
		for _, candidate := range candidates {
			if filepath.IsAbs(candidate) && candidate != spec.ResolveDefaultInput(home) {
				t.Fatalf("%s: unexpected absolute candidate %q", name, candidate)
			}
			if seen[candidate] {
				t.Fatalf("%s: duplicate candidate %q", name, candidate)
			}
			seen[candidate] = true
		}
	}
}
