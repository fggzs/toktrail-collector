package registry

import (
	"path/filepath"
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
		{"CodeBuddy", "CodeBuddy", "codebuddy-json", true},
		{"codebuddy", "CodeBuddy", "codebuddy-json", true},
		{"code buddy", "CodeBuddy", "codebuddy-json", true},
		{"codebuddy cn", "CodeBuddy", "codebuddy-json", true},
		{"  CodeBuddy  ", "CodeBuddy", "codebuddy-json", true},
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
