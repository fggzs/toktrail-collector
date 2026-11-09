package registry

import (
	"os"
	"path/filepath"
	"strings"

	"toktrail-collector/internal/source/adapter"
)

// SourceMode classifies how a tool's usage is collected.
type SourceMode string

const (
	// ModeLocal marks tools collected by reading explicitly granted local
	// files (the only mode before account sources existed).
	ModeLocal SourceMode = "local"
	// ModeAccountNetwork marks tools collected by direct authenticated
	// requests to the vendor's account-level API, driven by a local
	// permit that requires explicit first-time user confirmation.
	ModeAccountNetwork SourceMode = "account-network"
)

// ToolSpec defines a supported developer tool and its default local source configuration.
type ToolSpec struct {
	Tool           string   // Canonical tool name, e.g. "Codex", "Claude Code"
	Aliases        []string // Case-insensitive matching aliases
	Source         string   // Collector adapter source identifier
	DefaultSubpath []string // Path segments relative to user home directory
	// FallbackSubpaths are probed in order only when the preferred path is absent.
	FallbackSubpaths [][]string
	// XDGDataSubpath, when non-empty, is an additional preferred layout
	// anchored at the XDG data directory instead of the user home:
	// $XDG_DATA_HOME/<segments> when that variable holds an absolute path
	// (a relative value is invalid per the XDG spec and is ignored),
	// otherwise <home>/.local/share/<segments>. Its candidate is probed
	// before DefaultSubpath, so a POSIX install is detected ahead of the
	// Windows-compatible AppData layout carried by the same spec. Empty for
	// every home-relative tool.
	XDGDataSubpath []string
	// Mode classifies the collection path. The zero value behaves as
	// ModeLocal so every pre-existing local tool spec is unchanged.
	Mode SourceMode
}

var supportedTools = []ToolSpec{
	{
		Tool:           "Codex",
		Aliases:        []string{"codex"},
		Source:         adapter.CodexJSONLSource,
		DefaultSubpath: []string{".codex", "sessions"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Claude Code",
		Aliases:        []string{"claude code", "claude-code", "claudecode"},
		Source:         adapter.ClaudeCodeJSONLSource,
		DefaultSubpath: []string{".claude", "projects"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "DeepSeek Harness",
		Aliases:        []string{"deepseek harness", "deepseek-harness", "deepseekharness", "dsh"},
		Source:         adapter.DeepSeekHarnessSource,
		DefaultSubpath: []string{".dsh", "sessions"},
		Mode:           ModeLocal,
	},
	{
		Tool:             "WorkBuddy",
		Aliases:          []string{"workbuddy", "workbuddy-ai"},
		Source:           adapter.WorkBuddyJSONLSource,
		DefaultSubpath:   []string{".workbuddy-ai", "projects"},
		FallbackSubpaths: [][]string{{".workbuddy", "projects"}},
		Mode:             ModeLocal,
	},
	{
		Tool:           "Qwen Code",
		Aliases:        []string{"qwen", "qwen code", "qwen-code", "qwencode", "qwen cli", "qwen-cli", "qwencli"},
		Source:         adapter.QwenJSONLSource,
		DefaultSubpath: []string{".qwen", "projects"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Kimi CLI",
		Aliases:        []string{"kimi", "kimi cli", "kimi-cli", "kimicli"},
		Source:         adapter.KimiCLIJSONLSource,
		DefaultSubpath: []string{".kimi", "sessions"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Kimi Code",
		Aliases:        []string{"kimi code", "kimi-code", "kimicode"},
		Source:         adapter.KimiCodeJSONLSource,
		DefaultSubpath: []string{".kimi-code", "sessions"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "ZCode",
		Aliases:        []string{"zcode", "z code", "z-code", "zai zcode", "z.ai zcode", "智谱 zcode"},
		Source:         adapter.ZCodeSQLiteSource,
		DefaultSubpath: []string{".zcode", "cli", "db"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Hermes Agent",
		Aliases:        []string{"hermes", "hermes agent", "hermes-agent", "hermesagent"},
		Source:         adapter.HermesSQLiteSource,
		DefaultSubpath: []string{".hermes"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "OpenClaw",
		Aliases:        []string{"openclaw", "open claw", "open-claw"},
		Source:         adapter.OpenClawSQLiteSource,
		DefaultSubpath: []string{".openclaw", "agents"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Pi",
		Aliases:        []string{"pi", "pi-mono", "pi mono", "pi coding agent", "pi-agent", "badlogic pi", "earendil pi"},
		Source:         adapter.PiJSONLSource,
		DefaultSubpath: []string{".pi", "agent", "sessions"},
		Mode:           ModeLocal,
	},
	{
		Tool:           "Oh My Pi",
		Aliases:        []string{"omp", "oh my pi", "oh-my-pi", "ohmypi"},
		Source:         adapter.OMPJSONLSource,
		DefaultSubpath: []string{".omp", "agent", "sessions"},
		Mode:           ModeLocal,
	},
	{
		// CodeBuddy IDE (CodeBuddy CN) stores per-request usage counters in
		// its local session history under an extension data directory; the
		// adapter discovers .../history/<workspace>/<conversation>/index.json
		// below whatever ancestor is granted, and also resolves the recorded
		// model identifier from messages/*.json. Conversation bodies are
		// never read, and only completed requests are collected.
		//
		// Two layouts exist for the same data, and neither is a fallback
		// decoration: POSIX hosts follow the XDG base spec
		// ($XDG_DATA_HOME/CodeBuddyExtension/Data, default
		// ~/.local/share/CodeBuddyExtension/Data) while Windows keeps
		// ~/AppData/Local/CodeBuddyExtension/Data. The XDG candidate is
		// probed first so a Linux install is never reported as "not
		// detected" just because the Windows path is absent; the AppData
		// candidate keeps Windows (and WSL) working.
		Tool:           "CodeBuddy",
		Aliases:        []string{"codebuddy", "code buddy", "codebuddy cn", "codebuddy-cn", "codebuddycn", "codebuddy ide", "codebuddy-ide", "codebuddyide", "腾讯云代码助手"},
		Source:         adapter.CodeBuddyHistorySource,
		DefaultSubpath: []string{"AppData", "Local", "CodeBuddyExtension", "Data"},
		XDGDataSubpath: []string{"CodeBuddyExtension", "Data"},
		Mode:           ModeLocal,
	},
	{
		// OpenCode CLI stores every conversation message in one SQLite
		// database at ~/.local/share/opencode/opencode.db; the adapter reads
		// per-request usage counters from assistant rows in session_message
		// through a read-only immutable DSN and never writes to the
		// directory.
		Tool:           "OpenCode",
		Aliases:        []string{"opencode", "open code", "open-code", "opencodecli", "opencode cli", "sst opencode"},
		Source:         adapter.OpenCodeSQLiteSource,
		DefaultSubpath: []string{".local", "share", "opencode"},
		Mode:           ModeLocal,
	},
	{
		// Cursor is the first account-level network source: usage is
		// collected by direct authenticated requests to the Cursor
		// dashboard API using the locally confirmed desktop login. It
		// has NO default local directory: connect probing and the grant
		// sync must branch on IsAccountNetwork instead of touching the
		// filesystem, and its local permit lives in the cursor sync
		// orchestration — never in grants.json.
		Tool:    "Cursor",
		Aliases: []string{"cursor"},
		Source:  adapter.CursorDashboardAPISource,
		Mode:    ModeAccountNetwork,
	},
}

// SupportedTools returns the registered tool specifications.
func SupportedTools() []ToolSpec {
	out := make([]ToolSpec, len(supportedTools))
	copy(out, supportedTools)
	return out
}

// LookupTool finds a registered tool definition by name.
// Matching is case-insensitive, trimmed, and normalizes hyphens/spaces.
func LookupTool(name string) (ToolSpec, bool) {
	clean := strings.ToLower(strings.TrimSpace(name))
	if clean == "" {
		return ToolSpec{}, false
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(clean, "-", ""), " ", "")

	for _, spec := range supportedTools {
		if strings.ToLower(spec.Tool) == clean {
			return spec, true
		}
		for _, alias := range spec.Aliases {
			if strings.ToLower(alias) == clean {
				return spec, true
			}
		}
		compactSpec := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(spec.Tool), "-", ""), " ", "")
		if compactSpec == compact {
			return spec, true
		}
	}
	return ToolSpec{}, false
}

// IsAccountNetwork reports whether this tool is collected through the
// account-level network path instead of granted local files.
func (t ToolSpec) IsAccountNetwork() bool { return t.Mode == ModeAccountNetwork }

// ResolveDefaultInput returns the absolute default input directory path
// for this tool, anchored at homeDir. Account-network tools have no local
// default input; the empty string tells callers to branch to their
// account-source flow instead of touching the filesystem.
func (t ToolSpec) ResolveDefaultInput(homeDir string) string {
	if t.IsAccountNetwork() || len(t.DefaultSubpath) == 0 {
		return ""
	}
	parts := append([]string{homeDir}, t.DefaultSubpath...)
	return filepath.Join(parts...)
}

// DefaultInputCandidates returns the layouts to probe, in order: the XDG data
// layout first when the spec carries one, then the preferred home-relative
// directory, then known alternate layouts. It does not read the filesystem or
// grant access itself. Callers must treat CANDIDATE ORDER as authoritative:
// candidates[0] is not always ResolveDefaultInput (CodeBuddy's POSIX layout is
// probed ahead of the Windows default that ResolveDefaultInput still reports),
// and a "not found" reason naming ResolveDefaultInput alone would point a Linux
// user at a path that never exists on their host.
func (t ToolSpec) DefaultInputCandidates(homeDir string) []string {
	primary := t.ResolveDefaultInput(homeDir)
	if primary == "" {
		return nil
	}
	var paths []string
	if xdg := t.xdgDataCandidate(homeDir); xdg != "" && xdg != primary {
		paths = append(paths, xdg)
	}
	paths = append(paths, primary)
	for _, subpath := range t.FallbackSubpaths {
		parts := append([]string{homeDir}, subpath...)
		paths = append(paths, filepath.Join(parts...))
	}
	return paths
}

// xdgDefaultDataSubpath is the XDG base-directory default relative to home,
// used when XDG_DATA_HOME is unset, empty, or relative (the spec requires an
// absolute value; anything else must be ignored rather than guessed at).
var xdgDefaultDataSubpath = []string{".local", "share"}

// xdgDataCandidate resolves the XDG data layout for a spec that declares one.
// An absolute XDG_DATA_HOME wins so a user with a relocated data directory is
// still detected from the managed grant path.
func (t ToolSpec) xdgDataCandidate(homeDir string) string {
	if len(t.XDGDataSubpath) == 0 {
		return ""
	}
	base := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if !filepath.IsAbs(base) {
		base = ""
	}
	if base == "" {
		if strings.TrimSpace(homeDir) == "" {
			return ""
		}
		parts := append([]string{homeDir}, xdgDefaultDataSubpath...)
		base = filepath.Join(parts...)
	}
	parts := append([]string{base}, t.XDGDataSubpath...)
	return filepath.Join(parts...)
}
