package adapter

import (
	"context"
	"time"

	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/scanledger"
)

const (
	UsageJSONSource        = "usage-json"
	CodexJSONLSource       = "codex-jsonl"
	ClaudeCodeJSONLSource  = "claude-code-jsonl"
	DeepSeekHarnessSource  = "deepseek-harness"
	WorkBuddyJSONLSource   = "workbuddy-jsonl"
	QwenJSONLSource        = "qwen-jsonl"
	KimiCLIJSONLSource     = "kimi-cli-jsonl"
	KimiCodeJSONLSource    = "kimi-code-jsonl"
	ZCodeSQLiteSource      = "zcode-sqlite"
	HermesSQLiteSource     = "hermes-sqlite"
	OpenClawSQLiteSource   = "openclaw-sqlite"
	PiJSONLSource          = "pi-jsonl"
	OMPJSONLSource         = "omp-jsonl"
	CodeBuddyHistorySource = "codebuddy-history"
	OpenCodeSQLiteSource   = "opencode-sqlite"
	// CursorDashboardAPISource identifies the account-level Cursor network
	// source. It is deliberately NOT a compiled-in local file adapter: it
	// never appears in the local grants store (whose validation requires
	// an absolute input path) and is collected only through the dedicated
	// cursor sync orchestration.
	CursorDashboardAPISource = "cursor-dashboard-api"
)

type Options struct {
	Source  string
	Input   string
	Output  string
	BatchID string
	Limit   int
	// StateDir points at the collector state directory. Interval sources
	// (claude-code-jsonl) use it to load confirmed per-message baselines and
	// to enforce the progress-integrity rule. Empty means stateless: the
	// claude-code-jsonl adapter then reports the full current usage per
	// message without interval state (updates are discarded).
	StateDir string
	// HistoryFrom is the optional cutoff timestamp. Records with occurredAt
	// strictly before this timestamp are filtered out of exports.
	HistoryFrom *time.Time
	// Context carries an optional cancellation scope into source loaders.
	// Nil keeps the legacy semantics: loaders that consult it through
	// ContextOrBackground see context.Background(), so a scan behaves
	// exactly as it did before cancellation support existed. Loaders check
	// the context only at coarse boundaries (file discovery, per file,
	// per line) and return the context error without partial results.
	Context context.Context
}

// LoadResult is the raw output of one source loader.
type LoadResult struct {
	Records        []Record
	Issues         []LineIssue
	Quarantined    int
	MessageUpdates []progress.MessagePendingUpdate
	// ScanStates carries the per-file content states a resumed scan
	// observed (see internal/local/scanledger). A loader that can skip
	// unchanged files returns the states of EVERY file it considered, and
	// the caller may persist them only after this batch's records have
	// been safely committed: persisting at parse time would drop records
	// whenever the export failed.
	ScanStates map[string]scanledger.FileState
}

// SourceLoader dispatches Options to one compiled-in source adapter.
type SourceLoader func(Options) (LoadResult, error)
type Record map[string]any

type Batch struct {
	BatchID string   `json:"batchId"`
	Records []Record `json:"records"`
}

type LineIssue struct {
	File   string
	Line   int
	Reason string
}
type Adapter struct {
	Source          string
	Description     string
	Load            SourceLoader
	FilterForExport func(Options, []Record) ([]Record, error)
	ValidateCommit  func(string) error
}
