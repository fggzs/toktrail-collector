package recollect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/exportcommit"
	"toktrail-collector/internal/local/filtertxn"
	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/knowncache"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/scanledger"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// scanClass is the classification of one enabled local grant for the
// pre-scan: either it joins the scan (ok) or it is excluded for a closed
// reason. Everything that would make the rebuild's coverage smaller than
// the local truth in a way the user has not authorized (an unknown source
// id, a missing or unreadable input, a load failure) fails the WHOLE run
// closed instead of contributing zero records — the server's unique
// history is about to be cleared, so a silently partial rebuild would be
// unrecoverable data loss.
type scanClass struct {
	grant   grants.Grant
	ok      bool
	exclude string // exclusion code when !ok
	reason  string // human text when !ok
}

// Closed exclusion codes for grants the pre-scan deliberately skips. The
// plan reports each exclusion by code; the human reasons stay out of the
// plan and out of the journal's exclusion record.
const (
	GrantNotAllowed = "not_allowed" // tool outside the live server consent scope
	GrantDisabled   = "disabled"    // grant disabled locally before the job
	GrantCursor     = "cursor"      // account-level network source (never local)
	GrantDuplicate  = "duplicate"   // same (source, input) already scanned
)

// Scan outcome codes (the non-fatal end states of a scanned grant).
const (
	GrantExported  = "exported"   // committed at least one batch
	GrantNoRecords = "no_records" // source legitimately holds no records
)

// classifyGrants derives the scan set from the ORIGINAL state's grant
// store under the live consent scope. The dynamic registry drives source
// discovery — nothing is hardcoded to a fixed source list, and an unknown
// source id (an older collector binary reading a newer grant store) fails
// closed rather than being skipped as zero.
func classifyGrants(stateDir string, scope liveScope) ([]scanClass, jobExclusions, error) {
	enabled, err := grants.New(stateDir).Enabled()
	if err != nil {
		return nil, jobExclusions{}, fmt.Errorf("cannot read the local source grants; the force recollection refuses to rebuild without current local authorization: %w", err)
	}
	out := make([]scanClass, 0, len(enabled))
	ex := jobExclusions{}
	seen := make(map[string]bool, len(enabled))
	for _, grant := range enabled {
		label := grant.Source + " " + grant.Input
		switch {
		case !registry.IsKnownSource(grant.Source):
			return nil, ex, fmt.Errorf("the enabled grant for source %q is not compiled into this collector (registered sources: %s); refusing to treat it as zero — upgrade the collector or disable the grant before rebuilding, or its history would be silently lost", grant.Source, strings.Join(registry.KnownSources(), ", "))
		case grant.Source == adapter.CursorDashboardAPISource || accountNetworkSource(grant.Source):
			ex.Cursor = append(ex.Cursor, label)
			out = append(out, scanClass{grant: grant, exclude: GrantCursor, reason: "account-level network source; force recollection rebuilds local sources only and never orchestrates the Cursor account sync"})
		case seen[grant.Source+"\x00"+grant.Input]:
			ex.Duplicate = append(ex.Duplicate, label)
			out = append(out, scanClass{grant: grant, exclude: GrantDuplicate, reason: "duplicate (source, input) grant; the first occurrence was scanned"})
		case !scope.sourceAllowed(grant.Source):
			ex.NotAllowed = append(ex.NotAllowed, label)
			out = append(out, scanClass{grant: grant, exclude: GrantNotAllowed, reason: "tool not allowed by the live server consent scope for this device"})
		default:
			seen[grant.Source+"\x00"+grant.Input] = true
			out = append(out, scanClass{grant: grant, ok: true})
		}
	}
	// Disabled grants never scan, but the plan reports them so the
	// coverage statement stays honest.
	cfg, err := grants.New(stateDir).Load()
	if err != nil {
		return nil, ex, err
	}
	for _, grant := range cfg.Grants {
		if grant.Enabled {
			continue
		}
		if !registry.IsKnownSource(grant.Source) {
			continue
		}
		ex.Disabled = append(ex.Disabled, grant.Source+" "+grant.Input)
	}
	return out, ex, nil
}

// accountNetworkSource reports whether the source belongs to an
// account-level network tool (the Cursor dashboard API today). Such
// sources are collected through their own orchestration and are
// deliberately outside a local rebuild.
func accountNetworkSource(source string) bool {
	for _, spec := range registry.SupportedTools() {
		if spec.Source == source {
			return spec.IsAccountNetwork()
		}
	}
	return false
}

// toolForSource maps an adapter source id to its tool name through the
// dynamic registry (mirrors collection's toolForSource).
func toolForSource(source string) string {
	for _, spec := range registry.SupportedTools() {
		if spec.Source == source {
			return spec.Tool
		}
	}
	return ""
}

// sourceAllowed reports whether the source's tool is within the live
// allowed-tools scope. An empty scope allows every tool; a source without
// a tool mapping cannot be proven allowed, so it is excluded.
func (s liveScope) sourceAllowed(source string) bool {
	if len(s.allowedTools) == 0 {
		return true
	}
	tool := toolForSource(source)
	if tool == "" {
		return false
	}
	_, ok := s.allowedTools[tool]
	return ok
}

// issueIsDiagnostic reports whether a LineIssue reason is one of the
// KNOWN non-fatal diagnostics the pre-scan tolerates: tools that do not
// record a model (the record reports model unknown — the usage itself is
// intact) and duplicate record keys inside one scan (ordinary
// de-duplication). The match is deliberately exact (full-reason equality,
// or the fixed duplicate-key shape with the key in between) rather than a
// broad substring, so a severe reason that merely MENTIONS models — an
// invalid or malformed model, malformed usage counters, invalid JSON,
// missing identity or timestamps — stays severe: the rebuild is about to
// clear the server's only copy of this device's history, and data the
// adapter could not parse must stop the run instead of silently
// shrinking the rebuild. Issue reasons never enter the plan or the
// journal; only counts do.
func issueIsDiagnostic(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	if strings.HasPrefix(r, "duplicate record key ") && strings.HasSuffix(r, " skipped") {
		return true
	}
	// kimi/pi/qwen prefix their source name, workbuddy writes "request
	// model not recorded"; all end with the fixed phrase.
	if strings.HasSuffix(r, "model not recorded; model reported unknown") {
		return true
	}
	const codexPrefix = "token_count delta recorded with model unknown: "
	if strings.HasPrefix(r, codexPrefix) {
		for _, cause := range strings.Split(strings.TrimPrefix(r, codexPrefix), "; ") {
			switch cause {
			case "model switch within interval", "no recorded model in effect", "no turn_context in file", "model not attributable":
			default:
				return false
			}
		}
		return true
	}
	switch r {
	case "model missing from every snapshot of this message; reporting unknown": // claude-code-jsonl
		return true
	case "some opencode messages do not record a model identifier; those records report model unknown": // opencode-sqlite
		return true
	}
	return false
}

// newScanBatchID mints a batch id for the rebuild, namespaced so receipts
// and archives are diagnosable as rebuild artifacts.
func newScanBatchID(now func() time.Time, grantIndex int) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate batch id: %w", err)
	}
	return fmt.Sprintf("recollect-%s-%02d-%s", now().UTC().Format("20060102T150405Z"), grantIndex, hex.EncodeToString(buf[:])), nil
}

// scanState is the accumulator of one pre-scan pass over the frozen grant
// list in the temporary state directory.
type scanState struct {
	tempDir  string
	scope    liveScope
	now      func() time.Time
	outcomes []GrantOutcome
	excluded jobExclusions
}

// scanGrants runs the full pre-scan: for every scanned grant, load the
// source read-only, filter its records against the live consent scope,
// prepare, split, and commit the batches into the temporary state's
// outbox, and persist the per-file scan states. The loop mirrors the
// collection round's scan phase exactly — same pipeline calls, same
// crash-safety (the export WAL, filter transactions, and scan ledger make
// an interrupted scan resumable by re-running it in the same temporary
// state), same known-record cache extension — but it never drains,
// reports tool statuses, or touches the Cursor orchestration.
//
// The empty temporary state is what makes the scan a FULL rebuild:
// interval sources (claude-code-jsonl) start from empty per-message
// baselines and export each message's current cumulative usage, and
// file-state ledgers start empty so every input file is re-parsed. All
// enabled grants of one source share the temporary state's baselines and
// ledgers exactly like a collection round, so synonymous data duplicated
// across two inputs of the same source de-duplicates instead of double
// counting.
func scanGrants(ctx context.Context, s *scanState, scanned []jobGrant, onGrantDone func(jobGrant)) error {
	if err := pipeline.RecoverPendingFilter(s.tempDir); err != nil {
		return err
	}
	for idx, grant := range scanned {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("force recollection stopped during the source scan: %w", err)
		}
		if grant.Done {
			// Completed in an earlier attempt of this job: its batches
			// are already committed in the temporary state and re-scanning
			// it could only duplicate them (sources without a local
			// known-record filter re-export everything they read).
			s.outcomes = append(s.outcomes, GrantOutcome{
				Source:  grant.Source,
				Input:   grant.Input,
				Skipped: "committed in an earlier attempt of this job",
			})
			continue
		}
		if err := scanOneGrant(ctx, s, grant, idx); err != nil {
			return err
		}
		if onGrantDone != nil {
			onGrantDone(grant)
		}
	}
	// The scan completed: no export or filter transaction may remain
	// half-applied in the temporary state (each is recovered at loop
	// entry; a journal that still exists here means recovery itself
	// failed and the scan cannot be frozen).
	for _, wal := range []string{
		exportcommit.JournalPath(s.tempDir),
		filepath.Join(s.tempDir, "filter-transaction.json"),
	} {
		if _, err := os.Stat(wal); err == nil {
			return fmt.Errorf("the temporary scan state still holds a pending transaction journal (%s); re-run the same command to converge it before the rebuild can be confirmed", wal)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// scanOneGrant scans one granted (source, input) into the temporary
// state. Load failures, inaccessible inputs, unevaluable records, and
// severe line issues fail the whole run closed BEFORE anything is reset;
// legitimate empty sources and tolerated diagnostics are recorded as
// outcomes.
func scanOneGrant(ctx context.Context, s *scanState, grant jobGrant, grantIndex int) error {
	outcome := GrantOutcome{Source: grant.Source, Input: grant.Input}
	defer func() { s.outcomes = append(s.outcomes, outcome) }()

	// Re-validate the granted input before reading it: the filesystem may
	// have changed since the grant was recorded. For a rebuild a missing
	// input is fatal, never a zero contribution.
	if err := grants.ValidateInput(grant.Input); err != nil {
		return fmt.Errorf("the granted input for source %s is not readable; refusing to rebuild while a granted source is missing — restore it, disable the grant, or remove the journal to abandon: %w", grant.Source, err)
	}
	batchID, err := newScanBatchID(s.now, grantIndex)
	if err != nil {
		return err
	}
	output := filepath.Join(s.tempDir, "batches", batchID+".json")
	loaded, err := pipeline.LoadSource(adapter.Options{
		Context:  ctx,
		Source:   grant.Source,
		Input:    grant.Input,
		StateDir: s.tempDir,
	})
	if err != nil {
		return fmt.Errorf("the source scan for a granted %s input failed; refusing to rebuild over an unreadable source — fix it and re-run the same command to resume, or remove the journal to abandon: %w", grant.Source, err)
	}
	for _, issue := range loaded.Issues {
		if !issueIsDiagnostic(issue.Reason) {
			return errors.New("a granted source quarantined usage lines the scanner could not parse; refusing to silently shrink the rebuild over unparsed usage — fix the source and re-run the same command to resume, or remove the journal to abandon")
		}
	}
	outcome.Issues = len(loaded.Issues)
	outcome.Quarantined = loaded.Quarantined

	// Live-scope record filter: only records the current authorization
	// covers may enter the rebuilt batches. Out-of-scope records (a
	// disallowed tool, or a record at/after uploadUntil) are NOT dropped:
	// they are quarantined recoverable in the rebuilt state through the
	// same crash-safe filter transaction the ordinary pipeline uses for
	// the history cutoff, with their interval baselines established so
	// they are never replayed as deltas — because the scan ledger marks
	// their files as read, a widened authorization can only recover them
	// from the quarantine store, never from a re-read. Records before
	// historyFrom are left to the pipeline's own FilterHistoryCutoff,
	// which quarantines them the same way.
	kept := make([]adapter.Record, 0, len(loaded.Records))
	keptUpdates := make([]progress.MessagePendingUpdate, 0, len(loaded.MessageUpdates))
	quarantined := make([]quarantine.Entry, 0)
	baselines := make([]progress.MessagePendingUpdate, 0)
	droppedKeys := make(map[string]bool, len(loaded.Records))
	for _, record := range loaded.Records {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("force recollection stopped during the source scan: %w", err)
		}
		in, reason, err := s.scope.evaluateRecord(record)
		if err != nil {
			return fmt.Errorf("a granted %s source produced a record the consent scope cannot evaluate; refusing to rebuild over unevaluable data: %w", grant.Source, err)
		}
		if in {
			kept = append(kept, record)
			continue
		}
		// Only the tool and uploadUntil dimensions are quarantined here;
		// before-history records flow into the pipeline and are handled
		// by FilterHistoryCutoff (which owns the historyFrom semantics
		// and its baselines).
		if reason == quarantine.ReasonBeforeHistoryFrom {
			kept = append(kept, record)
			continue
		}
		key := strings.TrimSpace(adapter.StringField(record, "recordKey"))
		if key == "" {
			return fmt.Errorf("a granted %s source produced an out-of-scope record without a record key; refusing to rebuild over unevaluable data", grant.Source)
		}
		droppedKeys[key] = true
		raw, merr := json.Marshal(record)
		if merr != nil {
			return fmt.Errorf("a granted %s source produced a record that cannot be serialized: %w", grant.Source, merr)
		}
		quarantined = append(quarantined, quarantine.Entry{
			Source:          grant.Source,
			Input:           grant.Input,
			RecordKey:       key,
			Record:          raw,
			OriginBatchID:   batchID,
			Reason:          reason,
			QuarantinedAt:   s.now().UTC(),
			ConsentRevision: s.scope.revision,
		})
	}
	for _, update := range loaded.MessageUpdates {
		if droppedKeys[strings.TrimSpace(update.RecordKey)] {
			// The interval's record is quarantined; its to-state becomes
			// the confirmed baseline so the withheld usage is never
			// replayed from zero, and scope recovery re-sends the stored
			// record verbatim.
			baselines = append(baselines, update)
			continue
		}
		keptUpdates = append(keptUpdates, update)
	}
	outcome.OutOfScope = len(quarantined)
	s.excluded.OutOfScope += len(quarantined)
	if len(quarantined) > 0 || len(baselines) > 0 {
		if err := filtertxn.Commit(s.tempDir, filtertxn.Journal{
			Schema:     filtertxn.SchemaVersion,
			Source:     grant.Source,
			Input:      grant.Input,
			Quarantine: quarantined,
			Baselines:  baselines,
			CreatedAt:  s.now().UTC(),
		}); err != nil {
			return fmt.Errorf("cannot durably quarantine the records the live consent scope excludes; the scan stays resumable — re-run the same command, or remove the journal to abandon: %w", err)
		}
	}

	prepared, err := pipeline.PrepareFromLoaded(adapter.Options{
		Context:     ctx,
		Source:      grant.Source,
		Input:       grant.Input,
		Output:      output,
		BatchID:     batchID,
		StateDir:    s.tempDir,
		HistoryFrom: s.scope.historyFrom,
	}, adapter.LoadResult{
		Records:        kept,
		Issues:         loaded.Issues,
		Quarantined:    loaded.Quarantined,
		MessageUpdates: keptUpdates,
		ScanStates:     loaded.ScanStates,
	})
	if err != nil {
		return fmt.Errorf("the export preparation for a granted %s source failed; refusing to rebuild over a broken source — fix it and re-run the same command to resume, or remove the journal to abandon: %w", grant.Source, err)
	}
	if prepared.Records == 0 {
		outcome.Skipped = "no records in the source under the current authorization"
		outcome.Code = GrantNoRecords
		if err := saveScanStates(s.tempDir, grant.Source, prepared.ScanStates); err != nil {
			return fmt.Errorf("save scan state for source %s: %w", grant.Source, err)
		}
		return nil
	}
	chunks, err := pipeline.SplitPreparedExport(prepared)
	if err != nil {
		return fmt.Errorf("the export split for a granted %s source failed; refusing to rebuild over a broken source: %w", grant.Source, err)
	}
	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("force recollection stopped before export commit: %w", err)
		}
		committed, err := exportcommit.CommitExport(exportcommit.ExportOptions{
			StateDir:    s.tempDir,
			Prepared:    chunk,
			Source:      grant.Source,
			Input:       grant.Input,
			CommittedAt: s.now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("commit the rebuild export for source %s; the scan stays resumable — re-run the same command, or remove the journal to abandon: %w", grant.Source, err)
		}
		if payload, rerr := os.ReadFile(committed.Output); rerr == nil {
			_ = knowncache.AppendCommittedBatch(s.tempDir, grant.Source, committed.BatchID, payload)
		}
		outcome.Exported = true
		outcome.Code = GrantExported
		outcome.BatchIDs = append(outcome.BatchIDs, committed.BatchID)
		outcome.Records += committed.Records
	}
	// The scan states advance only after every chunk committed (mirrors
	// the collection round's ordering).
	if err := saveScanStates(s.tempDir, grant.Source, prepared.ScanStates); err != nil {
		return fmt.Errorf("save scan state for source %s: %w", grant.Source, err)
	}
	return nil
}

// saveScanStates persists the per-file content states a scan observed,
// after that source's records were committed (mirrors collection's
// saveScanStates; a no-op for loaders that report no states).
func saveScanStates(tempDir, source string, states map[string]scanledger.FileState) error {
	if len(states) == 0 {
		return nil
	}
	return scanledger.New(tempDir).Save(source, states)
}

// frozenBatch is one validated artifact of the finished scan.
type frozenBatch struct {
	BatchID string
	File    string
	Source  string
	Input   string
	Records int
	Sum     string
	Created time.Time
}

// freezeArtifacts validates the temporary state's outbox and freezes the
// job's batch list with payload hashes: every entry must still be pending,
// every file must exist, parse as the batch it claims, and carry the
// stamped data epoch. The frozen list is what the journal binds to the
// request id BEFORE the reset is requested, so the reset's coverage is
// exactly the artifacts the user confirmed.
func freezeArtifacts(tempDir string, nextEpoch int64) ([]frozenBatch, error) {
	out, err := outbox.New(tempDir).Load()
	if err != nil {
		return nil, err
	}
	frozen := make([]frozenBatch, 0, len(out.Batches))
	seen := make(map[string]bool, len(out.Batches))
	for _, entry := range out.Batches {
		if seen[entry.BatchID] {
			return nil, fmt.Errorf("the temporary outbox lists batch %s twice; failing closed", entry.BatchID)
		}
		seen[entry.BatchID] = true
		if entry.Status != outbox.StatusPending {
			return nil, fmt.Errorf("the temporary outbox entry %s is %q, not pending; the scan state diverged, failing closed", entry.BatchID, entry.Status)
		}
		raw, err := os.ReadFile(entry.File)
		if err != nil {
			return nil, fmt.Errorf("a scanned batch cannot be read back: %w", err)
		}
		var batch syncclient.BatchRequest
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("a scanned batch is not a valid batch: %w", err)
		}
		if batch.BatchID != entry.BatchID {
			return nil, fmt.Errorf("the scanned batch %s carries a different batch id; the file does not match the outbox entry", entry.BatchID)
		}
		if batch.DataEpoch == nil || *batch.DataEpoch != nextEpoch {
			return nil, fmt.Errorf("the scanned batch %s does not carry the rebuild data epoch %d; the temporary state diverged, failing closed", entry.BatchID, nextEpoch)
		}
		if len(batch.Records) == 0 || (entry.RecordCount > 0 && entry.RecordCount != len(batch.Records)) {
			return nil, fmt.Errorf("the scanned batch %s carries %d record(s) but the outbox recorded %d; failing closed", entry.BatchID, len(batch.Records), entry.RecordCount)
		}
		sum := sha256.Sum256(raw)
		frozen = append(frozen, frozenBatch{
			BatchID: entry.BatchID,
			File:    entry.File,
			Source:  strings.TrimSpace(entry.Source),
			Input:   strings.TrimSpace(entry.Input),
			Records: len(batch.Records),
			Sum:     hex.EncodeToString(sum[:]),
			Created: entry.CreatedAt,
		})
	}
	sort.Slice(frozen, func(i, j int) bool {
		if !frozen[i].Created.Equal(frozen[j].Created) {
			return frozen[i].Created.Before(frozen[j].Created)
		}
		return frozen[i].BatchID < frozen[j].BatchID
	})
	return frozen, nil
}
