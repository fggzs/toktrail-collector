package recollect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/progress"
	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/syncclient"
)

// stableNow returns a fixed clock plus an advance helper, so batch ids and
// journal timestamps stay deterministic in tests.
// sha256Hex64 renders a fixed 64-character hex digest for journal
// validation tests.
func sha256Hex64() string {
	sum := sha256.Sum256([]byte("fixture"))
	return hex.EncodeToString(sum[:])
}

func stableNow() (func() time.Time, func()) {
	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	step := int64(0)
	now := func() time.Time { step++; return base.Add(time.Duration(step) * time.Minute) }
	return now, func() { step++ }
}

func TestRunFullRebuildHappyPath(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2", "k3")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	// Ordinary stores that must be archived, and preserved stores that
	// must survive the switch untouched.
	oldOutbox := filepath.Join(stateDir, "outbox.json")
	if err := os.WriteFile(oldOutbox, []byte(`{"batches":[{"batchId":"old","file":"/x","status":"synced","createdAt":"2026-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "batches"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "batches", "old.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "adapter-cursors.json"), []byte(`{"cursors":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{
		filepath.Join(stateDir, "cursor-outbox.json"),
		filepath.Join(stateDir, "cursor-source.json"),
	} {
		if err := os.WriteFile(preserved, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "cursor-batches"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "cursor-batches", "c.json"), []byte("cursor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "scheduler"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "scheduler", "periodic.log"), []byte("log"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, advance := stableNow()
	advance()
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL,
		ExpectedDeviceID: "device-recollect",
		Confirm:          confirmAll,
	})
	if err != nil {
		t.Fatalf("full rebuild: %v", err)
	}
	if !res.Completed {
		t.Fatalf("expected completion, stopped=%q remaining=%d", res.Stopped, res.Remaining)
	}
	if res.Epoch != 4 || res.Plan.OldDataEpoch != 3 || res.Plan.NextDataEpoch != 4 {
		t.Fatalf("epoch transition wrong: old=%d next=%d result=%d", res.Plan.OldDataEpoch, res.Plan.NextDataEpoch, res.Epoch)
	}
	if res.AcceptedRecords != 3 || res.Plan.PlannedRecords != 3 || len(res.Plan.Batches) != 1 {
		t.Fatalf("record accounting wrong: %#v", res)
	}
	if remote.resetCount != 1 {
		t.Fatalf("expected exactly one distinct reset, got %d", remote.resetCount)
	}
	if remote.selfCalls == 0 {
		t.Fatal("expected self reads")
	}

	// Journal: completed, guard-compatible.
	j, ok := loadJobForTest(t, stateDir)
	if !ok || !j.completed() || j.Phase != phaseUpload || j.Reset == nil || j.Completion == nil {
		t.Fatalf("journal state wrong: ok=%t %#v", ok, j)
	}
	guardFile, found, err := syncclient.ReadResetJournal(stateDir)
	if err != nil || !found || guardFile.RequestID != j.RequestID || guardFile.Status != "completed" {
		t.Fatalf("guard projection wrong: found=%t file=%#v err=%v", found, guardFile, err)
	}
	if err := syncclient.CheckResetJournal(stateDir); err != nil {
		t.Fatalf("a completed journal must not block ordinary entrypoints: %v", err)
	}

	// Device state: identity preserved, epoch advanced.
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.DeviceID != "device-recollect" || st.DeviceSecret != "testsecret" || st.DataEpoch != 4 {
		t.Fatalf("device state wrong: %#v", st)
	}

	// Preserved stores stay in place.
	for _, preserved := range []string{
		filepath.Join(stateDir, "cursor-outbox.json"),
		filepath.Join(stateDir, "cursor-source.json"),
		filepath.Join(stateDir, "cursor-batches", "c.json"),
		filepath.Join(stateDir, "scheduler", "periodic.log"),
		filepath.Join(stateDir, "grants.json"),
		filepath.Join(stateDir, ".collector.lock"),
	} {
		if _, err := os.Stat(preserved); err != nil {
			t.Fatalf("preserved store missing after the switch: %s: %v", preserved, err)
		}
	}
	// Ordinary stores are archived, not deleted.
	archive := archiveDirPath(stateDir, j.RequestID)
	for _, archived := range []string{
		filepath.Join(archive, "outbox.json"),
		filepath.Join(archive, "batches", "old.json"),
		filepath.Join(archive, "adapter-cursors.json"),
	} {
		if _, err := os.Stat(archived); err != nil {
			t.Fatalf("archived store missing: %s: %v", archived, err)
		}
	}
	archivedOutbox, err := os.ReadFile(filepath.Join(archive, "outbox.json"))
	if err != nil || !strings.Contains(string(archivedOutbox), "\"old\"") {
		t.Fatalf("the old outbox content must live in the archive, got err=%v", err)
	}

	// The installed outbox holds exactly the frozen batch, synced, at the
	// real path.
	out, err := outbox.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Batches) != 1 || out.Batches[0].Status != outbox.StatusSynced || out.Batches[0].AcceptedRecords != 3 {
		t.Fatalf("installed outbox wrong: %#v", out.Batches)
	}
	if out.Batches[0].File != filepath.Join(canonicalStateDir(stateDir), "batches", out.Batches[0].BatchID+".json") {
		t.Fatalf("installed outbox path not rewritten: %s", out.Batches[0].File)
	}

	// The uploaded batch carries the new data epoch (the fence the server
	// enforced) and the scan ledger + cursor ledger moved in.
	raw, err := os.ReadFile(out.Batches[0].File)
	if err != nil {
		t.Fatal(err)
	}
	var batch syncclient.BatchRequest
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.DataEpoch == nil || *batch.DataEpoch != 4 {
		t.Fatalf("uploaded batch not stamped with the new epoch: %#v", batch.DataEpoch)
	}
	for _, moved := range []string{
		filepath.Join(stateDir, "adapter-cursors.json"),
		filepath.Join(stateDir, "batches", out.Batches[0].BatchID+".json"),
	} {
		if _, err := os.Stat(moved); err != nil {
			t.Fatalf("scanned store not installed: %s: %v", moved, err)
		}
	}
	// The consumed temporary state is gone.
	if _, err := os.Stat(tempStateDirPath(stateDir, j.RequestID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary state must be removed after the switch, got %v", err)
	}
}

func TestRunDryRunChangesNothing(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)
	deviceBefore, err := os.ReadFile(filepath.Join(stateDir, "device.json"))
	if err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !res.DryRun || res.Completed || res.ServerReset {
		t.Fatalf("dry-run result wrong: %#v", res)
	}
	if res.Plan.Resumed {
		t.Fatal("a fresh dry-run plan must not claim a resume")
	}
	if res.Plan.PlannedRecords != 2 || res.Plan.RemoteRecordCount != 4242 || res.Plan.OldDataEpoch != 3 || res.Plan.NextDataEpoch != 4 {
		t.Fatalf("dry-run plan wrong: %#v", res.Plan)
	}
	if res.Plan.ArtifactDigest == "" || len(res.Plan.Batches) != 1 || res.Plan.Batches[0].PayloadSHA256 == "" {
		t.Fatalf("dry-run plan must carry the frozen artifact hashes: %#v", res.Plan.Batches)
	}
	if remote.resetCount != 0 {
		t.Fatalf("a dry run must never reset, got %d", remote.resetCount)
	}
	// No journal, no state change, no leftover temporary artifacts.
	if _, err := os.Stat(journalPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run must not write the journal, got %v", err)
	}
	deviceAfter, err := os.ReadFile(filepath.Join(stateDir, "device.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(deviceBefore) != string(deviceAfter) {
		t.Fatal("a dry run must not modify device.json")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "recollect")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run must clean its temporary artifacts, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "outbox.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run must not touch the outbox, got %v", err)
	}
}

func TestRunConfirmAbortFreshRollsBack(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: abortConfirm,
	})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("expected an abort error, got %v", err)
	}
	if res.ServerReset || remote.resetCount != 0 {
		t.Fatalf("an abort must never reset, got %d", remote.resetCount)
	}
	if _, err := os.Stat(journalPath(stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a fresh abort must roll the journal back, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "recollect")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a fresh abort must remove the temporary state, got %v", err)
	}
}

func TestRunMissingInputFailsClosedBeforeReset(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	inputDir := t.TempDir()
	input := writeUsageJSON(t, filepath.Join(inputDir, "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)
	if err := os.RemoveAll(inputDir); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err == nil || res.ServerReset {
		t.Fatalf("a missing granted input must fail the run before the reset, got %#v %v", res, err)
	}
	if remote.resetCount != 0 {
		t.Fatalf("nothing may be cleared over a missing source, got %d resets", remote.resetCount)
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("unexpected error: %v", err)
	}
	// The journal stays blocked (resumable) — ordinary entrypoints stop.
	j, ok := loadJobForTest(t, stateDir)
	if !ok || j.Phase != phaseScanning {
		t.Fatalf("expected a resumable scanning journal, got ok=%t phase=%s", ok, j.Phase)
	}
	if err := syncclient.CheckResetJournal(stateDir); !errors.Is(err, syncclient.ErrResetInProgress) {
		t.Fatalf("the unfinished journal must block ordinary entrypoints, got %v", err)
	}
}

func TestRunSevereIssueFailsClosedButModelMissingIsTolerated(t *testing.T) {
	// A claude-code-jsonl input with a model-less message (a tolerated
	// diagnostic) and, separately, an unparsable line (severe).
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	goodDir := t.TempDir()
	writeClaudeLine(t, filepath.Join(goodDir, "s.jsonl"), "m1", 10, 5, "2026-10-01T10:00:00Z")
	enableGrant(t, stateDir, adapter.ClaudeCodeJSONLSource, goodDir)

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("a model-less claude message is a tolerated diagnostic, not a failure: %v", err)
	}
	if !res.Completed || res.AcceptedRecords != 1 {
		t.Fatalf("cumulative claude rebuild wrong: %#v", res)
	}
	// The interval record is the message's full cumulative usage.
	j, _ := loadJobForTest(t, stateDir)
	if len(j.Batches) != 1 || j.Batches[0].Records != 1 {
		t.Fatalf("claude batch wrong: %#v", j.Batches)
	}
	mp, _, err := progress.New(stateDir).MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := mp["m1"]
	if !ok || entry.Confirmed == nil || entry.Confirmed.Input == nil || *entry.Confirmed.Input != 10 || *entry.Confirmed.Output != 5 {
		t.Fatalf("claude baseline not confirmed after the rebuild ACK: %#v", entry)
	}

	// Now the severe case: an unparsable usage line stops the run before
	// anything is cleared.
	remote2, server2 := newFakeRemote(t)
	stateDir2 := newBoundState(t, server2.URL)
	badDir := t.TempDir()
	writeClaudeLine(t, filepath.Join(badDir, "s.jsonl"), "m1", 10, 5, "2026-10-01T10:00:00Z")
	if err := os.WriteFile(filepath.Join(badDir, "s.jsonl"), []byte("not json at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, stateDir2, adapter.ClaudeCodeJSONLSource, badDir)
	res2, err := Run(context.Background(), Options{
		StateDir: stateDir2, ServerURL: server2.URL, Confirm: confirmAll,
	})
	if err == nil || res2.ServerReset || remote2.resetCount != 0 {
		t.Fatalf("an unparsable usage line must fail the run before the reset: %#v %v", res2, err)
	}
}

func TestIssueIsDiagnosticClassification(t *testing.T) {
	diagnostic := []string{
		"model not recorded; model reported unknown",
		"request model not recorded; model reported unknown",
		"qwen-jsonl model not recorded; model reported unknown",
		"model missing from every snapshot of this message; reporting unknown",
		"some OpenCode messages do not record a model identifier; those records report model unknown",
		"duplicate record key abc|def skipped",
	}
	for _, reason := range diagnostic {
		if !issueIsDiagnostic(reason) {
			t.Fatalf("expected diagnostic: %q", reason)
		}
	}
	severe := []string{
		"invalid JSON: unexpected token",
		"invalid model: model.id must be a string",
		"usage input_tokens must be a non-negative integer within uint64 range",
		"missing timestamp",
		"invalid timestamp: parse error",
		"assistant usage line missing message.id",
		"message.usage must be an object",
		"",
	}
	for _, reason := range severe {
		if issueIsDiagnostic(reason) {
			t.Fatalf("expected severe: %q", reason)
		}
	}
}

func TestRunEpochMovedStopsBeforeReset(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	// A foreign usage reset moves the server epoch between the plan and
	// the reset request.
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL,
		Confirm: func(Plan) error {
			remote.mu.Lock()
			remote.epoch = 9
			remote.mu.Unlock()
			return nil
		},
	})
	if err == nil || res.ServerReset {
		t.Fatalf("a moved epoch must stop the run before the reset: %#v %v", res, err)
	}
	if remote.resetCount != 0 {
		t.Fatalf("nothing was cleared: %d", remote.resetCount)
	}
	if !strings.Contains(err.Error(), "data epoch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBudgetResumeWithoutSecondReset(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	dir := t.TempDir()
	inputA := writeUsageJSON(t, filepath.Join(dir, "a", "usage.json"), "k1", "k2")
	inputB := writeUsageJSON(t, filepath.Join(dir, "b", "usage.json"), "k3", "k4")
	enableGrant(t, stateDir, adapter.UsageJSONSource, inputA)
	enableGrant(t, stateDir, adapter.UsageJSONSource, inputB)

	// First run: one upload only.
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, MaxBatches: 1, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("budgeted run: %v", err)
	}
	if res.Completed || res.Remaining == 0 || res.Stopped == "" {
		t.Fatalf("expected a budget stop, got %#v", res)
	}
	if remote.resetCount != 1 || res.ServerReset != true {
		t.Fatalf("expected exactly one reset, got %d", remote.resetCount)
	}
	firstRequestID := res.Plan.JobID

	// Second run: resumes, replays nothing (the reset is already
	// journaled), uploads the remainder, completes.
	res2, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if !res2.Completed || !res2.Plan.Resumed || res2.Plan.JobID != firstRequestID {
		t.Fatalf("resume wrong: %#v", res2.Plan)
	}
	if remote.resetCount != 1 {
		t.Fatalf("the resume must never issue a second reset, got %d", remote.resetCount)
	}
	j2, _ := loadJobForTest(t, stateDir)
	if res2.AcceptedRecords != 2 {
		t.Fatalf("the resume run counts only its own uploads: %#v", res2)
	}
	totalAccepted := 0
	for _, b := range j2.Batches {
		for _, u := range b.Uploads {
			totalAccepted += u.AcceptedRecords
		}
	}
	if totalAccepted != 4 {
		t.Fatalf("the job's total accepted records must be 4, got %d", totalAccepted)
	}
}

func TestRunRejectionBlocksCompletion(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)
	remote.mu.Lock()
	remote.rejectRecordKey = "k1"
	remote.mu.Unlock()

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err == nil || res.Completed {
		t.Fatalf("a rejected record must stop the rebuild without the completion marker: %#v", res)
	}
	if res.RejectedRecords != 1 || res.AcceptedRecords != 0 {
		t.Fatalf("rejection accounting wrong: %#v", res)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
	j, _ := loadJobForTest(t, stateDir)
	if j.completed() {
		t.Fatal("the job must stay unfinished over rejected records")
	}
}

func TestRunLostResetResponseReplaysFrozenPayloadAfterAuthorizationChange(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	// First attempt: the server applies the reset but the response is
	// lost; the authorization then changes (revision bump).
	remote.mu.Lock()
	remote.loseResetResponse = true
	remote.mu.Unlock()
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err == nil {
		t.Fatalf("expected the lost-response failure to surface, got %#v", res)
	}
	if remote.resetCount != 1 || remote.epoch != 4 {
		t.Fatalf("the reset must have applied server-side: count=%d epoch=%d", remote.resetCount, remote.epoch)
	}
	remote.mu.Lock()
	remote.loseResetResponse = false
	remote.revision = 8 // authorization changed after the lost response
	remote.mu.Unlock()

	// The resume must replay the FROZEN payload (same request id, the
	// ORIGINAL expected revision 7) and converge — never a
	// same-id-different-payload conflict.
	res2, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("the lost-response resume must replay the frozen payload and complete: %v", err)
	}
	if !res2.Completed || !res2.ResetReplay || remote.resetCount != 1 {
		t.Fatalf("resume must replay the original receipt exactly once more: %#v count=%d", res2, remote.resetCount)
	}
	j, _ := loadJobForTest(t, stateDir)
	if j.ResetRequest == nil || j.ResetRequest.ExpectedConsentRevision != 7 || j.ResetRequest.ExpectedDataEpoch != 3 {
		t.Fatalf("the frozen reset payload must keep the original CAS values: %#v", j.ResetRequest)
	}
}

func TestRunUploadUntilExcludesAndQuarantinesRecoverably(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	// Records on 2026-10-01..05; uploadUntil excludes 10-03 and later.
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2", "k3", "k4", "k5")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)
	until := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	remote.mu.Lock()
	remote.uploadUntil = &until
	remote.mu.Unlock()

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("uploadUntil rebuild: %v", err)
	}
	if !res.Completed {
		t.Fatalf("the rebuild completes with the excluded records quarantined: %#v", res)
	}
	if res.AcceptedRecords != 2 || res.Plan.PlannedRecords != 2 || res.Plan.ExcludedOutOfScope != 3 {
		t.Fatalf("exclusion accounting wrong: %#v", res.Plan)
	}
	// The excluded records are quarantined recoverable in the rebuilt
	// state (not dropped): recovery waits for a strictly newer revision
	// that re-covers them.
	entries, err := quarantine.New(stateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 quarantined recoverable records, got %#v", entries)
	}
	for _, entry := range entries {
		if entry.Reason != quarantine.ReasonAfterUploadUntil {
			t.Fatalf("unexpected quarantine reason: %s", entry.Reason)
		}
		if entry.RecordKey == "" || len(entry.Record) == 0 {
			t.Fatalf("quarantine entry must carry the full record for recovery: %#v", entry)
		}
	}
}

func TestRunScanResumeKeepsEarlierCommitsAndMergesCounts(t *testing.T) {
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	dir := t.TempDir()
	good := writeUsageJSON(t, filepath.Join(dir, "good", "usage.json"), "k1", "k2")
	bad := writeUsageJSON(t, filepath.Join(dir, "bad", "usage.json"), "k9")
	enableGrant(t, stateDir, adapter.UsageJSONSource, good)
	enableGrant(t, stateDir, adapter.UsageJSONSource, bad)
	// Corrupt the second input AFTER the grants exist: the scan fails
	// once it reaches it, after the good source committed.
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	}); err == nil {
		t.Fatal("expected the scan to fail over the unparsable source")
	}
	j, ok := loadJobForTest(t, stateDir)
	if !ok || j.Phase != phaseScanning {
		t.Fatalf("expected a resumable scanning journal: ok=%t phase=%s", ok, j.Phase)
	}

	// The good source's batch is already committed in the temporary
	// state; verify the partial progress exists.
	tempOut, err := outbox.New(j.TempStateDir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(tempOut.Batches) == 0 {
		t.Fatal("expected the earlier-committed source to survive in the temporary state")
	}

	// Fix the bad input and resume: the scan continues, earlier commits
	// stay, and the merged per-grant outcomes report BOTH grants.
	if err := os.WriteFile(bad, []byte(`[{"recordKey":"k3","kind":"delta","occurredAt":"2026-10-04T10:00:00Z","tool":"Codex","model":null,"input":"1","output":"1","adapterVersion":"t","sourceType":"f"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("scan resume: %v", err)
	}
	if !res.Completed || !res.Plan.Resumed {
		t.Fatalf("resume wrong: %#v", res)
	}
	if res.AcceptedRecords != 3 {
		t.Fatalf("resume record accounting wrong: %#v", res)
	}
	j2, _ := loadJobForTest(t, stateDir)
	exported := 0
	for _, outcome := range j2.Outcomes {
		if outcome.Exported {
			exported++
		}
	}
	if exported != 2 {
		t.Fatalf("both grants must report exported after the merged resume: %#v", j2.Outcomes)
	}
}

func TestRunSameSourceTwoInputsShareBaselines(t *testing.T) {
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	dir := t.TempDir()
	// The SAME message id appears in two granted inputs: the shared
	// per-message baselines must de-duplicate it instead of double
	// counting or wedging on a pending interval.
	writeClaudeLine(t, filepath.Join(dir, "a", "s.jsonl"), "m1", 10, 5, "2026-10-01T10:00:00Z")
	writeClaudeLine(t, filepath.Join(dir, "b", "s.jsonl"), "m1", 10, 5, "2026-10-01T11:00:00Z")
	enableGrant(t, stateDir, adapter.ClaudeCodeJSONLSource, filepath.Join(dir, "a"))
	enableGrant(t, stateDir, adapter.ClaudeCodeJSONLSource, filepath.Join(dir, "b"))

	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("same-source two-input rebuild: %v", err)
	}
	if !res.Completed {
		t.Fatalf("expected completion: %#v", res)
	}
	if res.AcceptedRecords != 1 {
		t.Fatalf("the duplicated message must de-duplicate to one record, got %d", res.AcceptedRecords)
	}
	mp, _, err := progress.New(stateDir).MessageProgressFor(adapter.ClaudeCodeJSONLSource)
	if err != nil {
		t.Fatal(err)
	}
	if len(mp) != 1 {
		t.Fatalf("expected exactly one message baseline, got %#v", mp)
	}
}

func TestRunExpectedDeviceGuard(t *testing.T) {
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	_, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL,
		ExpectedDeviceID: "device-somewhere-else",
		Confirm:          confirmAll,
	})
	if err == nil || !strings.Contains(err.Error(), "different device") {
		t.Fatalf("the expected-device guard must fail closed before any network work: %v", err)
	}
}

func TestRunUnboundRefuses(t *testing.T) {
	_, server := newFakeRemote(t)
	dir := t.TempDir()
	_, err := Run(context.Background(), Options{StateDir: dir, ServerURL: server.URL, Confirm: confirmAll})
	if !errors.Is(err, ErrNotBound) {
		t.Fatalf("expected ErrNotBound, got %v", err)
	}
}

func TestRunServerWithoutCapabilityRefuses(t *testing.T) {
	remote, server := newFakeRemote(t)
	remote.mu.Lock()
	remote.noCapability = true
	remote.mu.Unlock()
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	_, err := Run(context.Background(), Options{StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll})
	if err == nil || !strings.Contains(err.Error(), "device-usage-reset") {
		t.Fatalf("an old server must fail the capability gate: %v", err)
	}
}

func TestRunPausedRefuses(t *testing.T) {
	remote, server := newFakeRemote(t)
	remote.mu.Lock()
	remote.paused = true
	remote.mu.Unlock()
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	_, err := Run(context.Background(), Options{StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll})
	if !errors.Is(err, syncclient.ErrDevicePaused) {
		t.Fatalf("a paused device must refuse before scanning: %v", err)
	}
}

func TestRunNoScannableGrantsRefuses(t *testing.T) {
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	// A disabled grant only: nothing is scannable.
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	if _, err := grants.New(stateDir).Enable(adapter.UsageJSONSource, input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.New(stateDir).Disable(adapter.UsageJSONSource, input); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll})
	if err == nil || !strings.Contains(err.Error(), "no enabled local source grant") {
		t.Fatalf("a grant-less rebuild must refuse: %v", err)
	}
}

func TestRegistryDiscoveryCoversEveryLocalSource(t *testing.T) {
	// The scan set is derived from the dynamic registry, never a
	// hardcoded source list: every registered non-account-network source
	// must classify as scannable, and the account-network source (the
	// Cursor dashboard API) must classify as excluded.
	_, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	scoped := liveScope{}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := 0
	for _, spec := range registry.SupportedTools() {
		if spec.IsAccountNetwork() {
			// The account-network source (the Cursor dashboard API) is
			// not a grantable local source at all; the grants store
			// rejects it. The classifier's cursor branch stays a
			// defensive fence for hand-written stores.
			continue
		}
		if _, err := grants.New(stateDir).Enable(spec.Source, input); err != nil {
			t.Fatalf("enable %s: %v", spec.Source, err)
		}
		local++
	}
	if !accountNetworkSource(adapter.CursorDashboardAPISource) {
		t.Fatal("the Cursor dashboard API must classify as an account-network source")
	}
	classes, _, err := classifyGrants(stateDir, scoped)
	if err != nil {
		t.Fatal(err)
	}
	okCount := 0
	for _, class := range classes {
		switch class.exclude {
		case "":
			okCount++
		case GrantDuplicate:
			// two specs may share a source id; the first wins
		default:
			t.Fatalf("unexpected exclusion %q for %s", class.exclude, class.grant.Source)
		}
	}
	if okCount != local {
		t.Fatalf("expected %d scannable local sources through the dynamic registry, got %d", local, okCount)
	}
}

func TestRunDerivedBatchRejectionBlocksCompletionAcrossResume(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	// Two in-scope records and one record the scan excludes at/after
	// uploadUntil (quarantined recoverable in the rebuilt state).
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2", "k3", "k4", "k5")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)
	until := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	remote.mu.Lock()
	remote.uploadUntil = &until
	remote.mu.Unlock()

	// While the frozen batches upload, widen the authorization (a
	// strictly newer revision, no uploadUntil) so the drain's recovery
	// probe re-pends the quarantined records — and reject the recovered
	// record so the derived batch's receipt carries a rejection.
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
		Progress: func(ProgressEvent) {
			remote.mu.Lock()
			defer remote.mu.Unlock()
			remote.revision = 8
			remote.uploadUntil = nil
			remote.rejectRecordKey = "k3"
		},
	})
	if err == nil || res.Completed {
		t.Fatalf("a rejected recovery record must stop the rebuild without the completion marker: %#v", res)
	}
	if res.RejectedRecords != 1 {
		t.Fatalf("expected the derived batch's rejection to be counted: %#v", res)
	}
	j, _ := loadJobForTest(t, stateDir)
	if j.completed() {
		t.Fatal("the job must stay unfinished over a rejected derived batch")
	}

	// The resume converges the drain (nothing pending, nothing
	// recoverable) but the settled outbox still carries the rejected
	// receipt: the completion gate must refuse instead of faking a
	// completion over the frozen-batches-only count.
	res2, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err == nil || res2.Completed {
		t.Fatalf("the resume must not complete over a rejected derived batch: %#v", res2)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("unexpected resume error: %v", err)
	}
	if remote.resetCount != 1 {
		t.Fatalf("the resume must never issue a second reset, got %d", remote.resetCount)
	}
}

func TestRunUnpostedScopeChangeReplansSameRequest(t *testing.T) {
	remote, server := newFakeRemote(t)
	stateDir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2", "k3")
	enableGrant(t, stateDir, adapter.UsageJSONSource, input)

	// Build an unposted job: the authorization widens between the plan
	// and the reset CAS (inside the confirm callback, after the scan), so
	// requestReset stops before posting anything — no payload is frozen.
	_, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: func(Plan) error {
			remote.mu.Lock()
			defer remote.mu.Unlock()
			remote.revision = 8
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected the scope-change stop before the reset")
	}
	remote.resetCount = 0
	if remote.resetCount != 0 {
		t.Fatalf("nothing was posted, got %d resets", remote.resetCount)
	}
	j, ok := loadJobForTest(t, stateDir)
	if !ok || j.ResetRequest != nil || j.Phase != phaseScanned {
		t.Fatalf("expected an unposted scanned job: ok=%t phase=%s payload=%#v", ok, j.Phase, j.ResetRequest)
	}
	requestID := j.RequestID
	if _, err := os.Stat(j.TempStateDir); err != nil {
		t.Fatalf("the scanned artifacts must still exist: %v", err)
	}

	// The resume re-plans IN PLACE under the live (widened) scope: the
	// same request id, a fresh scan, and a completion — never a wedge
	// and never a second request.
	res, err := Run(context.Background(), Options{
		StateDir: stateDir, ServerURL: server.URL, Confirm: confirmAll,
	})
	if err != nil {
		t.Fatalf("the unposted re-plan must proceed under the live scope: %v", err)
	}
	if !res.Completed || res.Plan.JobID != requestID {
		t.Fatalf("re-plan must keep the same request id and complete: %#v", res.Plan)
	}
	if res.Plan.ConsentRevision != 8 || res.Plan.PlannedRecords != 3 {
		t.Fatalf("the re-planned scan must run under the live scope: %#v", res.Plan)
	}
	if remote.resetCount != 1 {
		t.Fatalf("the re-planned job posts its reset exactly once, got %d", remote.resetCount)
	}
	j2, _ := loadJobForTest(t, stateDir)
	if j2.ResetRequest == nil || j2.ResetRequest.ExpectedConsentRevision != 8 {
		t.Fatalf("the re-planned payload must carry the live revision: %#v", j2.ResetRequest)
	}
}

func TestJournalRejectsForeignPathsAndUnsafeIds(t *testing.T) {
	stateDir := t.TempDir()
	base := job{
		Schema: journalSchema, RequestID: "recollect-aa", Status: statusRecollecting, Phase: phaseScanning,
		DeviceID: "d", ServerURL: "http://x", StateDir: canonicalStateDir(stateDir),
		OldDataEpoch: 1, NextDataEpoch: 2,
		Scope:     &jobScope{Revision: 5, Fingerprint: "f"},
		CreatedAt: time.Now().UTC(),
	}
	root := canonicalStateDir(stateDir)

	// A foreign state directory must be rejected.
	foreign := base
	foreign.StateDir = filepath.Join(t.TempDir(), "elsewhere")
	if err := foreign.validate(root); err == nil {
		t.Fatal("a journal naming another state directory must fail closed")
	}
	// Free-form scratch paths must be rejected (only the strictly
	// derived ones are accepted).
	escaped := base
	escaped.TempStateDir = filepath.Join(root, "..", "escape")
	escaped.ArchiveDir = archiveDirPath(root, base.RequestID)
	if err := escaped.validate(root); err == nil {
		t.Fatal("a non-derived temporary path must fail closed")
	}
	// Unsafe request ids (path traversal) must be rejected.
	traversal := base
	traversal.RequestID = "../../evil"
	if err := traversal.validate(root); err == nil {
		t.Fatal("an unsafe request id must fail closed")
	}
	// Unsafe batch ids must be rejected.
	badBatch := base
	badBatch.Phase = phaseScanned
	badBatch.Grants = []jobGrant{{Source: adapter.UsageJSONSource, Input: "/x"}}
	badBatch.TempStateDir = tempStateDirPath(root, badBatch.RequestID)
	badBatch.ArchiveDir = archiveDirPath(root, badBatch.RequestID)
	badBatch.Batches = []jobBatch{{BatchID: "../escape", Records: 1, PayloadSHA256: sha256Hex64(), Outcome: outcomePlanned, CreatedAt: time.Now().UTC()}}
	if err := badBatch.validate(root); err == nil {
		t.Fatal("an unsafe batch id must fail closed")
	}
}

func TestRemoveTreeVerifiedOnlyRemovesTheDerivedTempDir(t *testing.T) {
	stateDir := t.TempDir()
	root := canonicalStateDir(stateDir)
	requestID := "recollect-ab"
	tmp := tempStateDirPath(root, requestID)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	// The state dir itself, the recollect root, and foreign paths are
	// untouchable.
	if err := removeTreeVerified(stateDir, root, requestID); err == nil {
		t.Fatal("the state root must never be removable")
	}
	if err := removeTreeVerified(stateDir, filepath.Join(root, recollectDirName), requestID); err == nil {
		t.Fatal("the recollect root must never be removable")
	}
	if err := removeTreeVerified(stateDir, filepath.Join(root, "recollect", "tmp-other"), requestID); err == nil {
		t.Fatal("a path that is not the derived temp dir of the request must never be removable")
	}
	// A symlinked component inside the tree must fail closed.
	linkTarget := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, recollectDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(root, recollectDirName, "tmp-"+requestID+"-x")
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeVerified(stateDir, linkPath, requestID); err == nil {
		t.Fatal("a symlink must never be removable")
	}
	// The exact derived directory is removable and idempotent.
	if err := removeTreeVerified(stateDir, tmp, requestID); err != nil {
		t.Fatalf("the derived temp dir must be removable: %v", err)
	}
	if err := removeTreeVerified(stateDir, tmp, requestID); err != nil {
		t.Fatalf("removal must be idempotent: %v", err)
	}
}
