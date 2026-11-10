package recollect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"toktrail-collector/internal/source/adapter"
)

func TestResumeAfterArchiveBeforeBatchInstall(t *testing.T) {
	remote, server := newFakeRemote(t)
	dir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1", "k2")
	enableGrant(t, dir, adapter.UsageJSONSource, input)
	remote.loseResetResponse = true
	_, err := Run(context.Background(), Options{StateDir: dir, Confirm: confirmAll})
	if err == nil || remote.resetCount != 1 {
		t.Fatal("fixture must stop after server reset with an unresolved receipt")
	}
	j, _ := loadJobForTest(t, dir)
	receipt := remote.resets[j.RequestID]
	j.Reset = &receipt
	j.Phase = phaseReset
	if err := archiveOrdinaryStores(j.StateDir, j.ArchiveDir); err != nil {
		t.Fatal(err)
	}
	j.Install = &installSteps{Archived: true}
	if err := saveJob(j.StateDir, j, time.Now); err != nil {
		t.Fatal(err)
	}
	remote.loseResetResponse = false
	res, err := Run(context.Background(), Options{StateDir: dir, Confirm: confirmAll})
	if err != nil || !res.Completed {
		t.Fatalf("mid-install resume must locate temporary batches and converge: %v", err)
	}
	if remote.resetCount != 1 {
		t.Fatal("mid-install resume cleared server history again")
	}
}

func TestConfirmedStateArtifactTamperingStopsBeforeReset(t *testing.T) {
	remote, server := newFakeRemote(t)
	dir := newBoundState(t, server.URL)
	input := writeUsageJSON(t, filepath.Join(t.TempDir(), "usage.json"), "k1")
	enableGrant(t, dir, adapter.UsageJSONSource, input)
	_, err := Run(context.Background(), Options{StateDir: dir, Confirm: func(plan Plan) error {
		j, _ := loadJobForTest(t, dir)
		for name := range j.StoreHashes {
			if name == "outbox.json" {
				continue
			}
			return os.WriteFile(filepath.Join(j.TempStateDir, name), []byte("tampered baseline"), 0o600)
		}
		t.Fatal("fixture must contain a frozen non-batch state artifact")
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("state artifact drift must fail closed: %v", err)
	}
	if remote.resetCount != 0 {
		t.Fatal("tampered pre-scan state was installed after clearing server data")
	}
}

func TestZeroRecordRecollectionStillFreezesStateManifest(t *testing.T) {
	remote, server := newFakeRemote(t)
	dir := newBoundState(t, server.URL)
	input := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(input, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	enableGrant(t, dir, adapter.UsageJSONSource, input)
	res, err := Run(context.Background(), Options{StateDir: dir, Confirm: confirmAll})
	if err != nil || !res.Completed || remote.resetCount != 1 {
		t.Fatalf("an explicitly confirmed empty scan should complete safely: %v", err)
	}
	j, _ := loadJobForTest(t, dir)
	if j.StoreHashes["outbox.json"] == "" {
		t.Fatal("zero-record rebuild lacks a frozen outbox manifest")
	}
	j.StoreHashes = nil
	if err := j.validate(j.StateDir); err == nil {
		t.Fatal("missing state manifest must fail journal validation")
	}
}

func TestCodexAttributionDiagnosticsAreNotParseFailures(t *testing.T) {
	for _, reason := range []string{
		"token_count delta recorded with model unknown: no turn_context in file",
		"token_count delta recorded with model unknown: model switch within interval; no recorded model in effect",
	} {
		if !issueIsDiagnostic(reason) {
			t.Fatalf("valid Codex attribution diagnostic rejected: %s", reason)
		}
	}
	if issueIsDiagnostic("token_count delta recorded with model unknown: invalid JSON") {
		t.Fatal("unknown cause must not be allowed as a harmless diagnostic")
	}
}
