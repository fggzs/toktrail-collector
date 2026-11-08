package registry

import (
	"reflect"
	"testing"

	"toktrail-collector/internal/source/adapter"
)

func TestListsCompiledInSources(t *testing.T) {
	adapters := All()
	if len(adapters) != 14 {
		t.Fatalf("expected 14 compiled-in adapters, got %d", len(adapters))
	}
	var sources []string
	for _, entry := range adapters {
		if entry.Source == "" || entry.Description == "" || entry.Load == nil {
			t.Fatalf("adapter registry entry is incomplete: %#v", entry)
		}
		if !IsKnownSource(entry.Source) {
			t.Fatalf("registry source %q is not known", entry.Source)
		}
		sources = append(sources, entry.Source)
	}
	expected := []string{adapter.UsageJSONSource, adapter.CodexJSONLSource, adapter.ClaudeCodeJSONLSource, adapter.DeepSeekHarnessSource, adapter.WorkBuddyJSONLSource, adapter.QwenJSONLSource, adapter.KimiCLIJSONLSource, adapter.KimiCodeJSONLSource, adapter.ZCodeSQLiteSource, adapter.HermesSQLiteSource, adapter.OpenClawSQLiteSource, adapter.PiJSONLSource, adapter.OMPJSONLSource, adapter.CodeBuddyJSONSource}
	if !reflect.DeepEqual(sources, expected) {
		t.Fatalf("unexpected adapter order: got %#v want %#v", sources, expected)
	}
	if !reflect.DeepEqual(KnownSources(), expected) {
		t.Fatalf("unexpected known sources: got %#v want %#v", KnownSources(), expected)
	}
	if IsKnownSource("missing-source") {
		t.Fatal("unknown source reported as known")
	}
}

func TestAllReturnsCopy(t *testing.T) {
	first := All()
	first[0].Source = "mutated"
	if got := All()[0].Source; got != adapter.UsageJSONSource {
		t.Fatalf("registry was mutated through returned slice: %q", got)
	}
}
