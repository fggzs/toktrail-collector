package codebuddyhistory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/codebuddyhistory"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/source/usagejson"
)

func TestAdapterViaRegistryAndPipeline(t *testing.T) {
	root := t.TempDir()
	req := `{"id":"req-1","type":"craft","state":"complete","startedAt":1790000001000,"usage":{"inputTokens":78677,"outputTokens":1609,"totalTokens":80286,"lastTokens":0,"cacheTokens":31360,"cachedWriteTokens":0,"cachedMissTokens":47317,"credit":1.5}}`
	index := `{"messages":[],"requests":[` + req + `]}`
	path := filepath.Join(root, "history", "ws1", "conv1", "index.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := registry.New(usagejson.Adapter(), codebuddyhistory.Adapter())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Lookup(adapter.CodeBuddyHistorySource); !ok {
		t.Fatalf("registry must expose %s", adapter.CodeBuddyHistorySource)
	}
	p := pipeline.New(reg)
	scan, err := p.Scan(adapter.Options{Source: adapter.CodeBuddyHistorySource, Input: root, Context: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	if scan.TokensInclude == nil || *scan.TokensInclude != 80286 {
		t.Fatalf("scan include total must equal inputTokens + outputTokens: %#v", scan.TokensInclude)
	}
	exclude := scan.TokensExclude
	if exclude == nil || *exclude != 78677+1609-31360 {
		t.Fatalf("scan exclude total must be net input + output: %#v", exclude)
	}
}
