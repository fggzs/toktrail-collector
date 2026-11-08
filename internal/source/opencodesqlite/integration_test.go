package opencodesqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/opencodesqlite"
	"toktrail-collector/internal/source/pipeline"
	"toktrail-collector/internal/source/registry"
	"toktrail-collector/internal/source/usagejson"
)

func TestAdapterViaRegistryAndPipeline(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "opencode.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, time_updated INTEGER, data TEXT)`); err != nil {
		t.Fatal(err)
	}
	data := `{"agent":"build","model":{"providerID":"minimax","id":"MiniMax-M3","variant":"default"},"tokens":{"input":23291,"output":472,"reasoning":0,"cache":{"read":31360,"write":0}},"time":{"created":1790000001000,"completed":1790000002000}}`
	if _, err := db.Exec(`INSERT INTO session_message VALUES ('msg_1','ses_1','assistant',1,1790000001000,1790000001000,?)`, data); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reg, err := registry.New(usagejson.Adapter(), opencodesqlite.Adapter())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Lookup(adapter.OpenCodeSQLiteSource); !ok {
		t.Fatalf("registry must expose %s", adapter.OpenCodeSQLiteSource)
	}
	p := pipeline.New(reg)
	scan, err := p.Scan(adapter.Options{Source: adapter.OpenCodeSQLiteSource, Input: dir, Context: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	if scan.TokensInclude == nil || *scan.TokensInclude != 23291+31360+472 {
		t.Fatalf("scan include total must sum the four buckets: %#v", scan.TokensInclude)
	}
	exclude := scan.TokensExclude
	if exclude == nil || *exclude != 23291+472 {
		t.Fatalf("scan exclude total must be net input + output: %#v", exclude)
	}
}
