// Package registry owns the explicit compiled-in adapter set and dispatch.
package registry

import (
	"fmt"
	"strings"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/source/claudecodejsonl"
	"toktrail-collector/internal/source/codebuddyhistory"
	"toktrail-collector/internal/source/codexjsonl"
	"toktrail-collector/internal/source/deepseekharness"
	"toktrail-collector/internal/source/hermessqlite"
	"toktrail-collector/internal/source/kimiwire"
	"toktrail-collector/internal/source/openclawsqlite"
	"toktrail-collector/internal/source/opencodesqlite"
	"toktrail-collector/internal/source/piwire"
	"toktrail-collector/internal/source/qwenjsonl"
	"toktrail-collector/internal/source/usagejson"
	"toktrail-collector/internal/source/workbuddyjsonl"
	"toktrail-collector/internal/source/zcodesqlite"
)

type Registry struct{ adapters []adapter.Adapter }

func New(adapters ...adapter.Adapter) (*Registry, error) {
	r := &Registry{adapters: make([]adapter.Adapter, 0, len(adapters))}
	seen := map[string]bool{}
	for _, a := range adapters {
		a.Source = strings.TrimSpace(a.Source)
		if a.Source == "" {
			return nil, fmt.Errorf("adapter source is empty")
		}
		if seen[a.Source] {
			return nil, fmt.Errorf("duplicate adapter source %q", a.Source)
		}
		if a.Load == nil {
			return nil, fmt.Errorf("adapter %q has no loader", a.Source)
		}
		seen[a.Source] = true
		r.adapters = append(r.adapters, a)
	}
	return r, nil
}

var production = mustProduction()

func mustProduction() *Registry {
	r, err := New(usagejson.Adapter(), codexjsonl.Adapter(), claudecodejsonl.Adapter(), deepseekharness.Adapter(), workbuddyjsonl.Adapter(), qwenjsonl.Adapter(), kimiwire.KimiCLIAdapter(), kimiwire.KimiCodeAdapter(), zcodesqlite.Adapter(), hermessqlite.Adapter(), openclawsqlite.Adapter(), piwire.PiAdapter(), piwire.OMPAdapter(), codebuddyhistory.Adapter(), opencodesqlite.Adapter())
	if err != nil {
		panic(err)
	}
	return r
}
func Production() *Registry                { return production }
func (r *Registry) All() []adapter.Adapter { return append([]adapter.Adapter(nil), r.adapters...) }
func (r *Registry) KnownSources() []string {
	ids := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		ids = append(ids, a.Source)
	}
	return ids
}
func (r *Registry) Lookup(source string) (adapter.Adapter, bool) {
	source = strings.TrimSpace(source)
	for _, a := range r.adapters {
		if a.Source == source {
			return a, true
		}
	}
	return adapter.Adapter{}, false
}
func (r *Registry) IsKnownSource(source string) bool { _, ok := r.Lookup(source); return ok }
func (r *Registry) LoadRecordsForSource(opt adapter.Options) (adapter.LoadResult, error) {
	a, ok := r.Lookup(opt.Source)
	if !ok {
		return adapter.LoadResult{}, fmt.Errorf("unsupported source %q", opt.Source)
	}
	return a.Load(opt)
}
func (r *Registry) ValidateCommit(source, stateDir string) error {
	a, ok := r.Lookup(source)
	if !ok {
		return fmt.Errorf("unsupported source %q", source)
	}
	if a.ValidateCommit == nil {
		return nil
	}
	return a.ValidateCommit(stateDir)
}
func All() []adapter.Adapter                       { return production.All() }
func KnownSources() []string                       { return production.KnownSources() }
func Lookup(source string) (adapter.Adapter, bool) { return production.Lookup(source) }
func IsKnownSource(source string) bool             { return production.IsKnownSource(source) }
func LoadRecordsForSource(opt adapter.Options) (adapter.LoadResult, error) {
	return production.LoadRecordsForSource(opt)
}
func ValidateCommit(source, stateDir string) error {
	return production.ValidateCommit(source, stateDir)
}
