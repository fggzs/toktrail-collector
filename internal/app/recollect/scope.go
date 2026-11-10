package recollect

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"toktrail-collector/internal/local/quarantine"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/adapter"
	"toktrail-collector/internal/syncclient"
)

// This file mirrors the consent-scope semantics that live unexported in
// internal/syncclient (reorg.go liveScopeFromSelf/evaluateRecord/fingerprint,
// sync.go checkNotPaused), the same way internal/app/resync does. recollect
// uses the mirror to PLAN the pre-scan (which records may enter the rebuilt
// batches at all) and to detect authorization drift between the plan and the
// reset/upload phases; the authoritative enforcement of every upload remains
// syncclient.Run's own fresh preflight and local scope gate, which re-checks
// the live consent on every POST. The mirror must stay in lockstep with those
// semantics: non-empty allowed-tools means membership, historyFrom is
// inclusive, uploadUntil is exclusive, and anything that cannot be evaluated
// is an error — unknown never becomes zero.

// pausedToolSentinel mirrors syncclient's paused marker in allowedTools.
const pausedToolSentinel = "__toktrail_paused__"

// devicePaused mirrors syncclient.checkNotPaused: only grant-protocol
// snapshots can pause; the explicit flag or the allowedTools sentinel both
// count. Old-protocol snapshots never pause.
func devicePaused(self syncclient.SelfStatus) bool {
	if self.GrantProtocolVersion == nil {
		return false
	}
	if self.Paused {
		return true
	}
	for _, tool := range self.AllowedTools {
		if strings.TrimSpace(tool) == pausedToolSentinel {
			return true
		}
	}
	return false
}

// liveScope mirrors syncclient's scope snapshot, always derived from a fresh
// GET /v1/devices/self, never from a rejected request, and never guessed.
type liveScope struct {
	revision     int64
	historyFrom  *time.Time
	uploadUntil  *time.Time
	allowedTools map[string]struct{}
}

// scopeFromSelf mirrors syncclient.liveScopeFromSelf plus the legacy
// never-widen adjustment of syncclient.preflightSelf: on old-protocol
// servers the bind-time cutoff stays authoritative. A missing or
// non-positive revision means the scope is unknown: fail closed, never
// treat unknown as unrestricted.
func scopeFromSelf(self syncclient.SelfStatus, st statedir.DeviceState) (liveScope, error) {
	if strings.TrimSpace(self.DeviceID) == "" || self.ConsentRevision <= 0 {
		return liveScope{}, fmt.Errorf("device self status does not report a valid consent revision (%d); the consent scope is unknown, so the force recollection fails closed before scanning or clearing anything", self.ConsentRevision)
	}
	if self.GrantProtocolVersion == nil && st.HistoryFrom != nil && !st.HistoryFrom.IsZero() {
		if self.HistoryFrom == nil || self.HistoryFrom.Before(*st.HistoryFrom) {
			hf := *st.HistoryFrom
			self.HistoryFrom = &hf
		}
	}
	scope := liveScope{revision: self.ConsentRevision, historyFrom: self.HistoryFrom, uploadUntil: self.UploadUntil}
	if len(self.AllowedTools) > 0 {
		scope.allowedTools = make(map[string]struct{}, len(self.AllowedTools))
		for _, tool := range self.AllowedTools {
			// The paused sentinel is handled by devicePaused before any
			// scope evaluation runs; filtering it here keeps the mirror
			// from treating it as a real tool name.
			if trimmed := strings.TrimSpace(tool); trimmed != "" && trimmed != pausedToolSentinel {
				scope.allowedTools[trimmed] = struct{}{}
			}
		}
	}
	return scope, nil
}

// evaluateRecord mirrors syncclient liveScope.evaluateRecord. The quarantine
// reason constants are reused verbatim so reports speak the same vocabulary
// as the pending-batch reorganization path. It works on the in-memory
// adapter.Record form the pre-scan filters (the same fields the raw-JSON
// mirror probes).
func (s liveScope) evaluateRecord(record adapter.Record) (bool, string, error) {
	key := strings.TrimSpace(adapter.StringField(record, "recordKey"))
	if key == "" {
		return false, "", errors.New("record has no recordKey; cannot evaluate it against the consent scope, failing closed")
	}
	occurredStr := strings.TrimSpace(adapter.StringField(record, "occurredAt"))
	if occurredStr == "" {
		return false, "", fmt.Errorf("record %s has no occurredAt; cannot evaluate it against the consent scope, failing closed", key)
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, occurredStr)
	if err != nil {
		return false, "", fmt.Errorf("record %s has unparseable occurredAt %q: %w", key, occurredStr, err)
	}
	if len(s.allowedTools) > 0 {
		if _, ok := s.allowedTools[adapter.StringField(record, "tool")]; !ok {
			return false, quarantine.ReasonToolNotAllowed, nil
		}
	}
	if s.historyFrom != nil && occurredAt.Before(*s.historyFrom) {
		return false, quarantine.ReasonBeforeHistoryFrom, nil
	}
	if s.uploadUntil != nil && !occurredAt.Before(*s.uploadUntil) {
		return false, quarantine.ReasonAfterUploadUntil, nil
	}
	return true, "", nil
}

// sortedTools renders the scope's allowed tools deterministically.
func (s liveScope) sortedTools() []string {
	tools := make([]string, 0, len(s.allowedTools))
	for tool := range s.allowedTools {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	return tools
}

// fingerprint mirrors syncclient liveScope.fingerprint: a deterministic
// rendering of the scope CONTENT (not the revision) so two snapshots with
// the same revision but different content never compare equal.
func (s liveScope) fingerprint() string {
	probe := struct {
		HistoryFrom  *time.Time `json:"historyFrom,omitempty"`
		UploadUntil  *time.Time `json:"uploadUntil,omitempty"`
		AllowedTools []string   `json:"allowedTools,omitempty"`
	}{s.historyFrom, s.uploadUntil, s.sortedTools()}
	b, err := json.Marshal(probe)
	if err != nil {
		return ""
	}
	return string(b)
}

// jobScope is the journal's durable record of the live consent scope the
// job's scan and reset decisions were made under. A resume that observes a
// different live scope adopts it (recorded durably) before proceeding; the
// CAS before the reset and every upload's own preflight enforce the live
// scope server-side regardless.
type jobScope struct {
	Revision     int64      `json:"revision"`
	Fingerprint  string     `json:"fingerprint"`
	HistoryFrom  *time.Time `json:"historyFrom,omitempty"`
	UploadUntil  *time.Time `json:"uploadUntil,omitempty"`
	AllowedTools []string   `json:"allowedTools,omitempty"`
}

// snapshotScope freezes the live scope into its durable journal form.
func snapshotScope(scope liveScope) *jobScope {
	return &jobScope{
		Revision:     scope.revision,
		Fingerprint:  scope.fingerprint(),
		HistoryFrom:  scope.historyFrom,
		UploadUntil:  scope.uploadUntil,
		AllowedTools: scope.sortedTools(),
	}
}

// matches reports whether the recorded baseline still equals the fresh live
// scope. The revision is the server's authoritative consent version (a
// consent change always bumps it), and the fingerprint comparison
// additionally fails closed when the scope content changed without a
// revision bump — the same never-guess rule syncclient applies to
// reorganizations.
func (s *jobScope) matches(scope liveScope) bool {
	if s == nil || s.Revision != scope.revision {
		return false
	}
	return s.Fingerprint == scope.fingerprint()
}

// describeScopeChange renders the divergence between a recorded baseline
// and a fresh live scope for stop messages.
func describeScopeChange(old *jobScope, fresh liveScope) string {
	renderTime := func(t *time.Time) string {
		if t == nil {
			return "(none)"
		}
		return t.UTC().Format(time.RFC3339)
	}
	renderTools := func(tools []string) string {
		if len(tools) == 0 {
			return "(any)"
		}
		return "[" + strings.Join(tools, ",") + "]"
	}
	if old == nil {
		return fmt.Sprintf("consent scope unrecorded -> revision %d", fresh.revision)
	}
	parts := []string{fmt.Sprintf("consent revision %d -> %d", old.Revision, fresh.revision)}
	if !sameTimePtr(old.HistoryFrom, fresh.historyFrom) {
		parts = append(parts, fmt.Sprintf("historyFrom %s -> %s", renderTime(old.HistoryFrom), renderTime(fresh.historyFrom)))
	}
	if !sameTimePtr(old.UploadUntil, fresh.uploadUntil) {
		parts = append(parts, fmt.Sprintf("uploadUntil %s -> %s", renderTime(old.UploadUntil), renderTime(fresh.uploadUntil)))
	}
	if !sameStrings(old.AllowedTools, fresh.sortedTools()) {
		parts = append(parts, fmt.Sprintf("allowedTools %s -> %s", renderTools(old.AllowedTools), renderTools(fresh.sortedTools())))
	}
	return strings.Join(parts, "; ")
}

func sameTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}
