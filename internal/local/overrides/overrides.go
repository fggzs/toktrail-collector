// Package overrides owns the authoritative current-scan baseline that an
// explicitly confirmed override pass (toktrail resync --all
// --replace-existing) persists for the codex-jsonl and deepseek-harness
// sources.
//
// The store is a single JSON ledger, <stateDir>/overrides.json, mapping a
// record key to the override state of that key:
//
//   - Record is the last content the server ACKNOWLEDGED for the key
//     (the server-known baseline). While a new override attempt is in
//     flight it is never discarded: a pending attempt that crashes, is
//     rejected, or is abandoned always leaves the previous confirmed
//     baseline intact.
//   - PendingRecord is the in-flight new content: the pass durably
//     decided to override the key but the server has not acknowledged it
//     yet. A key with a pending attempt blocks normal collection of its
//     source (the history filters fail closed) and is never treated as
//     authoritative by plain resync; only the override pass itself
//     retries it. On the acknowledgment the pending content is promoted
//     into Record; on a rejection it stays pending for the next explicit
//     pass.
//
// Confirmed content is the authoritative baseline for its key: the source
// history filters drop an identical fresh scan and fail closed on a new
// drift, and the plain resync retransmission substitutes it for the older
// archived payload (and includes ledger-only keys that no archived batch
// carries, so a later full restore cannot lose them).
//
// The ledger is override-owned state: nothing else writes it. Old batch
// files, outbox entries, per-message progress, cursors, and the
// quarantine store are never modified — the old payloads stay
// byte-identical on disk and are merely superseded for baseline
// comparisons.
//
// Every ledger with entries is bound to the device and server it was
// created for. Readers (the history filters, plain resync, and the
// override pass itself) verify that binding against the currently bound
// device before applying any entry: a collector bound differently must
// fail closed instead of mistaking another binding's acknowledgments for
// its own synced baseline.
package overrides

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
)

// fileName is the single override ledger file.
const fileName = "overrides.json"

// Schema is the current ledger format version.
const Schema = 1

// Entry statuses: an entry is pending while an override attempt is in
// flight (PendingRecord set), and confirmed once the server acknowledged
// its Record content.
const (
	StatusPending   = "pending"
	StatusConfirmed = "confirmed"

	CodexSource    = "codex-jsonl"
	DeepSeekSource = "deepseek-harness"
)

// overrideSources is the closed set of sources the override pass covers.
// Other sources are excluded by design and never enter the ledger.
var overrideSources = map[string]bool{
	CodexSource:    true,
	DeepSeekSource: true,
}

// OverrideSources returns the closed set of sources the override ledger
// may carry, in stable order.
func OverrideSources() []string { return []string{CodexSource, DeepSeekSource} }

// IsOverrideSource reports whether a source participates in the override
// protocol.
func IsOverrideSource(source string) bool { return overrideSources[source] }

// Entry is the override state of one record key.
type Entry struct {
	RecordKey string `json:"recordKey"`
	Source    string `json:"source"`
	Input     string `json:"input,omitempty"`
	// Record is the last server-acknowledged content for the key
	// (canonical compact JSON). It is empty only for a first-time
	// override attempt of a key the server has never acknowledged.
	Record json.RawMessage `json:"record,omitempty"`
	// AttemptID is the persistent id of the attempt whose acknowledgment
	// produced Record (the content's generation). It is kept while the
	// entry stays confirmed so later retransmissions of this key derive
	// distinct batch identities per generation — a content sequence
	// A→B→A can never replay the first A's server receipt.
	AttemptID string `json:"attemptId,omitempty"`
	// Status is pending while PendingRecord is set, confirmed otherwise.
	Status string `json:"status"`
	// PendingRecord is the in-flight override content (canonical compact
	// JSON); set only while status is pending.
	PendingRecord json.RawMessage `json:"pendingRecord,omitempty"`
	// PendingAttemptID is the persistent unique id of the in-flight
	// attempt. It is generated when the attempt is decided, persisted
	// with it, reused by every retry of that attempt, and folded into
	// the upload batch identity: without it, a content sequence A→B→A
	// would derive the same batch id as the first A and wrongly replay
	// that old receipt instead of re-applying A over B.
	PendingAttemptID string `json:"pendingAttemptId,omitempty"`
	// PendingSince stamps the current attempt.
	PendingSince *time.Time `json:"pendingSince,omitempty"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

// Ledger is the whole override store.
type Ledger struct {
	Schema    int    `json:"schema"`
	DeviceID  string `json:"deviceId,omitempty"`
	ServerURL string `json:"serverUrl,omitempty"`
	DataEpoch int64  `json:"dataEpoch,omitempty"`
	// Entries maps record key -> override state.
	Entries map[string]Entry `json:"entries"`
}

// Store reads and writes the ledger under one state directory.
type Store struct{ dir string }

// New returns the store for a state directory.
func New(stateDir string) Store { return Store{dir: strings.TrimSpace(stateDir)} }

// Path is the ledger file location.
func (s Store) Path() string { return filepath.Join(s.dir, fileName) }

// Load reads the ledger. A missing file is an empty ledger (false, nil).
// A corrupt file, a foreign schema, or an entry that violates the
// override invariants is a hard error: the override state is unknown, so
// callers must fail closed instead of guessing. Removing the file is the
// explicit user action to abandon an override.
func (s Store) Load() (Ledger, bool, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Ledger{}, false, nil
	}
	if err != nil {
		return Ledger{}, false, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return Ledger{}, false, fmt.Errorf("corrupt %s: %w; failing closed (remove the file only if you accept abandoning the override state)", s.Path(), err)
	}
	if err := l.Validate(); err != nil {
		return Ledger{}, false, err
	}
	return l, true, nil
}

// Save validates and atomically persists the ledger (tmp + rename, 0600,
// private directory). It is called before the first override upload and
// after every acknowledged batch, so a crash at any point leaves a state
// the next override pass can resume: pending attempts are retried, and
// the previously acknowledged baselines are never lost.
func (s Store) Save(l Ledger) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if s.dir == "" {
		return errors.New("override store requires a state directory")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// Compact, not indented: MarshalIndent would re-indent the embedded
	// RawMessage record bodies, and the canonical-form invariant requires
	// the stored bytes to equal their own canonical form.
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

// Validate enforces the ledger invariants: schema, closed source set,
// per-entry key identity, status/content pairing, record canonicality,
// and the device/server binding whenever entries exist.
func (l Ledger) Validate() error {
	if l.DataEpoch < 0 {
		return errors.New("corrupt override ledger: invalid data epoch")
	}
	if l.Schema != Schema {
		return fmt.Errorf("corrupt override ledger: unsupported schema %d", l.Schema)
	}
	if l.Entries == nil {
		return fmt.Errorf("corrupt override ledger: missing entries map")
	}
	if len(l.Entries) == 0 {
		return nil
	}
	if strings.TrimSpace(l.DeviceID) == "" || strings.TrimSpace(l.ServerURL) == "" {
		return fmt.Errorf("corrupt override ledger: entries exist but the device or server binding is missing")
	}
	for key, e := range l.Entries {
		if e.RecordKey == "" || e.RecordKey != key {
			return fmt.Errorf("corrupt override ledger: entry key %q does not match its map key %q", e.RecordKey, key)
		}
		if !IsOverrideSource(e.Source) {
			return fmt.Errorf("corrupt override ledger: record %s carries unsupported source %q", key, e.Source)
		}
		if e.UpdatedAt.IsZero() {
			return fmt.Errorf("corrupt override ledger: record %s has no updatedAt", key)
		}
		switch e.Status {
		case StatusPending:
			if len(e.PendingRecord) == 0 {
				return fmt.Errorf("corrupt override ledger: pending record %s has no pending content", key)
			}
			if strings.TrimSpace(e.PendingAttemptID) == "" {
				return fmt.Errorf("corrupt override ledger: pending record %s has no attempt id", key)
			}
			if err := checkCanonical(e.PendingRecord, key); err != nil {
				return err
			}
			if e.PendingSince == nil || e.PendingSince.IsZero() {
				return fmt.Errorf("corrupt override ledger: pending record %s has no pendingSince", key)
			}
		case StatusConfirmed:
			if len(e.PendingRecord) != 0 {
				return fmt.Errorf("corrupt override ledger: confirmed record %s still carries pending content", key)
			}
			if len(e.Record) == 0 {
				return fmt.Errorf("corrupt override ledger: confirmed record %s has no acknowledged content", key)
			}
			if strings.TrimSpace(e.AttemptID) == "" {
				return fmt.Errorf("corrupt override ledger: confirmed record %s has no attempt id", key)
			}
			if err := checkCanonical(e.Record, key); err != nil {
				return err
			}
		default:
			return fmt.Errorf("corrupt override ledger: record %s has unknown status %q", key, e.Status)
		}
		if len(e.Record) > 0 {
			if err := checkCanonical(e.Record, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkCanonical(raw json.RawMessage, key string) error {
	canonical, err := Canonical(raw)
	if err != nil {
		return fmt.Errorf("corrupt override ledger: record %s is not valid JSON: %w", key, err)
	}
	if !bytes.Equal(canonical, raw) {
		return fmt.Errorf("corrupt override ledger: record %s is not stored in canonical form", key)
	}
	var probe struct {
		RecordKey string `json:"recordKey"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.RecordKey != key {
		return fmt.Errorf("corrupt override ledger: record %s does not carry its own recordKey", key)
	}
	return nil
}

// Confirmed returns the confirmed (server-acknowledged) entry for a key;
// an entry whose attempt is still pending is not confirmed.
func (l Ledger) Confirmed(key string) (Entry, bool) {
	e, ok := l.Entries[key]
	if !ok || e.Status != StatusConfirmed {
		return Entry{}, false
	}
	return e, true
}

// Pending returns the pending entry for a key.
func (l Ledger) Pending(key string) (Entry, bool) {
	e, ok := l.Entries[key]
	if !ok || e.Status != StatusPending {
		return Entry{}, false
	}
	return e, true
}

// PendingForSource lists the pending keys of one source.
func (l Ledger) PendingForSource(source string) []string {
	keys := make([]string, 0)
	for key, e := range l.Entries {
		if e.Status == StatusPending && e.Source == source {
			keys = append(keys, key)
		}
	}
	return keys
}

// HasPending reports whether any override attempt is in flight.
func (l Ledger) HasPending() bool {
	for _, e := range l.Entries {
		if e.Status == StatusPending {
			return true
		}
	}
	return false
}

// BindingError verifies that a ledger with entries belongs to the device
// currently bound in the state directory (and the server that device is
// bound to, defaulting like the sync path). A collector bound differently
// must not apply another binding's acknowledgments as its own synced
// baseline: that would silently skip uploads after a re-bind.
func (l Ledger) BindingError(stateDir string) error {
	if len(l.Entries) == 0 {
		return nil
	}
	st, err := statedir.New(stateDir).Load()
	if err != nil {
		return err
	}
	if st.DataEpoch != l.DataEpoch {
		return errors.New("override ledger belongs to another data epoch; old baselines cannot be promoted after recollection")
	}
	if st.DeviceID == "" {
		return fmt.Errorf("the override ledger belongs to device %s, but this collector is not bound; the override baseline is device-bound — bind the device or remove the override ledger only if you accept abandoning it", l.DeviceID)
	}
	if st.DeviceID != l.DeviceID {
		return fmt.Errorf("the override ledger belongs to device %s, but this collector is bound as %s; the override baseline is device-bound — use a separate state directory, or remove the ledger only if you accept abandoning it", l.DeviceID, st.DeviceID)
	}
	bound := strings.TrimRight(strings.TrimSpace(st.ServerURL), "/")
	if bound == "" {
		bound = "http://127.0.0.1:3211"
	}
	if bound != l.ServerURL {
		return fmt.Errorf("the override ledger targets server %s, but this collector is bound to %s; re-bind against the recorded server, or remove the ledger only if you accept abandoning it", l.ServerURL, bound)
	}
	return nil
}

// Canonical returns the canonical compact JSON for a raw record: the
// record is decoded with UseNumber (so large integers keep their exact
// literal) and re-marshaled, which sorts object keys and drops formatting.
// This is the same canonicalization the source history filters use, so
// ledger content, stored batch content, and fresh scan content all
// compare bytewise.
func Canonical(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty record")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errors.New("record is null")
	}
	return json.Marshal(rec)
}

// CanonicalRecord canonicalizes a decoded record map (as produced by the
// source adapters, which decode with UseNumber).
func CanonicalRecord(rec map[string]any) ([]byte, error) {
	if rec == nil {
		return nil, errors.New("record is nil")
	}
	return json.Marshal(rec)
}

// ApplyToBaseline folds the override ledger into one source's known-key
// baseline without a cancellation scope. It is the legacy entry point and
// behaves exactly like ApplyToBaselineContext(context.Background(), ...),
// so pre-context callers keep their historical uncancellable behavior.
func ApplyToBaseline(stateDir, source string, known map[string][]byte) error {
	return ApplyToBaselineContext(context.Background(), stateDir, source, known)
}

// ApplyToBaselineContext folds the override ledger into one source's
// known-key baseline (the canonical content map the source history
// filters build from the outbox and quarantine store):
//
//   - The ledger's device/server binding is verified against the
//     currently bound device first; a mismatch fails closed instead of
//     misjudging another binding's acknowledgments as already-synced.
//   - Any pending attempt of this source blocks the whole scan
//     fail-closed: an override was durably decided but not yet
//     acknowledged, so normal collection must neither re-export the
//     superseded payload nor treat the unconfirmed attempt as
//     authoritative. The message tells the user to finish or abandon the
//     override pass.
//   - Confirmed entries supersede the stored payload for their key: the
//     baseline becomes the acknowledged override content, so an identical
//     fresh scan drops (already authoritative and acknowledged) and a new
//     drift fails closed instead of silently overwriting history. The
//     old stored payloads are not modified on disk.
//
// Cancellation: the scope is checked at entry and once per ledger record
// in both per-record scans (the pending-source scan and the
// confirmed-entry scan). The single-file ledger load and the binding
// check stay non-interruptible at their file boundaries — they either
// run to completion or never start. Supersessions are staged in a
// private map and applied to known in one shot only after every record
// has passed its check, so a cancelled pass returns ctx.Err()
// (matchable with errors.Is(err, context.Canceled) or errors.Is(err,
// context.DeadlineExceeded)) and leaves the caller's known map exactly
// as it was. Nothing here writes the ledger or any other persistent
// state.
//
// A missing ledger is a no-op. A corrupt ledger fails closed through
// Load.
func ApplyToBaselineContext(ctx context.Context, stateDir, source string, known map[string][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store := New(stateDir)
	ledger, has, err := store.Load()
	if err != nil {
		return err
	}
	if !has {
		return nil
	}
	if err := ledger.BindingError(stateDir); err != nil {
		return err
	}
	// Pending scan: count this source's in-flight attempts record by
	// record, honoring the scope at each step, so a pass cancelled
	// mid-scan fails with the scope error instead of running the whole
	// ledger.
	pending := 0
	for _, e := range ledger.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Status == StatusPending && e.Source == source {
			pending++
		}
	}
	if pending > 0 {
		return fmt.Errorf("an override pass is incomplete for source %s: %d record(s) are pending acknowledgment and block normal collection; re-run toktrail resync --all --replace-existing to finish the repair, or remove %s only if you accept abandoning the override", source, pending, store.Path())
	}
	// Confirmed entries supersede the stored payloads, but only in one
	// shot: stage every canonical record first so a cancellation (or a
	// corrupt record) anywhere in the scan leaves the caller's known map
	// untouched instead of half-applied.
	staged := make(map[string][]byte, len(ledger.Entries))
	for key, entry := range ledger.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Source != source || entry.Status != StatusConfirmed {
			continue
		}
		canonical, err := Canonical(entry.Record)
		if err != nil {
			return fmt.Errorf("override ledger record %s is not valid JSON: %w", key, err)
		}
		staged[key] = canonical
	}
	for key, canonical := range staged {
		known[key] = canonical
	}
	return nil
}
