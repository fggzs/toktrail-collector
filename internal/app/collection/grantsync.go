package collection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/managedconsent"
	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/source/registry"
	synccmd "toktrail-collector/internal/syncclient"
)

// maxGrantSyncCycles bounds the fetch→apply→ack loop when the server's
// consent revision keeps advancing during the sync. Reading never continues
// under a revision the server has already moved past.
const maxGrantSyncCycles = 2

// GrantSync reports what the server-driven grant sync did in one run.
// It is display/accounting state only; the applied policy governs reading.
type GrantSync struct {
	// Active is true when the grant protocol governed this run (a fresh
	// view was fetched and applied).
	Active bool
	// Paused is the applied server pause state.
	Paused bool
	// ConsentRevision is the applied revision.
	ConsentRevision int64
	// AllowedTools mirrors the applied raw server tool list.
	AllowedTools []string
	// Refreshed is true when a fresh view was applied this run.
	Refreshed bool
	// Acked is true when the server confirmed the applied revision via
	// grant-ack (never true while application is restricted).
	Acked bool
	// AddedGrants lists managed default-path grants added this run
	// ("source input").
	AddedGrants []string
	// Pending maps an allowed tool to the reason it could not be fully
	// applied locally. While non-empty the revision is not acknowledged.
	Pending map[string]string
	// Note carries non-fatal diagnostics (old protocol, ack retry, ...).
	Note string
}

// syncGrants performs the server-driven grant authorization sync. It must
// run before any local scanning and under the collector runlock (Run
// guarantees both). The device's own credentials fetch the authoritative
// view; the collector never re-runs connect or bind and never changes the
// device identity, progress, or outbox.
//
// Fail-closed rules (contraction safety):
//   - terminal conditions stop local reading unconditionally, even on first
//     contact: a revoked or deleted device, rejected credentials (401/403),
//     a self view naming a different device, or a structurally invalid
//     self response;
//   - after the grant protocol has been seen, any refresh failure or an
//     old-protocol response (anti-downgrade) stops local reading — the
//     cached overlay authorizes nothing;
//   - a server that never spoke the protocol keeps the legacy behavior,
//     including transport-level failures (documented compatibility: reading
//     continues under local grants and the drain reports the failure);
//   - a revision that keeps advancing during the sync stops the run rather
//     than reading under a stale revision.
//
// The ack is sent only after the view is durably applied and the managed
// grant merge completed; fully applied revisions ack as
// applyState=applied, restricted ones (unknown tool, missing default
// directory, manually disabled grant) ack as applyState=pending so the
// server UI never keeps claiming a full application that no longer holds.
// The ack also carries the collector's capability report — the registered
// supportedTools list and one closed-code pendingReason per restricted
// tool (names and codes only, never local paths). An older server that
// rejects those unknown fields is re-acked once with the legacy payload;
// that fallback is recorded as "capabilities NOT reported" so it is never
// claimed as delivered and is retried on the next run. The same revision
// is re-acked whenever the applied state, collector version, or the
// capability/reason payload changes; an old revision's ack never stands
// in for a newer one. Ack failures are non-fatal and retried on the next
// run.
func syncGrants(ctx context.Context, opt Options, stateDir string, grantStore grants.Store, now func() time.Time) (GrantSync, managedconsent.Policy, error) {
	info := GrantSync{}
	store := statedir.New(stateDir)
	mcStore := managedconsent.New(stateDir)

	st, err := store.Load()
	if err != nil {
		return info, managedconsent.Policy{}, err
	}
	unbound := st.DeviceID == "" || st.DeviceSecret == ""
	if _, seen, err := mcStore.Load(); err != nil {
		return info, managedconsent.Policy{}, err
	} else if unbound {
		if seen {
			return info, managedconsent.Policy{}, errors.New("device is not bound but a server grant view was previously applied; refusing to read under an unconfirmable authorization (re-bind the device or resolve the state directory)")
		}
		// Never spoke the protocol and cannot ask the server: legacy
		// local-grant behavior, zero network.
		info.Note = "device is not bound; server grant sync skipped"
		return info, managedconsent.Policy{}, nil
	}

	// The capability list reported with every ack: the tool names actually
	// registered in this collector build (canonical registry names only,
	// sorted, never local paths). Computed once per run — the compiled-in
	// registry cannot change mid-run — and used both on the wire and as
	// part of the ack cache key.
	supportedTools := ackSupportedTools()

	var lastOverlay managedconsent.Overlay
	for cycle := 0; cycle < maxGrantSyncCycles; cycle++ {
		// Durable authorization-attempt accounting precedes every
		// authenticated self GET, mirroring the sync preflight.
		if _, err := outbox.New(stateDir).RecordPreflightAttempt(now().UTC()); err != nil {
			return info, managedconsent.Policy{}, fmt.Errorf("cannot persist grant-sync attempt accounting; no HTTP request was made: %w", err)
		}
		self, err := synccmd.FetchDeviceSelf(ctx, store, synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient})
		if err != nil {
			// Terminal conditions stop local reading unconditionally —
			// even when the grant protocol was never seen. A device the
			// server revoked or deleted, credentials the server rejects
			// (401/403), a self view naming a different device, or a
			// structurally invalid response are never treated as a
			// transient network failure to fall back from.
			if errors.Is(err, synccmd.ErrDeviceRevoked) || errors.Is(err, synccmd.ErrSubjectDeleted) ||
				errors.Is(err, synccmd.ErrDeviceUnauthorized) || errors.Is(err, synccmd.ErrSelfProtocol) {
				return info, managedconsent.Policy{}, err
			}
			_, seen, lerr := mcStore.Load()
			if lerr != nil {
				return info, managedconsent.Policy{}, lerr
			}
			if seen {
				return info, managedconsent.Policy{}, fmt.Errorf("cannot refresh the server grant authorization (the grant protocol was previously active); local reading is stopped until the next successful refresh: %w", err)
			}
			// Transport-level failure on a server that never spoke the
			// grant protocol: documented legacy-compatible behavior —
			// reading continues under the local grants and the drain
			// reports the same network failure.
			info.Note = fmt.Sprintf("server grant sync unavailable, keeping legacy local-grant behavior: %v", err)
			return info, managedconsent.Policy{}, nil
		}

		// Data-epoch fence, BEFORE any grant write, scan or export: a
		// server whose epoch for this device no longer matches the
		// locally locked epoch means a usage reset happened that this
		// device has not been force-recollected through. The round stops
		// here so no source is read (baselines must not advance under
		// the old epoch), no batch is exported, and no server-derived
		// grant view is applied until the reset flow completes. The
		// local epoch is never advanced from this snapshot.
		if err := synccmd.CheckSelfDataEpoch(self, st.DataEpoch); err != nil {
			return info, managedconsent.Policy{}, err
		}

		if self.GrantProtocolVersion == nil {
			_, seen, lerr := mcStore.Load()
			if lerr != nil {
				return info, managedconsent.Policy{}, lerr
			}
			if seen {
				return info, managedconsent.Policy{}, errors.New("server no longer advertises the grant protocol after it was previously active (possible downgrade); local reading is stopped until the server advertises grantProtocolVersion again")
			}
			info.Note = "server does not advertise the grant protocol; keeping legacy local-grant behavior"
			return info, managedconsent.Policy{}, nil
		}
		if *self.GrantProtocolVersion != managedconsent.SchemaVersion {
			return info, managedconsent.Policy{}, fmt.Errorf("server advertises unsupported grant protocol version %d (this collector supports %d); local reading is stopped - upgrade the collector", *self.GrantProtocolVersion, managedconsent.SchemaVersion)
		}

		view, omittedManaged, err := viewFromSelf(self)
		if err != nil {
			return info, managedconsent.Policy{}, fmt.Errorf("invalid server grant view: %w", err)
		}

		// Controlled merge first: its outcome decides whether a previous
		// ack may be carried forward. A restricted (pending) application
		// never inherits the "applied" marker.
		prev, seen, lerr := mcStore.Load()
		if lerr != nil {
			return info, managedconsent.Policy{}, lerr
		}
		// Identity binding: an overlay recorded for a different device or
		// server is never reused — its ack is dropped and the managed
		// grants it added are disabled so no grant crosses devices.
		identityMatch := seen && prev.DeviceID == st.DeviceID &&
			normalizeServerURL(prev.ServerURL) == normalizeServerURL(resolveServerURL(opt.ServerURL, st))
		if seen && !identityMatch {
			if n, derr := grantStore.DisableManaged(); derr != nil {
				return info, managedconsent.Policy{}, fmt.Errorf("disable managed grants after a device identity change: %w", derr)
			} else if n > 0 {
				info.Note = fmt.Sprintf("device identity changed; disabled %d managed grant(s) from the previous device", n)
			}
			seen = false
			prev = managedconsent.Overlay{}
		}
		var added []string
		var pending map[string]string
		if view.DeviceGrantManaged {
			added, pending, err = mergeManagedGrants(grantStore, view, homeDirOrDefault(opt.HomeDir), opt.probeDefaultInput)
			if err != nil {
				return info, managedconsent.Policy{}, err
			}
		}
		// Unmanaged devices (explicit false, or the server omitted the
		// flag) never gain grants: the sync only filters existing local
		// grants, which always fully applies.
		if omittedManaged && info.Note == "" {
			info.Note = "server did not state deviceGrantManaged; treating the device as unmanaged (no automatic grants)"
		}

		// The collector version sent with the ack: only a strict SemVer
		// release string is ever claimed; dev/unknown builds omit it.
		effectiveVersion := strings.TrimSpace(opt.CollectorVersion)
		if !synccmd.ValidCollectorVersion(effectiveVersion) {
			effectiveVersion = ""
		}

		overlay := managedconsent.Overlay{
			SchemaVersion:      managedconsent.SchemaVersion,
			ConsentRevision:    view.ConsentRevision,
			Paused:             view.Paused,
			AllowedTools:       view.AllowedTools,
			HistoryFrom:        view.HistoryFrom,
			AppliedAt:          now().UTC(),
			Pending:            pending,
			DeviceGrantManaged: view.DeviceGrantManaged,
			DeviceID:           st.DeviceID,
			ServerURL:          resolveServerURL(opt.ServerURL, st),
		}
		// The applied state reported with the ack: "applied" when every
		// allowed tool is executable, "pending" while a restriction holds.
		// A restricted revision is still acknowledged — with its
		// restrictions stated — so an earlier full ack cannot keep the UI
		// claiming "applied".
		applyState := "applied"
		if len(pending) > 0 {
			applyState = "pending"
		}
		// The capability payload reported with the ack: the registered
		// supported-tools list plus one closed-code reason per restricted
		// tool (names and codes only, never local paths). It is part of
		// the ack cache key below, so a changed capability or reason
		// payload re-acks the SAME revision. A restriction whose reason
		// maps to no closed code is never given a fabricated one: the
		// whole pendingReasons field is then omitted (the server reads
		// "reasons unknown") while supportedTools still travels.
		pendingReasons, unmappedReasons := ackPendingReasons(pending)
		reasonsIncomplete := len(unmappedReasons) > 0
		note := ""
		if omittedManaged {
			note = "server did not state deviceGrantManaged; treating the device as unmanaged (no automatic grants)"
		}
		if reasonsIncomplete {
			unmappedNote := fmt.Sprintf("pending reason for %s has no closed grant-ack code and was not reported to the server", strings.Join(unmappedReasons, ", "))
			if note == "" {
				note = unmappedNote
			} else {
				note = note + "; " + unmappedNote
			}
		}
		ackUpToDate := false
		if seen && ackedPayloadCurrent(prev, view.ConsentRevision, applyState, effectiveVersion, supportedTools, pendingReasons, reasonsIncomplete) {
			overlay.AckedRevision, overlay.AckedAt, overlay.AckedCollectorVersion, overlay.AckedApplyState =
				prev.AckedRevision, prev.AckedAt, prev.AckedCollectorVersion, prev.AckedApplyState
			overlay.AckedSupportedTools = prev.AckedSupportedTools
			overlay.AckedPendingReasons = prev.AckedPendingReasons
			overlay.AckedReasonsIncomplete = prev.AckedReasonsIncomplete
			ackUpToDate = true
		}
		if err := mcStore.Save(overlay); err != nil {
			return info, managedconsent.Policy{}, fmt.Errorf("persist server grant view: %w", err)
		}
		lastOverlay = overlay

		info = GrantSync{
			Active:          true,
			Paused:          view.Paused,
			ConsentRevision: view.ConsentRevision,
			AllowedTools:    view.AllowedTools,
			Refreshed:       true,
			AddedGrants:     added,
			Pending:         pending,
			Note:            note,
		}

		// Ack after the view is durably applied and the grant merge
		// completed: fully applied revisions ack as applyState=applied,
		// restricted ones (unknown tool, missing default directory,
		// manually disabled grant) ack as applyState=pending so the server
		// UI never keeps claiming a full application that no longer holds.
		// The ack carries the capability report (supportedTools plus
		// pendingReasons; [] explicitly when nothing is restricted). The
		// same revision is re-acked when the applied state, the collector
		// version, or the capability/reason payload changed; an old
		// revision's ack never stands in for a newer one.
		if !ackUpToDate {
			ackReq := ackRequestFor(view.ConsentRevision, applyState, effectiveVersion, supportedTools, pendingReasons, reasonsIncomplete)
			ack, ackErr := synccmd.ReportGrantAck(ctx, store, synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient}, ackReq)
			capabilitiesConfirmed := ackErr == nil
			legacyFallback := false
			if ackErr != nil && errors.Is(ackErr, synccmd.ErrAckUnknownFields) {
				// The server rejected the payload while it carried the
				// optional capability fields — an older server refusing
				// unknown JSON fields. Retry ONCE with the legacy payload
				// shape (byte-identical to the pre-capability protocol).
				// Only a SUCCESSFUL legacy retry counts as a downgrade:
				// the capability report is then explicitly NOT recorded as
				// delivered (never faked) and is retried on the next run.
				// If the legacy payload fails too, the error below
				// surfaces it like any ordinary ack failure.
				legacyReq := ackReq
				legacyReq.SupportedTools, legacyReq.PendingReasons = nil, nil
				ack, ackErr = synccmd.ReportGrantAck(ctx, store, synccmd.Options{StateDir: stateDir, ServerURL: opt.ServerURL, HTTPClient: opt.HTTPClient}, legacyReq)
				capabilitiesConfirmed = false
				legacyFallback = ackErr == nil
				if ackErr != nil {
					// Keep the original capability-fields rejection
					// visible when the legacy retry fails too.
					ackErr = fmt.Errorf("legacy grant-ack retry after the capability-fields rejection failed as well: %w", ackErr)
				}
			}
			if ackErr != nil {
				if errors.Is(ackErr, synccmd.ErrAckRevisionAdvanced) {
					// The server moved past the applied revision: never
					// read under the stale view. Bounded re-fetch, and a
					// conservative stop at the cycle limit.
					if cycle == maxGrantSyncCycles-1 {
						return info, managedconsent.Policy{}, fmt.Errorf("server consent revision advanced during the grant sync (%v); local reading is stopped for this run to avoid reading under a stale revision", ackErr)
					}
					continue
				}
				if errors.Is(ackErr, synccmd.ErrAckEchoMismatch) {
					// The server confirmed an unexpected revision or
					// state: the bookkeeping is unclear, stop reading.
					return info, managedconsent.Policy{}, fmt.Errorf("grant ack state is unclear, stopping local reading for this run: %w", ackErr)
				}
				// Ordinary ack failure (network, endpoint absent, server
				// error): the freshly fetched view remains this run's
				// authorization — the fetch, not the receipt, authorizes
				// reading, and the server still enforces the revision at
				// ingest. Reading continues; the ack retries next run.
				info.Note = fmt.Sprintf("grant ack not confirmed (retried on the next run): %v", ackErr)
				break
			}
			ackedAt := ack.AckedAt
			if ackedAt.IsZero() {
				ackedAt = now().UTC()
			}
			overlay.AckedRevision = view.ConsentRevision
			overlay.AckedApplyState = applyState
			overlay.AckedCollectorVersion = effectiveVersion
			// The cached ack records the capability payload that was
			// actually confirmed: the full lists when the capability
			// request succeeded, nothing after a legacy fallback (or for
			// pre-capability collectors) so the report is never claimed
			// as delivered and the next run re-attempts it. An
			// incomplete reason report is cached as such — the wire
			// omitted pendingReasons — never as a complete receipt.
			overlay.AckedSupportedTools = nil
			overlay.AckedPendingReasons = nil
			overlay.AckedReasonsIncomplete = false
			if capabilitiesConfirmed {
				overlay.AckedSupportedTools = supportedTools
				overlay.AckedReasonsIncomplete = reasonsIncomplete
				if !reasonsIncomplete {
					overlay.AckedPendingReasons = pendingReasons
				}
			}
			overlay.AckedAt = &ackedAt
			if err := mcStore.Save(overlay); err != nil {
				return info, managedconsent.Policy{}, fmt.Errorf("persist grant ack: %w", err)
			}
			lastOverlay = overlay
			info.Acked = true
			if legacyFallback {
				// The revision receipt is confirmed, but the capability
				// report was not delivered — surface it, never silently.
				downgradeNote := "server rejected the grant-ack supportedTools/pendingReasons fields (older server); acknowledged with the legacy payload and the capability report will be retried on the next run"
				if info.Note == "" {
					info.Note = downgradeNote
				} else {
					info.Note = info.Note + "; " + downgradeNote
				}
			}
			if ack.CurrentConsentRevision > view.ConsentRevision {
				// The server moved on: never read under the stale
				// revision. Re-fetch and re-apply once more.
				if cycle == maxGrantSyncCycles-1 {
					return info, managedconsent.Policy{}, fmt.Errorf("server consent revision keeps advancing (applied %d, server at %d); local reading is stopped for this run to avoid reading under a stale revision", view.ConsentRevision, ack.CurrentConsentRevision)
				}
				continue
			}
		} else {
			info.Acked = true
		}
		break
	}

	return info, lastOverlay.Policy(), nil
}

// viewFromSelf maps a fetched self snapshot onto the grant view. The pause
// signal is honored from the explicit flag or the allowedTools sentinel.
// DeviceGrantManaged defaults to false: only a present-and-true server flag
// permits automatic grants, so a missing field (or an unconfirmed legacy
// device) means filter-only. The second return value reports whether the
// server omitted the field entirely under the new protocol.
func viewFromSelf(self synccmd.SelfStatus) (managedconsent.View, bool, error) {
	v := managedconsent.View{
		ConsentRevision: self.ConsentRevision,
		Paused:          self.Paused,
		AllowedTools:    self.AllowedTools,
		HistoryFrom:     self.HistoryFrom,
	}
	if self.DeviceGrantManaged != nil {
		v.DeviceGrantManaged = *self.DeviceGrantManaged
	}
	omittedManaged := self.DeviceGrantManaged == nil
	for _, tool := range self.AllowedTools {
		if strings.TrimSpace(tool) == managedconsent.PausedToolSentinel {
			v.Paused = true
		}
	}
	if err := managedconsent.ValidateView(v); err != nil {
		return managedconsent.View{}, false, err
	}
	return v, omittedManaged, nil
}

// mergeManagedGrants performs the controlled merge for the allowed tools:
// for every allowed tool known to the compiled-in registry, the built-in
// default-directory grant is added when no grant exists for that exact
// (source, input) pair and the directory is present. Existing entries are
// never modified, disabled entries are never silently restarted, unknown
// tool names never become grants, and the server never supplies a path.
// Tools that cannot be fully applied are reported as pending with a clear
// reason so the revision is not acknowledged as applied.
//
// probeDefaultInput overrides the per-tool default-directory probe for
// in-package tests (nil probes the real filesystem via
// defaultInputMissing); see Options.probeDefaultInput.
func mergeManagedGrants(grantStore grants.Store, view managedconsent.View, homeDir string, probeDefaultInput func(string) (bool, error)) ([]string, map[string]string, error) {
	var tools []string
	for _, tool := range view.AllowedTools {
		if strings.TrimSpace(tool) != managedconsent.PausedToolSentinel {
			tools = append(tools, tool)
		}
	}
	if view.Paused || len(tools) == 0 {
		// Paused, or the legacy "unrestricted" empty list: no tool was
		// explicitly confirmed, so nothing is added and nothing is
		// restricted.
		return nil, nil, nil
	}
	cfg, err := grantStore.Load()
	if err != nil {
		return nil, nil, err
	}
	var added []string
	pending := map[string]string{}
	// The default-directory probe, resolved once before the loop: the
	// real filesystem probe unless an in-package test injected a
	// deterministic override (see Options.probeDefaultInput).
	probe := defaultInputMissing
	if probeDefaultInput != nil {
		probe = probeDefaultInput
	}
	for _, tool := range tools {
		spec, ok := registry.LookupTool(tool)
		if !ok {
			pending[tool] = "unknown tool: not supported by this collector version"
			continue
		}
		if spec.IsAccountNetwork() {
			// Account-network tools (Cursor) are never auto-granted: their
			// local permit requires an explicit first-time confirmation
			// (connect or `toktrail cursor enable`) that an unattended sync
			// must not complete by itself, and their server-side state
			// travels on self.accountSources instead of the tool-grant
			// channel. They are also never "pending" here: the account
			// source state governs them.
			continue
		}
		candidates := spec.DefaultInputCandidates(homeDir)
		// def starts as the FIRST probed layout, not ResolveDefaultInput:
		// for CodeBuddy the registry probes its POSIX/XDG directory before
		// the Windows home-relative default, and a "not found" reason that
		// named the Windows path sent Linux users looking at a directory
		// that cannot exist on their host. candidates[0] equals
		// ResolveDefaultInput for every other tool, so their reasons and
		// grants are unchanged.
		def := spec.ResolveDefaultInput(homeDir)
		if len(candidates) > 0 {
			def = candidates[0]
		}
		// A managed default grant this sync created earlier stays the
		// tool's default layout even when the current environment no
		// longer proposes its path: XDG_DATA_HOME set in the interactive
		// shell but absent from the scheduled task changes the candidate
		// list, and answering that change by adding a second default
		// elsewhere would re-enable collection the user had manually
		// disabled at the old path (or leave two enabled default layouts
		// for one source). Migrating the default to another directory is
		// an explicit user operation.
		if managed, found := managedDefaultGrant(cfg, spec.Source); found {
			if managed.Enabled {
				continue
			}
			if managed.SystemDisabled {
				// The sync itself disabled this grant (device identity
				// change): the new device's explicit authorization for
				// the same tool restores it. A user's manual disable is
				// never restarted here.
				restored, err := grantStore.EnableManagedGrant(spec.Source, managed.Input)
				if err != nil {
					return nil, nil, fmt.Errorf("restore system-disabled grant for tool %q: %w", tool, err)
				}
				if restored {
					added = append(added, managed.Source+" "+managed.Input+" (restored after device change)")
				}
				continue
			}
			pending[tool] = "default-directory grant is manually disabled; re-enable it (toktrail sources enable) to resume collection"
			continue
		}
		// No managed default exists yet: keep an existing user-authored
		// grant for a known layout, including a manually disabled one. A
		// newly created preferred directory must not bypass the user's
		// earlier decision to disable the alternate layout.
		for _, candidate := range candidates {
			if _, exists := grantOf(cfg, spec.Source, candidate); exists {
				def = candidate
				break
			}
		}
		pair, pairExists := grantOf(cfg, spec.Source, def)
		if pairExists {
			if pair.Enabled {
				continue
			}
			if pair.Managed && pair.SystemDisabled {
				// The sync itself disabled this grant (device identity
				// change): the new device's explicit authorization for the
				// same tool restores it. A user's manual disable is never
				// restarted here.
				restored, err := grantStore.EnableManagedGrant(spec.Source, def)
				if err != nil {
					return nil, nil, fmt.Errorf("restore system-disabled grant for tool %q: %w", tool, err)
				}
				if restored {
					added = append(added, pair.Source+" "+def+" (restored after device change)")
				}
				continue
			}
			pending[tool] = "default-directory grant is manually disabled; re-enable it (toktrail sources enable) to resume collection"
			continue
		}
		// The default-directory probe for a tool with NO grant yet.
		// Only a truly absent directory (os.ErrNotExist) counts as
		// "never detected" — the normal skip of an optional tool this
		// device never installed. Any other probe failure (a permission
		// error, an I/O error, or a path that exists but is not a
		// directory) must surface: classifying a real local fault as
		// "not found" would disguise it as an uninstalled tool.
		missing := true
		for _, candidate := range candidates {
			candidateMissing, probeErr := probe(candidate)
			if probeErr != nil {
				return nil, nil, fmt.Errorf("probe default directory for tool %q: %w", tool, probeErr)
			}
			if !candidateMissing {
				def, missing = candidate, false
				break
			}
		}
		if missing {
			if anyEnabledForSource(cfg, spec.Source) {
				// The tool is collected through a user-authored
				// custom grant; the missing default directory is
				// not a restriction.
				continue
			}
			pending[tool] = "default directory not found: " + def
			continue
		}
		g, wasAdded, err := grantStore.AddManagedGrant(spec.Source, def)
		if err != nil {
			return nil, nil, fmt.Errorf("add managed grant for tool %q: %w", tool, err)
		}
		if wasAdded {
			added = append(added, g.Source+" "+g.Input)
		}
	}
	return added, pending, nil
}

func grantOf(cfg grants.Config, source, input string) (grants.Grant, bool) {
	input = filepath.Clean(input)
	for idx := range cfg.Grants {
		if cfg.Grants[idx].Source == source && filepath.Clean(cfg.Grants[idx].Input) == input {
			return cfg.Grants[idx], true
		}
	}
	return grants.Grant{}, false
}

// managedDefaultGrant returns the managed grant that carries the tool's
// default layout when the sync itself has created one — at any path, not
// only the layouts the current environment proposes. Preference order: an
// enabled grant (the default layout is active, nothing to do), then a
// system-disabled one (restorable by this sync), then a manually disabled
// one (the user's disable stands). Grants are never removed, reordered or
// merged here; user-authored multi-path grants keep their own semantics.
func managedDefaultGrant(cfg grants.Config, source string) (grants.Grant, bool) {
	var disabled grants.Grant
	found := false
	for idx := range cfg.Grants {
		grant := cfg.Grants[idx]
		if grant.Source != source || !grant.Managed {
			continue
		}
		if grant.Enabled || grant.SystemDisabled {
			return grant, true
		}
		if !found {
			disabled, found = grant, true
		}
	}
	return disabled, found
}

func anyEnabledForSource(cfg grants.Config, source string) bool {
	for idx := range cfg.Grants {
		if cfg.Grants[idx].Source == source && cfg.Grants[idx].Enabled {
			return true
		}
	}
	return false
}

// defaultInputMissing classifies the default-directory probe for one
// allowed tool that has no grant yet. missing is true ONLY for
// os.ErrNotExist — a directory this device never had, the normal skip
// of an optional authorized tool. Any other stat failure (a permission
// error, an I/O error) is returned as-is, and a path that exists but
// is not a directory is likewise an honest error: every default path
// in the registry is a directory (including the sqlite sources, whose
// defaults are the directories holding the databases), so a file (or
// FIFO, socket, ...) at that path is a real local fault, never an
// undetected tool. Existing grants with custom file inputs (a
// user-enabled .sqlite database, for example) never pass through this
// probe — only a tool's default directory does.
func defaultInputMissing(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return false, fmt.Errorf("%s exists but is not a directory", path)
		}
		return false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, err
}

// resolveServerURL mirrors syncclient's server URL resolution so the
// overlay records the same identity the fetch used.
func resolveServerURL(optURL string, st statedir.DeviceState) string {
	if u := strings.TrimSpace(optURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	if u := strings.TrimSpace(st.ServerURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:3211"
}

func normalizeServerURL(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), "/")
}

func homeDirOrDefault(override string) string {
	if dir := strings.TrimSpace(override); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return home
}

func pendingSummary(pending map[string]string) string {
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+pending[k])
	}
	return strings.Join(parts, "; ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// pendingToolStatuses maps the grant sync's per-tool restriction reasons
// onto the tool-status vocabulary so the server sees why a revision is not
// currently fully applied. Matching is by fixed reason PREFIX (the exact
// texts mergeManagedGrants produces), never substring: the
// missing-directory reason embeds the default path, and a directory named
// e.g. "unknown tool" must not flip a missing input into "unsupported".
// A reason that matches no known format is omitted entirely — the closed
// tool-status vocabulary has no "unknown" value, and fabricating a
// specific path-related reason would misreport the user's device state.
func pendingToolStatuses(pending map[string]string) []synccmd.ToolStatus {
	tools := make([]string, 0, len(pending))
	for tool := range pending {
		tools = append(tools, tool)
	}
	sortStrings(tools)
	statuses := make([]synccmd.ToolStatus, 0, len(tools))
	for _, tool := range tools {
		reason := pending[tool]
		status := synccmd.ToolStatus{Tool: tool}
		switch {
		case strings.HasPrefix(reason, "unknown tool:"):
			status.Status = "unsupported"
			status.Detail = "unsupported tool"
		case strings.HasPrefix(reason, "default-directory grant is manually disabled"):
			status.Status = "not_detected"
			status.Detail = "default directory grant disabled"
		case strings.HasPrefix(reason, "default directory not found:"):
			status.Status = "not_detected"
			status.Detail = "default directory not found"
		default:
			// Unknown reason: report nothing rather than guess.
			continue
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// ackSupportedTools returns the tool names actually registered in this
// collector build, sorted and deduplicated by construction of the
// registry. Only canonical names travel — never aliases, adapter source
// ids, or local paths.
func ackSupportedTools() []string {
	specs := registry.SupportedTools()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Tool)
	}
	sortStrings(names)
	return names
}

// ackPendingReasons maps the grant sync's per-tool restriction reasons
// onto the closed grant-ack reason codes. Matching is by fixed reason
// PREFIX (the exact texts mergeManagedGrants produces), never substring:
// the missing-directory reason embeds the default path, and a directory
// named e.g. "unknown tool" must not turn a missing_input into an
// unsupported_tool. A reason that matches no known format gets NO
// fabricated code — the tool is left out of the wire reasons and
// returned as unmapped so the run can surface it.
func ackPendingReasons(pending map[string]string) (map[string]string, []string) {
	if len(pending) == 0 {
		return nil, nil
	}
	reasons := make(map[string]string, len(pending))
	var unmapped []string
	for tool, reason := range pending {
		switch {
		case strings.HasPrefix(reason, "unknown tool:"):
			reasons[tool] = synccmd.PendingReasonUnsupportedTool
		case strings.HasPrefix(reason, "default-directory grant is manually disabled"):
			reasons[tool] = synccmd.PendingReasonDisabled
		case strings.HasPrefix(reason, "default directory not found:"):
			reasons[tool] = synccmd.PendingReasonMissingInput
		default:
			unmapped = append(unmapped, tool)
		}
	}
	sortStrings(unmapped)
	if len(reasons) == 0 {
		reasons = nil
	}
	return reasons, unmapped
}

// ackRequestFor builds the grant-ack request for one applied view. A
// complete reason mapping attaches pendingReasons (as [] when nothing is
// restricted); any unmapped reason omits the field entirely — the server
// reads "reasons unknown" — while the supported-tools report still
// travels.
func ackRequestFor(revision int64, applyState, collectorVersion string, supportedTools []string, pendingReasons map[string]string, reasonsIncomplete bool) synccmd.GrantAckRequest {
	req := synccmd.GrantAckRequest{ConsentRevision: revision, ApplyState: applyState, SupportedTools: supportedTools}
	if !reasonsIncomplete {
		req.PendingReasons = wireAckPendingReasons(pendingReasons)
	}
	if collectorVersion != "" {
		req.CollectorVersion = collectorVersion
	}
	return req
}

// ackedPayloadCurrent reports whether a previously confirmed ack already
// covers exactly the payload this run would send: the same revision,
// applied state, collector version, supported-tools list, and reason-code
// COMPLETENESS — and, for complete reports, the same per-tool codes. An
// incomplete report omits pendingReasons on the wire, so while it stays
// incomplete the mapped subset is not compared: the wire payload cannot
// change without one of the other key parts changing.
func ackedPayloadCurrent(prev managedconsent.Overlay, revision int64, applyState, collectorVersion string, supportedTools []string, pendingReasons map[string]string, reasonsIncomplete bool) bool {
	if prev.AckedRevision != revision || prev.AckedApplyState != applyState || prev.AckedCollectorVersion != collectorVersion {
		return false
	}
	if !sameAckedTools(prev.AckedSupportedTools, supportedTools) {
		return false
	}
	if prev.AckedReasonsIncomplete != reasonsIncomplete {
		return false
	}
	if reasonsIncomplete {
		return true
	}
	return sameAckedPendingReasons(prev.AckedPendingReasons, pendingReasons)
}

// wireAckPendingReasons renders the pending-reason codes in the ack's
// wire shape, sorted by tool for a deterministic payload. The result is
// always a non-nil complete report: an empty restriction set serializes
// as the explicit [] "no reasons" array. The caller attaches it only
// when every restriction mapped to a closed code.
func wireAckPendingReasons(reasons map[string]string) *[]synccmd.GrantAckPendingReason {
	out := make([]synccmd.GrantAckPendingReason, 0, len(reasons))
	tools := make([]string, 0, len(reasons))
	for tool := range reasons {
		tools = append(tools, tool)
	}
	sortStrings(tools)
	for _, tool := range tools {
		out = append(out, synccmd.GrantAckPendingReason{Tool: tool, Code: reasons[tool]})
	}
	return &out
}

// sameAckedTools compares two cached acked supported-tools lists. Both
// nil and empty compare equal (nothing reported).
func sameAckedTools(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameAckedPendingReasons compares two cached acked pending-reason maps.
// Both nil and empty compare equal (no restricted tool).
func sameAckedPendingReasons(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for tool, code := range a {
		if b[tool] != code {
			return false
		}
	}
	return true
}
