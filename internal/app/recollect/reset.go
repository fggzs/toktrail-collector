package recollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

// reset.go drives the server-side half of the force recollection: the
// capability probe, the post-confirmation scope/epoch CAS, the idempotent
// usage-reset request, and the completion marker. Every call rides the
// syncclient reset API (bearer device, redirect-refusing, body-capped,
// identity-checked); this file only decides WHEN they are safe to call
// and what the journal must record first.

// deviceUsageResetFeature is the server capability gating the whole flow.
const deviceUsageResetFeature = "device-usage-reset"

// probeUsageResetCapability verifies the server advertises the
// device-usage-reset capability before anything else happens: the plan
// fetch, the reset, and the completion all depend on endpoints an older
// server does not have. The capabilities endpoint is unauthenticated and
// carries no device data (the same probe pattern resync's override pass
// uses). An absent feature, an unreachable endpoint, or an undecodable
// response fails closed.
func probeUsageResetCapability(ctx context.Context, client *http.Client, serverURL string) error {
	endpoint := strings.TrimRight(strings.TrimSpace(serverURL), "/") + "/v1/capabilities"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	probe := safeProbeClient(client)
	resp, err := probe.Do(req)
	if err != nil {
		return fmt.Errorf("cannot check the server's capabilities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the server's capabilities endpoint returned HTTP %d", resp.StatusCode)
	}
	var caps struct {
		Features []string `json:"features"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return fmt.Errorf("the server's capabilities response is not decodable: %w", err)
	}
	for _, feature := range caps.Features {
		if feature == deviceUsageResetFeature {
			return nil
		}
	}
	return fmt.Errorf("the server does not advertise the %s capability; upgrade the server before running a force recollection", deviceUsageResetFeature)
}

// safeProbeClient applies the same HTTP policy the sync path enforces to
// the unauthenticated capabilities GET: bounded timeout, no redirects.
func safeProbeClient(client *http.Client) *http.Client {
	cloned := http.Client{}
	if client != nil {
		cloned = *client
	}
	if cloned.Timeout <= 0 || cloned.Timeout > 15*time.Second {
		cloned.Timeout = 15 * time.Second
	}
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return &cloned
}

// selfEpoch reads the device self snapshot's data epoch. A server that
// advertises the usage-reset capability always reports the field; a
// missing field after a passed capability probe is a protocol violation
// and fails closed rather than guessing epoch 0.
func selfEpoch(self syncclient.SelfStatus) (int64, error) {
	if self.DataEpoch == nil {
		return 0, fmt.Errorf("the server did not report a data epoch although it advertises the %s capability; failing closed instead of guessing epoch 0", deviceUsageResetFeature)
	}
	if *self.DataEpoch < 0 {
		return 0, errors.New("the server reported a negative data epoch; failing closed")
	}
	return *self.DataEpoch, nil
}

// requestReset executes the reset step for a scanned job, AFTER the user
// confirmed the frozen plan.
//
// Idempotency contract: the journal freezes the exact request payload
// (request id, expected epoch, expected consent revision) durably BEFORE
// the first POST, and every retry — including a resume after a LOST
// response, even when the live authorization has since changed — replays
// that identical payload. The server keeps the original receipt keyed on
// the payload, so the replay can never wedge behind a
// same-id-different-payload conflict.
//
//   - First attempt (no frozen payload yet): the live consent scope must
//     still match the journal's frozen baseline and the live data epoch
//     must still be the old epoch. A scope change stops BEFORE anything
//     is reset — nothing was cleared, so the job may be abandoned and
//     re-planned fresh under the live authorization.
//
//   - Replay (frozen payload, no receipt yet): the live epoch is either
//     still the old one (the reset never happened or the response was
//     lost before it applied) or the new one with the self summary's
//     reset task naming THIS job's request id (the reset happened but
//     the receipt was lost). Both re-POST the frozen payload. Anything
//     else (a foreign epoch, a foreign in-flight reset) fails closed:
//     the pre-scanned batches are stale for that epoch.
//
//   - A 409 while the live epoch is still the old one proves the reset
//     never happened (an applied reset answers with its receipt before
//     the CAS) and the expected epoch or revision moved: nothing was
//     cleared, and the job is safely re-plannable after abandoning it.
func requestReset(ctx context.Context, store statedir.Store, client *http.Client, j *job, self syncclient.SelfStatus, now func() time.Time) (syncclient.UsageReset, error) {
	liveEpoch, err := selfEpoch(self)
	if err != nil {
		return syncclient.UsageReset{}, err
	}
	if j.ResetRequest == nil {
		// First attempt: strict scope CAS before the payload is frozen.
		if liveEpoch != j.OldDataEpoch {
			return syncclient.UsageReset{}, fmt.Errorf("the server reports data epoch %d but the rebuild planned %d -> %d; another usage reset moved the device's epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", liveEpoch, j.OldDataEpoch, j.NextDataEpoch, journalPath(j.StateDir))
		}
		live, err := scopeFromSelf(self, stateOf(store))
		if err != nil {
			return syncclient.UsageReset{}, err
		}
		if !j.Scope.matches(live) {
			return syncclient.UsageReset{}, fmt.Errorf("force recollection stopped before the reset: the consent scope changed since the plan was built (%s); nothing was cleared — remove %s and the recollect directories it names to abandon this job, then re-run for a fresh plan under the live authorization (or restore the planned authorization and re-run to continue this job)", describeScopeChange(j.Scope, live), journalPath(j.StateDir))
		}
		// Freeze the immutable payload durably BEFORE the POST, so every
		// retry replays exactly these bytes.
		j.ResetRequest = &syncclient.UsageResetRequest{
			RequestID:               j.RequestID,
			ExpectedDataEpoch:       j.OldDataEpoch,
			ExpectedConsentRevision: j.Scope.Revision,
		}
		if err := saveJob(j.StateDir, *j, now); err != nil {
			return syncclient.UsageReset{}, fmt.Errorf("cannot persist the frozen reset payload before the request; nothing was cleared: %w", err)
		}
	}
	switch {
	case liveEpoch == j.OldDataEpoch:
		// The reset has not observably happened (first attempt, or a
		// lost response before it applied).
	case liveEpoch == j.NextDataEpoch && self.UsageReset != nil && self.UsageReset.RequestID == j.RequestID:
		// The server already applied THIS job's reset; the replay below
		// returns the original receipt without clearing anything again.
	default:
		return syncclient.UsageReset{}, fmt.Errorf("the server reports data epoch %d for this device (the rebuild planned %d -> %d); another usage reset moved the device's epoch, so this job's pre-scanned batches are stale and can never upload under the live epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", liveEpoch, j.OldDataEpoch, j.NextDataEpoch, journalPath(j.StateDir))
	}
	receipt, err := syncclient.RequestUsageReset(ctx, store, syncclient.Options{ServerURL: j.ServerURL, HTTPClient: client}, *j.ResetRequest)
	if err != nil {
		if errors.Is(err, syncclient.ErrResetConflict) && liveEpoch == j.OldDataEpoch {
			// The reset definitively never happened (an applied reset
			// answers with its receipt before the CAS), and the expected
			// epoch or consent revision moved. Nothing was cleared; the
			// job is safely re-plannable.
			return syncclient.UsageReset{}, fmt.Errorf("the usage reset was refused because the expected data epoch or consent revision moved; nothing was cleared — remove %s and the recollect directories it names to abandon this job, then re-run for a fresh plan under the live authorization: %w", journalPath(j.StateDir), err)
		}
		return syncclient.UsageReset{}, fmt.Errorf("the usage reset request failed; the frozen payload stays replayable and nothing was installed locally — re-run the same command to retry it: %w", err)
	}
	if receipt.DataEpoch != j.NextDataEpoch || receipt.PreviousDataEpoch != j.OldDataEpoch {
		return syncclient.UsageReset{}, fmt.Errorf("the server's reset receipt advanced the data epoch %d -> %d, but this rebuild pre-scanned its batches for epoch %d; the frozen artifacts cannot be uploaded under the received epoch — remove %s and the recollect directories it names to abandon this job and start a fresh force recollection", receipt.PreviousDataEpoch, receipt.DataEpoch, j.NextDataEpoch, journalPath(j.StateDir))
	}
	return receipt, nil
}

// stateOf loads the device state for the scope mirror's legacy
// never-widen adjustment.
func stateOf(store statedir.Store) statedir.DeviceState {
	st, err := store.Load()
	if err != nil {
		return statedir.DeviceState{}
	}
	return st
}

// completeReset posts the completion marker once every frozen batch was
// fully accepted with no rejections. The identical request replays the
// original receipt, so a crash between the server recording the
// completion and the journal write converges on the next run.
func completeReset(ctx context.Context, store statedir.Store, client *http.Client, j *job) (syncclient.UsageResetCompletion, error) {
	completion, err := syncclient.CompleteUsageReset(ctx, store, syncclient.Options{ServerURL: j.ServerURL, HTTPClient: client}, syncclient.UsageResetCompletionRequest{
		RequestID: j.RequestID,
		DataEpoch: j.NextDataEpoch,
	})
	if err != nil {
		return syncclient.UsageResetCompletion{}, fmt.Errorf("the rebuild completion marker was not accepted; the job stays resumable and nothing was lost — re-run the same command: %w", err)
	}
	return completion, nil
}
