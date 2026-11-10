package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncretry"
)

// ToolStatus is a source observation, independent of usage batches and cursors.
type ToolStatus struct {
	Tool   string `json:"tool"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ReportToolStatuses never changes usage ACKs, baselines, or progress.
// With Retry, transient preflight and report failures use the run's bounded
// policy. Each attempt rechecks live authorization and resends the same status
// payload. Metadata POSTs do not consume the ingest budget.
func ReportToolStatuses(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	opt.ToolStatuses = append([]ToolStatus(nil), opt.ToolStatuses...)
	if len(opt.ToolStatuses) == 0 || len(opt.ToolStatuses) > 32 {
		return Result{}, errors.New("tool status count must be between 1 and 32")
	}
	seen := map[string]bool{}
	for _, item := range opt.ToolStatuses {
		if strings.TrimSpace(item.Tool) == "" || len(item.Tool) > 64 || seen[item.Tool] {
			return Result{}, errors.New("invalid or duplicate tool status")
		}
		seen[item.Tool] = true
		switch item.Status {
		case "synced", "no_new_records", "unsupported", "not_detected":
		default:
			return Result{}, errors.New("invalid tool status")
		}
		switch item.Detail {
		case "", "no new records since last confirmed baseline", "unsupported tool", "default directory not found", "default directory grant disabled":
		default:
			return Result{}, errors.New("invalid tool status detail")
		}
	}
	payload, err := json.Marshal(struct {
		Statuses []ToolStatus `json:"statuses"`
	}{opt.ToolStatuses})
	if err != nil {
		return Result{}, err
	}
	if opt.Retry == nil {
		return reportToolStatusAttempt(ctx, store, opt, payload)
	}
	var outcome Result
	err = opt.Retry.Do(ctx, func(ctx context.Context, _ int) error {
		var err error
		outcome, err = reportToolStatusAttempt(ctx, store, opt, payload)
		return err
	})
	return outcome, err
}

func reportToolStatusAttempt(ctx context.Context, store statedir.Store, opt Options, payload []byte) (Result, error) {
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return Result{}, errors.New("device is not bound; run toktrail bind first")
	}
	serverURL := strings.TrimSpace(opt.ServerURL)
	if serverURL == "" {
		serverURL = st.ServerURL
	}
	if serverURL == "" {
		return Result{}, errors.New("server URL is required")
	}
	client := noRedirectClient(opt.HTTPClient)
	if strings.TrimSpace(opt.StateDir) != "" {
		if _, err := outbox.New(opt.StateDir).RecordPreflightAttempt(time.Now().UTC()); err != nil {
			return Result{}, err
		}
	}
	self, err := preflightSelfAttempt(ctx, client, serverURL, st, opt.Retry != nil)
	if err != nil {
		return Result{}, err
	}
	// A paused device sends nothing — not even status metadata.
	if err := checkNotPaused(self); err != nil {
		return Result{}, err
	}
	// Data-epoch fence: a device whose locally locked epoch no longer
	// matches the server's (a usage reset happened elsewhere, or the
	// local state predates it) reports no tool statuses either — the
	// server cleared the ordinary tool status at the reset, and stale
	// pre-reset reports would quietly repopulate it. The check is the
	// same fence the upload preflight applies.
	if err := CheckSelfDataEpoch(self, st.DataEpoch); err != nil {
		return Result{}, err
	}
	if len(self.AllowedTools) > 0 {
		for _, item := range opt.ToolStatuses {
			allowed := false
			for _, tool := range self.AllowedTools {
				if tool == item.Tool {
					allowed = true
					break
				}
			}
			if !allowed {
				return Result{}, ErrOutsideScope
			}
		}
	}
	endpoint, err := joinURL(serverURL, "/v1/devices/tool-status")
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+st.DeviceID+"."+st.DeviceSecret)
	req.Header.Set("X-Consent-Revision", strconv.FormatInt(self.ConsentRevision, 10))
	resp, err := client.Do(req)
	if err != nil {
		// Raw transport text never reaches a human message; the cause
		// stays matchable through Unwrap.
		return Result{}, retryToolStatusTransport(ctx, opt.Retry != nil, "tool status report", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return Result{State: st, Self: self, Status: resp.StatusCode}, nil
		}
		var body ingestResponse
		if err := json.NewDecoder(capResponseBody(resp.Body)).Decode(&body); err != nil {
			failure := fmt.Errorf("tool status response HTTP %d", resp.StatusCode)
			if opt.Retry != nil && ctx.Err() == nil && retryableIngestStatus(resp.StatusCode) && !errors.Is(err, errResponseBodyTooLarge) {
				return Result{}, syncretry.RetryAfterHeader(failure, resp.Header.Get("Retry-After"))
			}
			return Result{}, failure
		}
		code := ""
		if body.Error != nil {
			code = body.Error.Code
		}
		failure := classifyIngestError(resp.StatusCode, code)
		if opt.Retry != nil && ctx.Err() == nil && retryableIngestStatus(resp.StatusCode) && retryableIngestCode(code) {
			return Result{}, syncretry.RetryAfterHeader(failure, resp.Header.Get("Retry-After"))
		}
		return Result{}, failure
	}
	return Result{State: st, Self: self, Status: resp.StatusCode}, nil
}

func retryToolStatusTransport(ctx context.Context, enabled bool, scope string, err error) error {
	failure := wrapTransportError(scope, err)
	if enabled && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, errDeviceRedirect) {
		return syncretry.Retryable(failure)
	}
	return failure
}
