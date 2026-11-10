package bind

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"toktrail-collector/internal/local/outbox"
	"toktrail-collector/internal/local/statedir"
	"toktrail-collector/internal/syncclient"
)

type Options struct {
	ServerURL         string
	Ticket            string
	ApplicationID     string
	ExternalSubjectID string
	DeviceName        string
	Platform          string
	HTTPClient        *http.Client
	Now               func() time.Time
}

type Result struct {
	State  statedir.DeviceState
	Replay bool
	Status int
}

type bindRequest struct {
	RequestID         string `json:"requestId"`
	Ticket            string `json:"ticket"`
	ApplicationID     string `json:"applicationId"`
	ExternalSubjectID string `json:"externalSubjectId"`
	DeviceName        string `json:"deviceName"`
	Platform          string `json:"platform"`
	DeviceSecret      string `json:"deviceSecret"`
}

// responseError mirrors the server's error block. Both fields are untrusted
// free text: a hostile server can reflect the request's ticket or
// deviceSecret straight into them, so neither value may ever reach an error
// message (see responseCategory).
type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type bindResponse struct {
	Device struct {
		DeviceID          string `json:"deviceId"`
		ApplicationID     string `json:"applicationId"`
		ExternalSubjectID string `json:"externalSubjectId"`
		DeviceName        string `json:"deviceName"`
		Platform          string `json:"platform"`
		ConsentRevision   int64  `json:"consentRevision"`
		// DataEpoch is the device's data epoch on servers that speak the
		// device-usage-reset feature; nil on older servers and treated
		// as epoch 0. Only an INITIAL bind (a state that had no device
		// bound yet) adopts it — see Run.
		DataEpoch *int64    `json:"dataEpoch,omitempty"`
		BoundAt   time.Time `json:"boundAt"`
		Replay    bool      `json:"replay"`
	} `json:"device"`
	Error *responseError `json:"error,omitempty"`
}

// maxResponseBodyBytes bounds how much of a bind response Run reads.
//
// A legitimate bind receipt is the small JSON device block decoded into
// bindResponse (a few hundred bytes); even a generously extended receipt
// with extra unknown fields stays far below 64 KiB, so a 1 MiB ceiling
// leaves >16x headroom for large legitimate receipts while stopping an
// untrusted server from making the collector buffer an unbounded body. A
// response whose first JSON value exceeds the ceiling fails with a fixed
// sanitized error. Trailing data after the first JSON value is never read,
// matching the previous streaming-decoder behavior.
const maxResponseBodyBytes = 1 << 20

// Error is the sanitized failure type Run returns for bind failures that
// involve the server round trip.
//
// Its message is assembled only from fixed literal strings, the numeric HTTP
// status, and category labels from the fixed tables in this file, so it can
// never echo server-controlled response values or the bind credentials
// (ticket, deviceSecret). A wrapped cause stays reachable through
// errors.Is/errors.As for programmatic handling.
type Error struct {
	msg      string
	category string
	status   int
	cause    error
}

func (e *Error) Error() string { return e.msg }

// Unwrap keeps errors.Is/errors.As semantics for the wrapped cause.
func (e *Error) Unwrap() error { return e.cause }

// Category returns the fixed failure category. It is either a literal from
// serverErrorCodeCategories / serverStatusCategories or CategoryOther — never
// a server-reported code.
func (e *Error) Category() string { return e.category }

// Status returns the HTTP status code of the bind response, or 0 when the
// request never completed, so callers can map exit codes without string
// matching.
func (e *Error) Status() int { return e.status }

// Fixed Error categories surfaced by Category.
const (
	CategoryTransport        = "transport"
	CategoryInvalidResponse  = "invalid_response"
	CategoryTicketSuperseded = "ticket_superseded"
	CategoryOther            = "other"
)

// serverStatusCategories maps HTTP status codes to fixed category labels.
// The numeric status carries no server free text, so surfacing it (plus a
// label from this fixed table) cannot leak response values. The 3xx entries
// back the redirect refusal: redirects are never followed, so a 3xx answer
// is reported as an ordinary refused status.
var serverStatusCategories = map[int]string{
	http.StatusBadRequest:          "bad_request",
	http.StatusUnauthorized:        "unauthorized",
	http.StatusForbidden:           "forbidden",
	http.StatusNotFound:            "not_found",
	http.StatusConflict:            "conflict",
	http.StatusUnprocessableEntity: "invalid_request",
	http.StatusTooManyRequests:     "rate_limited",
	http.StatusInternalServerError: "server_error",
	http.StatusBadGateway:          "server_error",
	http.StatusServiceUnavailable:  "server_error",
	http.StatusGatewayTimeout:      "server_error",
	http.StatusMovedPermanently:    "redirect",
	http.StatusFound:               "redirect",
	http.StatusSeeOther:            "redirect",
	http.StatusTemporaryRedirect:   "redirect",
	http.StatusPermanentRedirect:   "redirect",
}

// serverErrorCodeCategories is the fixed whitelist of server error codes Run
// reports by name. A received code is used only for an exact table lookup;
// the surfaced label is always the literal stored here, never the received
// string. Codes outside the whitelist — including anything a hostile server
// reflects back, such as the ticket or deviceSecret — never surface: the
// category then falls back to the HTTP-status table, then CategoryOther.
// Extend this table only with fixed literals vetted against the server
// contract.
var serverErrorCodeCategories = map[string]string{
	"unauthorized":      "unauthorized",
	"ticket_superseded": CategoryTicketSuperseded,
}

// responseCategory resolves the fixed category for a refused bind. The
// server-reported code only selects a whitelisted label; unknown codes
// contribute nothing and the category falls back to the HTTP-status table,
// then CategoryOther.
func responseCategory(status int, srvErr *responseError) string {
	if srvErr != nil {
		if category, ok := serverErrorCodeCategories[srvErr.Code]; ok {
			return category
		}
	}
	if category, ok := serverStatusCategories[status]; ok {
		return category
	}
	return CategoryOther
}

// transportErrorMessage is the fixed message surfaced for every bind
// transport failure. Transport error text is not enumerable: besides this
// run's ticket and deviceSecret, a custom transport, proxy, or TLS layer can
// embed other principals' credentials, proxy URLs, or reflected request data
// that bind cannot predict. The underlying text is therefore never surfaced —
// not even when it looks clean.
const transportErrorMessage = "bind request failed: transport error (details withheld because transport error text may contain credentials)"

// newTransportError wraps a failed bind request with the fully fixed
// transportErrorMessage. The cause stays wrapped so errors.Is/errors.As
// still work.
func newTransportError(cause error) *Error {
	return &Error{msg: transportErrorMessage, category: CategoryTransport, cause: cause}
}

// reflectedCredentialMessage is the fixed error surfaced when a bind receipt
// echoes this run's credentials back. The affected field is never named.
const reflectedCredentialMessage = "bind failed: response contained reflected credential material"

// reflectedCredential reports whether any server-controlled string that bind
// would persist contains one of this run's credentials. The receipt's
// deviceId, deviceName and platform are printed and stored in state, and a
// hostile server that saw the bind payload can reflect the ticket or
// deviceSecret into them (applicationId/externalSubjectId are additionally
// constrained by the identity check above). Hex credentials are
// case-insensitive, so the comparison ignores case.
func reflectedCredential(values []string, credentials ...string) bool {
	for _, credential := range credentials {
		if credential == "" {
			continue
		}
		needle := strings.ToLower(credential)
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), needle) {
				return true
			}
		}
	}
	return false
}

// noRedirectClient returns a shallow copy of client that never follows
// redirects, leaving the caller's client untouched. The bind request body
// carries the ticket and deviceSecret, so a 3xx answer must never be
// followed: Go would forward the credentials to the server-chosen redirect
// target (307/308 resend the body verbatim). The copy preserves the
// original transport, timeout and jar. CheckRedirect returns
// http.ErrUseLastResponse, so Do returns the 3xx response itself with a nil
// error and never issues a second request; the redirect target URL is never
// parsed or echoed (returning a plain error instead would make net/http put
// the raw, server-controlled Location into the resulting *url.Error). The
// 3xx response is then reported by Run as an ordinary refused status.
func noRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	cloned := *client
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &cloned
}

func Run(ctx context.Context, store statedir.Store, opt Options) (Result, error) {
	opt = opt.withDefaults()
	if err := opt.validate(); err != nil {
		return Result{}, err
	}
	// Force-recollect journal guard: while a reset is in flight the state
	// directory belongs to the recollect driver, and a manual bind with a
	// new ticket must not swap the device identity out from under it
	// (connect already refuses earlier; this covers the direct `toktrail
	// bind` path). Bind offers no bypass — the recollect flow never
	// re-binds, it keeps the device secret and id.
	if err := syncclient.CheckResetJournal(store.Dir()); err != nil {
		return Result{}, err
	}
	st, err := store.Load()
	if err != nil {
		return Result{}, err
	}
	if st.DeviceSecret == "" {
		st.DeviceSecret, err = randomHex(32)
		if err != nil {
			return Result{}, err
		}
	}
	// Persist the replay identity before sending a single-use ticket. Hash the
	// request scope so a replacement ticket cannot inherit an old request ID.
	fingerprint := Fingerprint(opt.ServerURL, opt.Ticket, opt.ApplicationID, opt.ExternalSubjectID, opt.DeviceName, opt.Platform)
	legacyPending := st.PendingBindFingerprint == "" && st.DeviceID == "" && st.BindRequestID != ""
	if st.BindRequestID == "" || (!legacyPending && st.PendingBindFingerprint != fingerprint) {
		st.BindRequestID, err = randomHex(16)
		if err != nil {
			return Result{}, err
		}
	}
	st.PendingBindFingerprint = fingerprint
	request := bindRequest{
		RequestID:         st.BindRequestID,
		Ticket:            opt.Ticket,
		ApplicationID:     opt.ApplicationID,
		ExternalSubjectID: opt.ExternalSubjectID,
		DeviceName:        opt.DeviceName,
		Platform:          opt.Platform,
		DeviceSecret:      st.DeviceSecret,
	}
	endpoint, err := joinURL(opt.ServerURL, "/v1/devices/bind")
	if err != nil {
		return Result{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := store.Save(st); err != nil {
		return Result{}, err
	}
	client := noRedirectClient(opt.HTTPClient)
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, newTransportError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Redirects are refused before this point (noRedirectClient), so a
		// 3xx answer means the server tried to move the credential-bearing
		// request elsewhere. Report it as a refused status without reading
		// the body.
		category := responseCategory(resp.StatusCode, nil)
		return Result{}, &Error{
			msg:      fmt.Sprintf("bind failed: status %d: %s", resp.StatusCode, category),
			category: category,
			status:   resp.StatusCode,
		}
	}
	var body bindResponse
	// Bound the untrusted body, and never surface decode errors verbatim:
	// json error text can quote body content, and a hostile server can echo
	// the ticket or deviceSecret back inside the body.
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err := dec.Decode(&body); err != nil {
		return Result{}, &Error{
			msg:      "bind failed: invalid or oversized response body",
			category: CategoryInvalidResponse,
			status:   resp.StatusCode,
			cause:    err,
		}
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Only fixed whitelist labels and the numeric status are reported;
		// the server's error code and message strings never reach the user.
		category := responseCategory(resp.StatusCode, body.Error)
		return Result{}, &Error{
			msg:      fmt.Sprintf("bind failed: status %d: %s", resp.StatusCode, category),
			category: category,
			status:   resp.StatusCode,
		}
	}
	if body.Device.DeviceID == "" {
		return Result{}, errors.New("bind response missing deviceId")
	}
	if body.Device.ApplicationID != opt.ApplicationID || body.Device.ExternalSubjectID != opt.ExternalSubjectID {
		return Result{}, errors.New("bind response identity does not match request")
	}
	// Trust boundary: every string taken from the receipt below is printed
	// and persisted, and the server has just seen this request's ticket and
	// deviceSecret. Fail closed on any reflection before the pending replay
	// identity is ACKed or the bound state is saved.
	if reflectedCredential([]string{
		body.Device.DeviceID,
		body.Device.ApplicationID,
		body.Device.ExternalSubjectID,
		body.Device.DeviceName,
		body.Device.Platform,
	}, opt.Ticket, st.DeviceSecret) {
		return Result{}, &Error{
			msg:      reflectedCredentialMessage,
			category: CategoryInvalidResponse,
			status:   resp.StatusCode,
		}
	}
	// Data epoch adoption: only the INITIAL bind of a not-yet-bound state
	// takes the receipt's dataEpoch (0 on both old servers and fresh
	// devices). A state that already carries a bound device keeps its
	// local epoch verbatim — re-binding must never advance it — so a
	// server that usage-reset the device since leaves this state epoch-
	// stale on purpose: the syncclient epoch fences then block every
	// ordinary upload until the force-recollect flow (whose journal
	// transition is the only other epoch writer) completes. This keeps an
	// old outbox from being quietly relabeled with the new epoch.
	//
	// One fail-closed exception: an UNBOUND state that still carries an
	// ordinary outbox (a backup that lost its device identity, or a
	// hand-stripped device.json) must not adopt a non-zero receipt epoch
	// either. Adopting it would promote those pre-identity batches onto
	// the receipt's post-reset epoch and let them upload as if they were
	// new-epoch data — exactly the backfill the fence exists to stop.
	// The bind is refused; the operator restores the device identity or
	// runs the force-recollect flow instead.
	wasBound := st.DeviceID != ""
	receiptEpoch := int64(0)
	if body.Device.DataEpoch != nil && *body.Device.DataEpoch > 0 {
		receiptEpoch = *body.Device.DataEpoch
	}
	if !wasBound {
		if receiptEpoch > 0 {
			ordinaryBatches, ledgerErr := outbox.New(store.Dir()).Load()
			switch {
			case ledgerErr != nil:
				return Result{}, errors.New("bind refused: cannot verify the local outbox while the device state carries no bound identity and the server reports a non-zero data epoch; restore the device identity or resolve the state directory before binding")
			case len(ordinaryBatches.Batches) > 0:
				return Result{}, errors.New("bind refused: the state directory carries ordinary batches but no bound device identity, and the server reports a non-zero data epoch; restoring a backup must not promote those batches onto the reset device — restore the device identity or run the force-recollect flow")
			}
		}
		st.DataEpoch = receiptEpoch
	}
	st.PendingBindFingerprint = ""
	st.LastBindFingerprint = fingerprint
	if st.PendingConnectReceiptHash != "" {
		st.ConnectReceiptHash = st.PendingConnectReceiptHash
		st.PendingConnectReceiptHash = ""
	}
	st.ServerURL = strings.TrimRight(opt.ServerURL, "/")
	st.ApplicationID = body.Device.ApplicationID
	st.ExternalSubjectID = body.Device.ExternalSubjectID
	st.DeviceID = body.Device.DeviceID
	st.DeviceName = body.Device.DeviceName
	st.Platform = body.Device.Platform
	st.ConsentRevision = body.Device.ConsentRevision
	st.BoundAt = body.Device.BoundAt
	if err := store.Save(st); err != nil {
		return Result{}, err
	}
	return Result{State: st, Replay: body.Device.Replay, Status: resp.StatusCode}, nil
}

func (o Options) withDefaults() Options {
	o.ServerURL = strings.TrimSpace(o.ServerURL)
	if o.ServerURL == "" {
		o.ServerURL = "http://127.0.0.1:3211"
	}
	o.ApplicationID = strings.TrimSpace(o.ApplicationID)
	if o.ApplicationID == "" {
		o.ApplicationID = "leaderboard-local"
	}
	o.ExternalSubjectID = strings.TrimSpace(o.ExternalSubjectID)
	o.DeviceName = strings.TrimSpace(o.DeviceName)
	if o.DeviceName == "" {
		o.DeviceName = "toktrail-collector"
	}
	o.Platform = strings.TrimSpace(o.Platform)
	if o.Platform == "" {
		o.Platform = runtime.GOOS + "-" + runtime.GOARCH
	}
	o.Ticket = strings.TrimSpace(o.Ticket)
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return o
}

func (o Options) validate() error {
	if o.Ticket == "" {
		return errors.New("missing bind ticket")
	}
	if o.ExternalSubjectID == "" {
		return errors.New("missing external subject id")
	}
	u, err := url.Parse(o.ServerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("invalid server URL")
	}
	return nil
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

// Fingerprint computes the deterministic bind fingerprint for a request scope.
func Fingerprint(serverURL, ticket, appID, subjectID, deviceName, platform string) string {
	payload, _ := json.Marshal([]string{serverURL, ticket, appID, subjectID, deviceName, platform})
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
