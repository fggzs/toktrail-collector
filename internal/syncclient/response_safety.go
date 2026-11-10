package syncclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxResponseBodyBytes caps every device-endpoint response body this
// package decodes (device self, ingest, grant-ack, tool-status). A
// legitimate ingest receipt mirrors the submitted batch: at most 500
// records and at most 500 record errors, which stays orders of magnitude
// below this bound; a self or grant-ack response is smaller still. A
// body that needs MORE than the cap to complete its first JSON value is
// hostile or broken: the capped reader reads at most cap+1 bytes,
// identifies the excess explicitly (errResponseBodyTooLarge) without
// recording any content, and the failure lands in the same paths a
// genuinely lost or truncated body already takes — the self check fails
// closed with ErrSelfProtocol, a success-status ingest response becomes
// the retryable lost-receipt outcome, a non-2xx ingest answer keeps its
// status-based classification, and grant-ack / tool-status keep their
// fixed status-only texts. No retry semantics change.
//
// Boundary behavior, stated exactly: a JSON value that completes within
// the cap decodes normally — trailing bytes after a complete value are
// never read, exactly as an unrestricted json.Decoder behaves; a value
// that ends precisely at the cap succeeds without the probe; a body
// that ends cleanly at the cap mid-value surfaces as a plain truncated
// body (unexpected EOF), not as an over-cap excess.
const maxResponseBodyBytes int64 = 8 << 20

// errResponseBodyTooLarge marks a response body whose first JSON value
// required more than maxResponseBodyBytes. The capped reader discards
// the one probe byte it reads beyond the cap; no oversized content is
// ever buffered, logged, or embedded in an error.
var errResponseBodyTooLarge = errors.New("response body exceeds the safety limit")

// cappedResponseBody allows at most maxResponseBodyBytes to flow to the
// decoder. When the decoder is still hungry at the cap, exactly one
// further byte is read and discarded to distinguish "the body continues
// past the cap" (errResponseBodyTooLarge) from "the body ended at the
// cap" (clean io.EOF); both outcomes latch so repeated reads are stable.
type cappedResponseBody struct {
	r         io.Reader
	remaining int64
	eof       bool
	over      bool
}

// capResponseBody bounds a response body for decoding.
func capResponseBody(r io.Reader) io.Reader {
	return &cappedResponseBody{r: r, remaining: maxResponseBodyBytes}
}

func (c *cappedResponseBody) Read(p []byte) (int, error) {
	if c.over {
		return 0, errResponseBodyTooLarge
	}
	if c.eof {
		return 0, io.EOF
	}
	if c.remaining <= 0 {
		// The decoder needs more than the cap allows. Probe a single
		// byte — content discarded — so over-cap is an explicit,
		// identified outcome rather than a silent truncation.
		var probe [1]byte
		if _, err := io.ReadFull(c.r, probe[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				c.eof = true
				return 0, io.EOF
			}
			return 0, err
		}
		c.over = true
		return 0, errResponseBodyTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:int(c.remaining)]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		c.eof = true
	}
	return n, err
}

// sanitizedTransportError replaces a raw transport error (typically a
// *url.Error, whose text names the endpoint and whatever an intermediary
// or the runtime chose to include) with a fixed, human-safe description,
// while keeping the cause reachable through Unwrap for errors.Is and
// errors.As — authorization sentinels, context cancellation, io.EOF from
// a dropped connection, the redirect refusal, and the syncretry markers
// all keep matching. The scope string is a stable human prefix such as
// "device self check failed" or "sync upload"; the cause text is derived
// only from the error's identity, never from its message.
type sanitizedTransportError struct {
	scope string
	err   error
}

// wrapTransportError builds the sanitized wrapper. A nil err stays nil.
func wrapTransportError(scope string, err error) error {
	if err == nil {
		return nil
	}
	return &sanitizedTransportError{scope: scope, err: err}
}

func (e *sanitizedTransportError) Error() string {
	return e.scope + ": " + transportCauseText(e.err)
}

func (e *sanitizedTransportError) Unwrap() error { return e.err }

// transportCauseText renders a transport failure's identity as fixed,
// safe wording. A hostile endpoint cannot influence any of these strings
// (they key off sentinel identities, not error text); everything else
// collapses to the generic withheld-cause wording.
func transportCauseText(err error) string {
	switch {
	case errors.Is(err, errDeviceRedirect):
		return "redirect refused (credentials never follow redirects)"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, io.EOF):
		return "connection closed by the server before a response"
	default:
		return "transport failure (network-level error text withheld; the cause remains matchable with errors.Is/errors.As)"
	}
}

// safeDecodeError hides a response-body decode error's own text behind a
// fixed description derived only from the error's identity. Go's JSON
// syntax errors quote a character of the offending body — untrusted
// server content — so the raw text must never reach a human message; the
// identity-derived wording below ("EOF", "unexpected EOF", …) is what
// dropped-connection semantics need, and Unwrap keeps the original
// cause for programmatic matching.
type safeDecodeError struct {
	err error
}

func safeDecodeErrorOf(err error) error {
	if err == nil {
		return nil
	}
	return &safeDecodeError{err: err}
}

func (e *safeDecodeError) Error() string {
	switch {
	case errors.Is(e.err, io.EOF):
		return "EOF"
	case errors.Is(e.err, io.ErrUnexpectedEOF):
		return "unexpected EOF"
	case errors.Is(e.err, errResponseBodyTooLarge):
		return fmt.Sprintf("response body exceeded the %d MiB safety limit", maxResponseBodyBytes>>20)
	case errors.Is(e.err, context.Canceled):
		return "body read canceled"
	case errors.Is(e.err, context.DeadlineExceeded):
		return "body read timed out"
	default:
		return "malformed response body"
	}
}

func (e *safeDecodeError) Unwrap() error { return e.err }

// The closed vocabulary of status words the device path recognizes on
// the wire. "partial" is the historical alias this repository's own
// syncclient fixtures document; "partial_error" is the spelling the
// server contract mirrored by the collection and cursor fixtures uses.
// Both spellings mean the same thing: some records accepted, some
// rejected.
var knownReceiptStatuses = map[string]bool{
	"accepted":      true,
	"rejected":      true,
	"partial":       true,
	"partial_error": true,
}

// receiptStatusContradictsCounts reports whether a KNOWN status word
// disagrees with the decision counts the receipt also reports. A
// contradiction is an inconsistent receipt: reconcileReceipt fails it
// closed (the batch stays pending, nothing is ACKed) instead of letting
// a receipt claim an outcome its counts disprove.
//
// Empty and unknown status words are deliberately NOT contradictions.
// Evidence for that compatibility: the device path has never validated
// the status string — reconcile historically checked only counts,
// indexes, and keys — so old servers with absent or differently-worded
// statuses have always been accepted, and this repository's fixtures
// themselves mix the "partial" and "partial_error" spellings. The safety
// argument for keeping them: the persisted and displayed status is
// always DERIVED from the counts reconcileReceipt validated against the
// submitted batch (see deriveReceiptStatus), and the unknown wire value
// is dropped without echo — so an unknown status can never forge
// success or any other outcome. Success is decided solely by the
// counts, which must sum to the submitted record count with every
// rejection reconciled index-by-index and key-by-key; a lying server
// fails reconciliation, and a lying status string is simply never used.
func receiptStatusContradictsCounts(status string, accepted, rejected int) bool {
	trimmed := strings.TrimSpace(status)
	if !knownReceiptStatuses[trimmed] {
		return false
	}
	switch trimmed {
	case "accepted":
		return rejected != 0
	case "rejected":
		return accepted != 0
	default: // "partial", "partial_error"
		return accepted == 0 || rejected == 0
	}
}

// deriveReceiptStatus computes the receipt status LOCALLY from the
// counts reconcileReceipt already validated against the submitted
// batch, mirroring the derivation the server itself documents (and the
// cursor path enforces): no rejections means accepted, every record
// rejected means rejected, some of each means partial_error. The two
// partial spellings normalize to the canonical partial_error.
//
// The wire status is never persisted or displayed: a KNOWN word that
// contradicts the counts fails the receipt closed (see
// receiptStatusContradictsCounts), and an unknown or absent word falls
// back to this derivation, which is computed only from validated
// counts. No untrusted string can reach device state, the outbox,
// per-message progress, the returned Result, or human output.
func deriveReceiptStatus(accepted, rejected int) string {
	switch {
	case rejected == 0:
		return "accepted"
	case accepted == 0:
		return "rejected"
	default:
		return "partial_error"
	}
}

// selfSnapshotReflectsSecret reports whether any string field of a
// decoded 200 self snapshot that propagates downstream — the device ID,
// the usage-reset task's request id, the allowed-tools list, or any
// account source's instance ID, type, or state — contains the device
// secret (case-insensitively; the secret is hex, so an attacker cannot
// case-fold its way past the check). A hostile server that echoes the
// credential it just received in the Authorization header back into any
// of these fields must never see it travel on into cursor hints,
// persisted state, or human output.
func selfSnapshotReflectsSecret(dev *SelfStatus, secret string) bool {
	if secret == "" {
		return false
	}
	needle := strings.ToLower(secret)
	reflects := func(s string) bool {
		return s != "" && strings.Contains(strings.ToLower(s), needle)
	}
	if reflects(dev.DeviceID) {
		return true
	}
	if dev.UsageReset != nil && reflects(dev.UsageReset.RequestID) {
		return true
	}
	for _, tool := range dev.AllowedTools {
		if reflects(tool) {
			return true
		}
	}
	for _, src := range dev.AccountSources {
		if reflects(src.SourceInstanceID) || reflects(src.SourceType) || reflects(src.State) {
			return true
		}
	}
	return false
}

// knownRecordErrorCodes is the closed set of record-rejection reason
// codes the device path carries onward (mirroring the server's stable
// codes and the cursor path's list). Everything else collapses to the
// generic record_rejected.
var knownRecordErrorCodes = map[string]bool{
	"stale_revision":          true,
	"record_conflict":         true,
	"invalid_event_key":       true,
	"invalid_revision":        true,
	"invalid_kind":            true,
	"invalid_time":            true,
	"invalid_tool":            true,
	"invalid_adapter_version": true,
	"invalid_source_type":     true,
	"invalid_model":           true,
	"invalid_decimal":         true,
}

// sanitizeRecordErrorCode maps one record-error code onto the closed
// set.
func sanitizeRecordErrorCode(code string) string {
	trimmed := strings.TrimSpace(code)
	if knownRecordErrorCodes[trimmed] {
		return trimmed
	}
	return "record_rejected"
}

// sanitizeReceiptRecordErrors closes the record-error codes and drops
// the server's free-text message entirely. The index stays, and the
// recordKey stays because reconcileReceipt already proved any non-empty
// key equals the locally submitted record's key at that index.
func sanitizeReceiptRecordErrors(errs []RecordError) []RecordError {
	if len(errs) == 0 {
		return nil
	}
	out := make([]RecordError, 0, len(errs))
	for _, re := range errs {
		out = append(out, RecordError{
			Index:     re.Index,
			RecordKey: re.RecordKey,
			Code:      sanitizeRecordErrorCode(re.Code),
		})
	}
	return out
}
