package codexjsonl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Codex-specific streaming JSONL reader.
//
// loadCodexJSONLFile previously decoded every physical line through the
// shared jsonl.WalkLinesContext + jsonl.DecodeObject path, which buffers
// one whole line (up to the shared 16 MiB ceiling) and materializes the
// entire decoded object before parseCodexObservation and
// parseCodexTurnContext read a handful of fields. A real Codex session
// line, however, is dominated by message bodies, tool output and images
// that the adapter never reads, so the old reader paid full memory and
// CPU for bytes that are immediately discarded.
//
// walkProjectedCodexLines replaces that path with one uniform streaming
// parser that reads the file through a single fixed 64 KiB window and
// never materializes a line:
//
//   - Every physical line is fully validated — JSON syntax, UTF-8,
//     escapes, number grammar, duplicate keys and nesting depth up to
//     encoding/json's 10000 limit — including values under keys the
//     adapter ignores.
//   - Only the projected fields are retained: root timestamp and type,
//     and payload.type, payload.model and
//     payload.info.total_token_usage.{input_tokens,
//     cached_input_tokens, cache_write_input_tokens, output_tokens}.
//     The projected map preserves the shared parsers' decisions and event
//     values: numbers retain exact integer precision, strings follow
//     adapter.StringAny's trimming, and timestamp fractions beyond
//     nanosecond precision are consumed without retention. No message
//     content is included in the projected map.
//   - Retained fields are bounded. Values over a field's bound are
//     replaced by a clearly invalid stand-in so the existing validation
//     still rejects them (an oversized model keeps 129 bytes, an
//     oversized trimmed string becomes the empty string, an oversized
//     number literal keeps a prefix that can never parse as uint64),
//     while the rest of the line keeps being validated.
//   - Duplicate keys resolve last-wins at every level, keys are matched
//     on their decoded spelling (escaped duplicates of a projected key
//     overwrite earlier values), and JSON null stays distinct from an
//     absent key.
//   - Small and giant lines share one code path; there is no
//     size-threshold fallback and no line-size limit at all.
//
// Line framing copies the shared reader exactly: physical line numbers
// count every line including blank ones, \n separates lines, one \r
// before \n (like bufio.ScanLines) plus Unicode whitespace around the
// line (like strings.TrimSpace) is ignored, a final line without a
// newline is still a line, and a raw newline inside a JSON string is
// illegal and never crosses lines.
//
// Errors are *streamError values carrying "path:line:byte" (the byte is
// the 1-based offset within the physical line) and never include line
// content. The context is checked once per 64 KiB buffer refill and once
// per line; cancellation errors wrap the context error so errors.Is
// keeps matching context.Canceled and context.DeadlineExceeded.

const (
	// streamBufferSize is the one and only read buffer; the parser never
	// grows it and never allocates per-line buffers proportional to line
	// length.
	streamBufferSize = 64 * 1024

	// maxJSONDepth matches encoding/json's nesting limit: a value nested
	// 10000 containers deep parses, the 10001st fails.
	maxJSONDepth = 10000

	// maxModelBytes retains 129 bytes of a model value. Wire validation
	// rejects anything over 128 bytes, so a longer value keeps a prefix
	// that is guaranteed to stay over the limit (129 bytes, possibly
	// splitting a rune, which fails the same check with the same
	// message) while the rest of the line is still fully validated.
	maxModelBytes = 129

	// maxProjectedStringBytes bounds the trimmed retention of the
	// projected string fields (root type, payload type, timestamp, and
	// string stand-ins for wrong-shaped containers). The bound matches
	// the streaming compatibility budget: any value whose trimmed form
	// fits is retained byte-exactly (keeping adapter.StringAny gates and
	// time.Parse error text identical to the old decoder), and a longer
	// one becomes the empty string, which can neither match a type
	// constant nor parse as a timestamp.
	maxProjectedStringBytes = 64 << 10

	// maxCounterStringBytes bounds the trimmed retention of counters
	// written as JSON strings. A valid counter is at most
	// 18446744073709551615 (20 digits), so anything within the bound is
	// kept byte-exactly and anything over it is replaced by the empty
	// string, which fails the same strict-decimal check.
	maxCounterStringBytes = 32

	// maxCounterNumberBytes bounds the literal kept for counters written
	// as JSON numbers. In-range integers are at most 20 digits; a longer
	// literal keeps a 32-byte prefix that can never parse as uint64.
	maxCounterNumberBytes = 32
)

// Parse and framing failure reasons. They describe the failure without
// ever quoting input bytes.
const (
	reasonUTF8        = "invalid UTF-8 in JSON"
	reasonUnexpected  = "unexpected end of JSON input"
	reasonTrailing    = "trailing data after JSON value"
	reasonMaxDepth    = "exceeded max depth"
	reasonBeginValue  = "invalid character looking for beginning of value"
	reasonObjectKey   = "invalid character looking for beginning of object key string"
	reasonAfterKey    = "invalid character after object key"
	reasonAfterPair   = "invalid character after object key:value pair"
	reasonAfterElem   = "invalid character after array element"
	reasonInString    = "invalid character in string literal"
	reasonInEscape    = "invalid character in string escape code"
	reasonInHexEscape = `invalid character in \u hexadecimal character escape`
	reasonAfterZero   = "invalid character after zero"
	reasonAfterPoint  = "invalid character after decimal point"
	reasonInExponent  = "invalid character in exponent"
	reasonNumLiteral  = "invalid character in number literal"
)

// streamError reports one parse or framing failure with its physical
// location. Byte is the 1-based byte offset within the line; when the
// failure is a premature end it points one past the last byte (or at
// the terminating newline).
type streamError struct {
	Path   string
	Line   int
	Byte   int
	Reason string
}

func (e *streamError) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s", e.Path, e.Line, e.Byte, e.Reason)
}

// walkProjectedCodexLines streams one Codex JSONL file and invokes fn
// once for every non-blank physical line with the projected raw map and
// the 1-based physical line number (blank lines are skipped but still
// counted). A root JSON null surfaces as a nil map, exactly like the
// old jsonl.DecodeObject did. Errors returned by fn stop the walk and
// are returned verbatim; the walk's own failures are *streamError
// values, and cancellation returns an error wrapping the context error.
func walkProjectedCodexLines(ctx context.Context, path string, fn func(raw map[string]any, line int) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := &streamWindow{
		ctx:  ctx,
		path: path,
		f:    f,
		buf:  make([]byte, streamBufferSize),
		line: 1,
		pos:  1,
	}
lineLoop:
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s:%d: %w", path, w.line, err)
		}
		// Skip the outer strings.TrimSpace whitespace prefix and detect
		// blank lines (including Unicode-whitespace-only lines).
		for {
			if w.start >= w.end {
				if err := w.fill(); err != nil {
					return err
				}
				if w.start >= w.end {
					return nil // clean EOF
				}
			}
			i := w.start
			for i < w.end && isTrimSpaceASCII(w.buf[i]) {
				i++
			}
			if i > w.start {
				w.pos += i - w.start
				w.start = i
				continue
			}
			b := w.buf[w.start]
			if b == '\n' {
				w.advanceNewline()
				continue lineLoop // blank line: count it, move on
			}
			if b >= utf8.RuneSelf {
				r, size, _, err := w.peekRune()
				if err != nil {
					return err
				}
				if unicode.IsSpace(r) {
					w.start += size
					w.pos += size
					continue
				}
			}
			break // line content starts at the current byte
		}
		raw, err := w.parseRootValue()
		if err != nil {
			return err
		}
		// Only Unicode whitespace may follow the root value on its line.
		if err := w.skipLineTrailing(); err != nil {
			return err
		}
		if err := fn(raw, w.line); err != nil {
			return err
		}
		if w.start < w.end && w.buf[w.start] == '\n' {
			w.advanceNewline()
		}
	}
}

// skipLineTrailing consumes the Unicode whitespace run after the root
// value. It returns with the line's newline as the current byte, or at
// EOF for a final line without a newline; any other byte is trailing
// data, which the old decoder rejected after decoding.
func (w *streamWindow) skipLineTrailing() error {
	for {
		if w.start >= w.end {
			if err := w.fill(); err != nil {
				return err
			}
			if w.start >= w.end {
				return nil
			}
		}
		i := w.start
		for i < w.end && isTrimSpaceASCII(w.buf[i]) {
			i++
		}
		if i > w.start {
			w.pos += i - w.start
			w.start = i
			continue
		}
		b := w.buf[w.start]
		if b == '\n' {
			return nil
		}
		if b >= utf8.RuneSelf {
			r, size, _, err := w.peekRune()
			if err != nil {
				return err
			}
			if unicode.IsSpace(r) {
				w.start += size
				w.pos += size
				continue
			}
		}
		return w.errAt(reasonTrailing)
	}
}

// parseRootValue parses one complete root value. Objects project into
// the retained map, null becomes the nil map (the old DecodeObject
// accepted it), and every other root shape is rejected with the same
// message json.Unmarshal produced for a non-object root.
func (w *streamWindow) parseRootValue() (map[string]any, error) {
	startPos := w.pos
	b, ok, err := w.peekByte()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, w.errUnexpectedEnd()
	}
	switch b {
	case '{':
		return w.parseObject(1, codexRootSpec)
	case 'n':
		if err := w.scanLiteral("null"); err != nil {
			return nil, err
		}
		return nil, nil
	case '[':
		if err := w.skipValue(1); err != nil {
			return nil, err
		}
		return nil, w.errAtPos(startPos, rootTypeReason("array"))
	case '"':
		if err := w.scanString(nil); err != nil {
			return nil, err
		}
		return nil, w.errAtPos(startPos, rootTypeReason("string"))
	case 't', 'f':
		word := "true"
		if b == 'f' {
			word = "false"
		}
		if err := w.scanLiteral(word); err != nil {
			return nil, err
		}
		return nil, w.errAtPos(startPos, rootTypeReason("bool"))
	}
	if b == '-' || (b >= '0' && b <= '9') {
		if err := w.scanNumber(nil); err != nil {
			return nil, err
		}
		return nil, w.errAtPos(startPos, rootTypeReason("number"))
	}
	return nil, w.badChar(reasonBeginValue)
}

func rootTypeReason(kind string) string {
	return "json: cannot unmarshal " + kind + " into Go value of type map[string]interface {}"
}

// streamWindow is the fixed-buffer reader and JSON scanner. buf is the
// only buffer; start/end delimit the valid window, line is the current
// physical line number and pos the 1-based byte offset of buf[start]
// within that line. Every refill checks the context.
type streamWindow struct {
	f     *os.File
	buf   []byte
	start int
	end   int
	eof   bool
	line  int
	pos   int
	ctx   context.Context
	path  string
}

// fill slides the window to make room and reads more bytes. It checks
// the context on every refill so a giant line can be cancelled between
// any two 64 KiB chunks.
func (w *streamWindow) fill() error {
	if w.eof {
		return nil
	}
	if err := w.ctx.Err(); err != nil {
		return fmt.Errorf("%s:%d: %w", w.path, w.line, err)
	}
	if w.start > 0 {
		copy(w.buf, w.buf[w.start:w.end])
		w.end -= w.start
		w.start = 0
	}
	if w.end < len(w.buf) {
		n, err := w.f.Read(w.buf[w.end:])
		w.end += n
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("%s:%d: %w", w.path, w.line, err)
		}
		if err != nil {
			w.eof = true
		}
	}
	return nil
}

func (w *streamWindow) peekByte() (byte, bool, error) {
	if w.start >= w.end {
		if err := w.fill(); err != nil {
			return 0, false, err
		}
		if w.start >= w.end {
			return 0, false, nil
		}
	}
	return w.buf[w.start], true, nil
}

// peekRune decodes the UTF-8 rune at the current position, topping the
// window up so multi-byte runes split across a refill boundary decode
// correctly. ok is false at EOF; an invalid or truncated sequence is an
// "invalid UTF-8 in JSON" error, matching the old whole-line check.
func (w *streamWindow) peekRune() (rune, int, bool, error) {
	if w.start >= w.end {
		if err := w.fill(); err != nil {
			return 0, 0, false, err
		}
		if w.start >= w.end {
			return 0, 0, false, nil
		}
	}
	for w.end-w.start < utf8.UTFMax && !w.eof {
		if err := w.fill(); err != nil {
			return 0, 0, false, err
		}
	}
	n := w.end - w.start
	if n > utf8.UTFMax {
		n = utf8.UTFMax
	}
	r, size := utf8.DecodeRune(w.buf[w.start : w.start+n])
	if r == utf8.RuneError && size == 1 {
		return 0, 0, true, w.errAt(reasonUTF8)
	}
	return r, size, true, nil
}

func (w *streamWindow) advanceNewline() {
	w.start++
	w.line++
	w.pos = 1
}

func (w *streamWindow) errAt(reason string) error {
	return &streamError{Path: w.path, Line: w.line, Byte: w.pos, Reason: reason}
}

func (w *streamWindow) errAtPos(pos int, reason string) error {
	return &streamError{Path: w.path, Line: w.line, Byte: pos, Reason: reason}
}

func (w *streamWindow) errUnexpectedEnd() error {
	return w.errAt(reasonUnexpected)
}

// badChar reports an unexpected-character failure, but keeps the old
// decoder's priority of rejecting invalid UTF-8 first: if the bytes at
// the failure position are not valid UTF-8, the UTF-8 error wins.
func (w *streamWindow) badChar(reason string) error {
	if _, _, _, err := w.peekRune(); err != nil {
		return err
	}
	return w.errAt(reason)
}

// skipJSONSpace consumes JSON inter-token whitespace (space, tab and
// carriage return; a physical newline inside a value is the line-based
// "unexpected end", never inter-token whitespace).
func (w *streamWindow) skipJSONSpace() error {
	for {
		if w.start >= w.end {
			if err := w.fill(); err != nil {
				return err
			}
			if w.start >= w.end {
				return w.errUnexpectedEnd()
			}
		}
		i := w.start
		for i < w.end {
			b := w.buf[i]
			if b == ' ' || b == '\t' || b == '\r' {
				i++
				continue
			}
			break
		}
		if i > w.start {
			w.pos += i - w.start
			w.start = i
		}
		if w.start >= w.end {
			continue // window exhausted; refill and keep skipping
		}
		if w.buf[w.start] == '\n' {
			return w.errUnexpectedEnd()
		}
		return nil
	}
}

func (w *streamWindow) expectColon() error {
	b, ok, err := w.peekByte()
	if err != nil {
		return err
	}
	if !ok {
		return w.errUnexpectedEnd()
	}
	if b != ':' {
		return w.badChar(reasonAfterKey)
	}
	w.start++
	w.pos++
	return nil
}

// isTrimSpaceASCII reports the ASCII bytes strings.TrimSpace strips:
// every ASCII whitespace except the newline, which the line loop treats
// as the line terminator.
func isTrimSpaceASCII(b byte) bool {
	switch b {
	case ' ', '\t', '\v', '\f', '\r':
		return true
	}
	return false
}

// isTrimSpaceControl reports the raw C0 control bytes that are both
// invalid inside JSON strings and strippable by strings.TrimSpace.
func isTrimSpaceControl(b byte) bool {
	switch b {
	case '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// restOfLineIsUnicodeSpace reports whether every byte from the current
// position to the line's newline (or EOF) is Unicode whitespace. The
// old reader trimmed that run away before parsing, so a raw whitespace
// control inside a string followed only by whitespace means the JSON
// text ended earlier and the string is unterminated. Both outcomes are
// terminal errors, so consuming while peeking is safe.
func (w *streamWindow) restOfLineIsUnicodeSpace() (bool, error) {
	for {
		if w.start >= w.end {
			if err := w.fill(); err != nil {
				return false, err
			}
			if w.start >= w.end {
				return true, nil // EOF: nothing but whitespace remains
			}
		}
		i := w.start
		for i < w.end && isTrimSpaceASCII(w.buf[i]) {
			i++
		}
		if i > w.start {
			w.pos += i - w.start
			w.start = i
			continue
		}
		b := w.buf[w.start]
		if b == '\n' {
			return true, nil
		}
		if b >= utf8.RuneSelf {
			r, size, _, err := w.peekRune()
			if err != nil {
				return false, err
			}
			if unicode.IsSpace(r) {
				w.start += size
				w.pos += size
				continue
			}
		}
		return false, nil
	}
}

// runeSink receives the decoded runes of one JSON string.
type runeSink interface {
	addRune(r rune)
}

// scanString consumes one JSON string literal, opening and closing
// quotes included; the opening quote must be the current byte. Every
// rune of the decoded value is validated (raw controls are rejected,
// escapes decoded, UTF-8 sequences checked) and passed to sink, which
// may be nil for pure validation. Bytes are consumed straight from the
// fixed window, so strings far larger than the buffer stream through
// without ever being materialized.
func (w *streamWindow) scanString(sink runeSink) error {
	w.start++
	w.pos++ // opening quote
	for {
		i := w.start
		for i < w.end {
			b := w.buf[i]
			if b < 0x20 || b >= utf8.RuneSelf || b == '"' || b == '\\' {
				break
			}
			i++
		}
		if n := i - w.start; n > 0 {
			if sink != nil {
				for _, b := range w.buf[w.start:i] {
					sink.addRune(rune(b))
				}
			}
			w.pos += n
			w.start = i
		}
		if w.start >= w.end {
			if err := w.fill(); err != nil {
				return err
			}
			if w.start >= w.end {
				return w.errUnexpectedEnd()
			}
			continue
		}
		switch b := w.buf[w.start]; {
		case b == '"':
			w.start++
			w.pos++
			return nil
		case b == '\\':
			w.start++
			w.pos++
			r, err := w.scanEscape()
			if err != nil {
				return err
			}
			if sink != nil {
				sink.addRune(r)
			}
		case b < 0x20:
			// Raw control. Whitespace controls may still be part of the
			// trailing run the old reader trimmed away before parsing;
			// only a lookahead can tell an unterminated string from a
			// genuinely illegal control byte.
			controlPos := w.pos
			if isTrimSpaceControl(b) {
				ws, err := w.restOfLineIsUnicodeSpace()
				if err != nil {
					return err
				}
				if ws {
					return w.errUnexpectedEnd()
				}
			}
			return w.errAtPos(controlPos, reasonInString)
		default: // b >= utf8.RuneSelf: multi-byte rune
			r, size, _, err := w.peekRune()
			if err != nil {
				return err
			}
			if sink != nil {
				sink.addRune(r)
			}
			w.start += size
			w.pos += size
		}
	}
}

// scanEscape decodes one escape sequence; the backslash must already
// be consumed. Lone surrogate halves decode to U+FFFD and a valid pair
// combines, exactly like encoding/json.
func (w *streamWindow) scanEscape() (rune, error) {
	b, ok, err := w.peekByte()
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, w.errUnexpectedEnd()
	}
	switch b {
	case '"', '\\', '/':
		w.start++
		w.pos++
		return rune(b), nil
	case 'b':
		w.start++
		w.pos++
		return '\b', nil
	case 'f':
		w.start++
		w.pos++
		return '\f', nil
	case 'n':
		w.start++
		w.pos++
		return '\n', nil
	case 'r':
		w.start++
		w.pos++
		return '\r', nil
	case 't':
		w.start++
		w.pos++
		return '\t', nil
	case 'u':
		w.start++
		w.pos++
		return w.scanUnicodeEscape()
	default:
		if b == '\n' {
			return 0, w.errUnexpectedEnd()
		}
		if _, _, _, err := w.peekRune(); err != nil {
			return 0, err
		}
		return 0, w.errAt(reasonInEscape)
	}
}

// scanUnicodeEscape decodes the four hexadecimal digits after \u and
// resolves surrogate pairs, peeking (without consuming) a following
// \uXXXX for the low half. An unpaired half becomes U+FFFD.
func (w *streamWindow) scanUnicodeEscape() (rune, error) {
	u1, err := w.scanHex4()
	if err != nil {
		return 0, err
	}
	if u1 >= 0xD800 && u1 <= 0xDBFF {
		u2, ok, err := w.peekUnicodeEscape()
		if err != nil {
			return 0, err
		}
		if ok && u2 >= 0xDC00 && u2 <= 0xDFFF {
			w.start += 6
			w.pos += 6
			return utf16.DecodeRune(rune(u1), rune(u2)), nil
		}
		return utf8.RuneError, nil
	}
	if u1 >= 0xDC00 && u1 <= 0xDFFF {
		return utf8.RuneError, nil
	}
	return rune(u1), nil
}

func (w *streamWindow) scanHex4() (int, error) {
	v := 0
	for i := 0; i < 4; i++ {
		b, ok, err := w.peekByte()
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, w.errUnexpectedEnd()
		}
		var d int
		switch {
		case b >= '0' && b <= '9':
			d = int(b - '0')
		case b >= 'a' && b <= 'f':
			d = int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			d = int(b-'A') + 10
		default:
			if b == '\n' {
				return 0, w.errUnexpectedEnd()
			}
			if _, _, _, err := w.peekRune(); err != nil {
				return 0, err
			}
			return 0, w.errAt(reasonInHexEscape)
		}
		v = v<<4 | d
		w.start++
		w.pos++
	}
	return v, nil
}

// peekUnicodeEscape looks ahead for a \uXXXX escape at the current
// position without consuming it.
func (w *streamWindow) peekUnicodeEscape() (int, bool, error) {
	for w.end-w.start < 6 && !w.eof {
		if err := w.fill(); err != nil {
			return 0, false, err
		}
	}
	if w.end-w.start < 6 {
		return 0, false, nil
	}
	if w.buf[w.start] != '\\' || w.buf[w.start+1] != 'u' {
		return 0, false, nil
	}
	v := 0
	for i := 2; i < 6; i++ {
		b := w.buf[w.start+i]
		switch {
		case b >= '0' && b <= '9':
			v = v<<4 | int(b-'0')
		case b >= 'a' && b <= 'f':
			v = v<<4 | int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			v = v<<4 | int(b-'A') + 10
		default:
			return 0, false, nil
		}
	}
	return v, true, nil
}

// scanLiteral consumes one of the JSON literals true, false or null.
func (w *streamWindow) scanLiteral(word string) error {
	for i := 0; i < len(word); i++ {
		b, ok, err := w.peekByte()
		if err != nil {
			return err
		}
		if !ok {
			return w.errUnexpectedEnd()
		}
		if b != word[i] {
			if b == '\n' {
				return w.errUnexpectedEnd()
			}
			if _, _, _, err := w.peekRune(); err != nil {
				return err
			}
			return w.errAt("invalid character in literal " + word)
		}
		w.start++
		w.pos++
	}
	return nil
}

// scanNumber consumes one JSON number with the full grammar
// (-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?). sink, which may be
// nil, receives the literal bytes up to its bound; validation always
// runs to the end of the literal.
func (w *streamWindow) scanNumber(sink *numSink) error {
	b, ok, err := w.peekByte()
	if err != nil {
		return err
	}
	if !ok {
		return w.errUnexpectedEnd()
	}
	if b == '-' {
		sink.put('-')
		w.start++
		w.pos++
		b, ok, err = w.peekByte()
		if err != nil {
			return err
		}
		if !ok {
			return w.errUnexpectedEnd()
		}
		if !(b >= '0' && b <= '9') {
			if b == '\n' {
				return w.errUnexpectedEnd()
			}
			return w.badChar(reasonNumLiteral)
		}
	}
	if b == '0' {
		sink.put('0')
		w.start++
		w.pos++
		nb, ok, err := w.peekByte()
		if err != nil {
			return err
		}
		if ok && nb >= '0' && nb <= '9' {
			return w.badChar(reasonAfterZero)
		}
	} else {
		if err := w.consumeDigitRun(sink); err != nil {
			return err
		}
	}
	// Fraction.
	after, okAfter, err := w.peekByte()
	if err != nil {
		return err
	}
	if okAfter && after == '.' {
		sink.put('.')
		w.start++
		w.pos++
		db, okDigit, err := w.peekByte()
		if err != nil {
			return err
		}
		if !okDigit {
			return w.errUnexpectedEnd()
		}
		if !(db >= '0' && db <= '9') {
			if db == '\n' {
				return w.errUnexpectedEnd()
			}
			return w.badChar(reasonAfterPoint)
		}
		if err := w.consumeDigitRun(sink); err != nil {
			return err
		}
		after, okAfter, err = w.peekByte()
		if err != nil {
			return err
		}
	}
	// Exponent.
	if okAfter && (after == 'e' || after == 'E') {
		sink.put(after)
		w.start++
		w.pos++
		eb, okExp, err := w.peekByte()
		if err != nil {
			return err
		}
		if okExp && (eb == '+' || eb == '-') {
			sink.put(eb)
			w.start++
			w.pos++
			eb, okExp, err = w.peekByte()
			if err != nil {
				return err
			}
		}
		if !okExp {
			return w.errUnexpectedEnd()
		}
		if !(eb >= '0' && eb <= '9') {
			if eb == '\n' {
				return w.errUnexpectedEnd()
			}
			return w.badChar(reasonInExponent)
		}
		if err := w.consumeDigitRun(sink); err != nil {
			return err
		}
	}
	return nil
}

// consumeDigitRun consumes a run of ASCII digits, feeding sink, and
// stops at the first non-digit byte (or EOF, which the caller treats as
// the end of the literal).
func (w *streamWindow) consumeDigitRun(sink *numSink) error {
	for {
		if w.start >= w.end {
			if err := w.fill(); err != nil {
				return err
			}
			if w.start >= w.end {
				return nil
			}
		}
		i := w.start
		for i < w.end && w.buf[i] >= '0' && w.buf[i] <= '9' {
			i++
		}
		if n := i - w.start; n > 0 {
			for _, d := range w.buf[w.start:i] {
				sink.put(d)
			}
			w.pos += n
			w.start = i
		}
		if w.start >= w.end {
			continue // window exhausted mid-run
		}
		return nil
	}
}

// numSink retains the first bytes of a number literal as a json.Number,
// preserving exact uint64 precision for every in-range integer.
type numSink struct {
	cap int
	buf []byte
}

func (n *numSink) put(b byte) {
	if n == nil || len(n.buf) >= n.cap {
		return
	}
	n.buf = append(n.buf, b)
}

func (n *numSink) finish() json.Number {
	if n == nil {
		return json.Number("")
	}
	return json.Number(n.buf)
}

// trimSink retains the strings.TrimSpace'd value of a decoded string
// bounded by cap bytes. Leading Unicode whitespace is never retained,
// trailing whitespace is dropped when the string closes, and inner
// whitespace is buffered (bounded) so it flushes back into the value
// when content follows. Once the trimmed value outgrows the bound the
// sink gives up and finish reports the empty string: an oversized
// string can neither match a type constant nor parse as a timestamp or
// counter, which is exactly the verdict the old full-value decode
// produced for oversized values.
type trimSink struct {
	cap      int
	started  bool
	buf      []byte
	pending  []byte
	pendOver bool
	over     bool
}

func (t *trimSink) addRune(r rune) {
	if !t.started {
		if unicode.IsSpace(r) {
			return // leading whitespace
		}
		t.started = true
	}
	if unicode.IsSpace(r) {
		if t.pendOver {
			return
		}
		var tmp [utf8.UTFMax]byte
		n := utf8.EncodeRune(tmp[:], r)
		if len(t.pending)+n > t.cap {
			t.pendOver = true
			return
		}
		t.pending = append(t.pending, tmp[:n]...)
		return
	}
	if t.over || t.pendOver {
		t.over = true
		return
	}
	if len(t.buf)+len(t.pending) > t.cap {
		t.over = true
		return
	}
	t.buf = append(t.buf, t.pending...)
	t.pending = t.pending[:0]
	var tmp [utf8.UTFMax]byte
	n := utf8.EncodeRune(tmp[:], r)
	if len(t.buf)+n > t.cap {
		t.over = true
		return
	}
	t.buf = append(t.buf, tmp[:n]...)
}

func (t *trimSink) finish() string {
	if t.over {
		return ""
	}
	return string(t.buf)
}

// timestampSink retains a timestamp without imposing a length limit on its
// fractional seconds. time.Parse accepts arbitrarily many fractional digits
// and ignores digits after nanosecond precision. Once a validated date/time
// prefix opens a fraction, retain its first nine digits and validate/consume
// the remaining digits without keeping them. The existing time parser still
// validates the suffix; invalid timestamps remain invalid. This does not
// rewrite any exported value: records already format the parsed time as RFC3339.
type timestampSink struct {
	trim       trimSink
	inFraction bool
	digits     int
}

func (t *timestampSink) addRune(r rune) {
	if t.inFraction {
		if r >= '0' && r <= '9' {
			if t.digits < 9 {
				t.trim.addRune(r)
			}
			if t.digits < 9 {
				t.digits++
			}
			return
		}
		t.inFraction = false
	}
	// RFC3339's date/time prefix is 19 bytes, or 18 for the single-digit
	// hour accepted by time.Parse. A separator anywhere else is not a
	// fractional-second opener and is retained for normal validation.
	if (r == '.' || r == ',') && !t.trim.over && !t.trim.pendOver && len(t.trim.pending) == 0 && (len(t.trim.buf) == 18 || len(t.trim.buf) == 19) {
		if _, err := time.Parse(time.RFC3339, string(t.trim.buf)+"Z"); err == nil {
			t.inFraction = true
			t.digits = 0
		}
	}
	t.trim.addRune(r)
}

func (t *timestampSink) finish() string { return t.trim.finish() }

// verbatimSink retains the decoded value byte-for-byte up to cap bytes;
// used for the model (129 bytes, so anything over the wire limit stays
// over the limit) and for bounded stand-ins of wrong-shaped containers.
type verbatimSink struct {
	cap int
	buf []byte
}

func (v *verbatimSink) addRune(r rune) {
	var tmp [utf8.UTFMax]byte
	n := utf8.EncodeRune(tmp[:], r)
	for i := 0; i < n; i++ {
		if len(v.buf) >= v.cap {
			return
		}
		v.buf = append(v.buf, tmp[i])
	}
}

func (v *verbatimSink) finish() string {
	return string(v.buf)
}

// keyMatcher matches a decoded object key against the projected key set
// without materializing it. Candidates that share the consumed prefix
// stay alive; a key matches the candidate it consumed exactly. Escaped
// spellings therefore resolve to the same slot as their plain form.
type keyMatcher struct {
	cands []string
	mask  uint32
	pos   int
}

func (m *keyMatcher) addRune(r rune) {
	if r >= utf8.RuneSelf {
		m.mask = 0
		m.pos++
		return
	}
	next := uint32(0)
	for i := range m.cands {
		if m.mask&(1<<i) == 0 {
			continue
		}
		if m.pos < len(m.cands[i]) && m.cands[i][m.pos] == byte(r) {
			next |= 1 << i
		}
	}
	m.mask = next
	m.pos++
}

func (m *keyMatcher) matched() int {
	for i := range m.cands {
		if m.mask&(1<<i) != 0 && m.pos == len(m.cands[i]) {
			return i
		}
	}
	return -1
}

// The projection schema. Each level lists the keys the shared parsers
// read; every other key of the same object is validated and discarded.
type valueKind int

const (
	vkTrimString valueKind = iota // timestamp and type fields
	vkModel                       // payload.model, kept verbatim up to 129 bytes
	vkCounter                     // token counters, number or string
	vkContainer                   // payload, info, total_token_usage
	vkTimestamp                   // timestamp, with bounded fractional-second retention
)

type objectSpec struct {
	keys  []string
	kinds []valueKind
	child *objectSpec // nested object spec for vkContainer members
}

type slot struct {
	present bool
	val     any
}

var codexUsageSpec = &objectSpec{
	keys:  []string{"input_tokens", "cached_input_tokens", "cache_write_input_tokens", "output_tokens"},
	kinds: []valueKind{vkCounter, vkCounter, vkCounter, vkCounter},
}

var codexInfoSpec = &objectSpec{
	keys:  []string{"total_token_usage"},
	kinds: []valueKind{vkContainer},
	child: codexUsageSpec,
}

var codexPayloadSpec = &objectSpec{
	keys:  []string{"type", "model", "info"},
	kinds: []valueKind{vkTrimString, vkModel, vkContainer},
	child: codexInfoSpec,
}

var codexRootSpec = &objectSpec{
	keys:  []string{"timestamp", "type", "payload"},
	kinds: []valueKind{vkTimestamp, vkTrimString, vkContainer},
	child: codexPayloadSpec,
}

// parseObject parses one JSON object (depth is the object's own nesting
// depth, the root being 1) keeping only the projected keys of spec.
// Members repeat with last-wins semantics: a later occurrence of a
// projected key replaces the earlier value wholesale, matching the old
// decode-into-map behavior. Unknown members are skipped by skipValue,
// which validates their full subtree without materializing anything.
func (w *streamWindow) parseObject(depth int, spec *objectSpec) (map[string]any, error) {
	if depth > maxJSONDepth {
		return nil, w.errAt(reasonMaxDepth)
	}
	w.start++
	w.pos++ // '{'
	slots := make([]slot, len(spec.keys))
	needKey := false // a comma was consumed: only a key may follow
	for {
		if err := w.skipJSONSpace(); err != nil {
			return nil, err
		}
		b, ok, err := w.peekByte()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, w.errUnexpectedEnd()
		}
		if b == '}' && !needKey {
			w.start++
			w.pos++
			break
		}
		if b != '"' {
			return nil, w.badChar(reasonObjectKey)
		}
		m := keyMatcher{cands: spec.keys, mask: uint32(1)<<len(spec.keys) - 1}
		if err := w.scanString(&m); err != nil {
			return nil, err
		}
		idx := m.matched()
		if err := w.skipJSONSpace(); err != nil {
			return nil, err
		}
		if err := w.expectColon(); err != nil {
			return nil, err
		}
		if err := w.skipJSONSpace(); err != nil {
			return nil, err
		}
		if idx >= 0 {
			v, err := w.parseProjectedValue(depth+1, spec.kinds[idx], spec.child)
			if err != nil {
				return nil, err
			}
			slots[idx] = slot{present: true, val: v}
		} else if err := w.skipValue(depth + 1); err != nil {
			return nil, err
		}
		if err := w.skipJSONSpace(); err != nil {
			return nil, err
		}
		sep, okSep, err := w.peekByte()
		if err != nil {
			return nil, err
		}
		if !okSep {
			return nil, w.errUnexpectedEnd()
		}
		if sep == ',' {
			w.start++
			w.pos++
			needKey = true
			continue
		}
		if sep == '}' {
			w.start++
			w.pos++
			break
		}
		return nil, w.badChar(reasonAfterPair)
	}
	out := make(map[string]any, len(spec.keys))
	for i := range slots {
		if slots[i].present {
			out[spec.keys[i]] = slots[i].val
		}
	}
	return out, nil
}

// parseProjectedValue parses the value of one projected member and
// returns what the raw map should carry. JSON null stays a present nil
// (distinct from an absent key, which the shared parsers observe), and
// values of the wrong JSON shape become small kind-preserving
// stand-ins: the old decoder materialized them in full, but the shared
// parsers only ever type-assert them, so a bounded stand-in keeps every
// "malformed payload" / "must be a non-negative integer" decision
// identical.
func (w *streamWindow) parseProjectedValue(depth int, kind valueKind, child *objectSpec) (any, error) {
	b, ok, err := w.peekByte()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, w.errUnexpectedEnd()
	}
	switch b {
	case '"':
		switch kind {
		case vkModel:
			v := &verbatimSink{cap: maxModelBytes}
			if err := w.scanString(v); err != nil {
				return nil, err
			}
			return v.finish(), nil
		case vkTimestamp:
			t := &timestampSink{trim: trimSink{cap: maxProjectedStringBytes}}
			if err := w.scanString(t); err != nil {
				return nil, err
			}
			return t.finish(), nil
		case vkCounter:
			t := &trimSink{cap: maxCounterStringBytes}
			if err := w.scanString(t); err != nil {
				return nil, err
			}
			return t.finish(), nil
		default: // vkTrimString and wrong-shaped container stand-ins
			t := &trimSink{cap: maxProjectedStringBytes}
			if err := w.scanString(t); err != nil {
				return nil, err
			}
			return t.finish(), nil
		}
	case '{':
		if kind == vkContainer {
			return w.parseObject(depth, child)
		}
		if err := w.skipValue(depth); err != nil {
			return nil, err
		}
		return map[string]any{}, nil
	case '[':
		if err := w.skipValue(depth); err != nil {
			return nil, err
		}
		return []any{}, nil
	case 't':
		if err := w.scanLiteral("true"); err != nil {
			return nil, err
		}
		return true, nil
	case 'f':
		if err := w.scanLiteral("false"); err != nil {
			return nil, err
		}
		return false, nil
	case 'n':
		if err := w.scanLiteral("null"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if b == '-' || (b >= '0' && b <= '9') {
		n := &numSink{cap: maxCounterNumberBytes}
		if err := w.scanNumber(n); err != nil {
			return nil, err
		}
		return n.finish(), nil
	}
	return nil, w.badChar(reasonBeginValue)
}

// skipValue validates one full JSON value without retaining any of it:
// strings stream through the fixed window, numbers are grammar-checked
// to their last digit, and containers recurse with the same depth
// budget as encoding/json. It allocates nothing.
func (w *streamWindow) skipValue(depth int) error {
	b, ok, err := w.peekByte()
	if err != nil {
		return err
	}
	if !ok {
		return w.errUnexpectedEnd()
	}
	switch b {
	case '{':
		if depth > maxJSONDepth {
			return w.errAt(reasonMaxDepth)
		}
		w.start++
		w.pos++
		needKey := false // a comma was consumed: only a key may follow
		for {
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			kb, okKey, err := w.peekByte()
			if err != nil {
				return err
			}
			if !okKey {
				return w.errUnexpectedEnd()
			}
			if kb == '}' && !needKey {
				w.start++
				w.pos++
				return nil
			}
			if kb != '"' {
				return w.badChar(reasonObjectKey)
			}
			if err := w.scanString(nil); err != nil {
				return err
			}
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			if err := w.expectColon(); err != nil {
				return err
			}
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			if err := w.skipValue(depth + 1); err != nil {
				return err
			}
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			sb, okSep, err := w.peekByte()
			if err != nil {
				return err
			}
			if !okSep {
				return w.errUnexpectedEnd()
			}
			if sb == ',' {
				w.start++
				w.pos++
				needKey = true
				continue
			}
			if sb == '}' {
				w.start++
				w.pos++
				return nil
			}
			return w.badChar(reasonAfterPair)
		}
	case '[':
		if depth > maxJSONDepth {
			return w.errAt(reasonMaxDepth)
		}
		w.start++
		w.pos++
		needValue := false // a comma was consumed: only a value may follow
		for {
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			eb, okElem, err := w.peekByte()
			if err != nil {
				return err
			}
			if !okElem {
				return w.errUnexpectedEnd()
			}
			if eb == ']' && !needValue {
				w.start++
				w.pos++
				return nil
			}
			if err := w.skipValue(depth + 1); err != nil {
				return err
			}
			if err := w.skipJSONSpace(); err != nil {
				return err
			}
			sb, okSep, err := w.peekByte()
			if err != nil {
				return err
			}
			if !okSep {
				return w.errUnexpectedEnd()
			}
			if sb == ',' {
				w.start++
				w.pos++
				needValue = true
				continue
			}
			if sb == ']' {
				w.start++
				w.pos++
				return nil
			}
			return w.badChar(reasonAfterElem)
		}
	case '"':
		return w.scanString(nil)
	case 't':
		return w.scanLiteral("true")
	case 'f':
		return w.scanLiteral("false")
	case 'n':
		return w.scanLiteral("null")
	}
	if b == '-' || (b >= '0' && b <= '9') {
		return w.scanNumber(nil)
	}
	return w.badChar(reasonBeginValue)
}
