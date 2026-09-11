package gocloak

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestWireRoundTrip covers a valid request followed by a valid response,
// end to end through the exported codec functions.
func TestWireRoundTrip(t *testing.T) {
	names := []string{
		"a",
		"myservice",
		"a-1-b",
		"9start",
		strings.Repeat("a", maxNameLen), // exactly 63 bytes, the max
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeHelloRequest(&buf, name); err != nil {
				t.Fatalf("writeHelloRequest: %v", err)
			}
			got, err := readHelloRequest(&buf)
			if err != nil {
				t.Fatalf("readHelloRequest: %v", err)
			}
			if got != name {
				t.Fatalf("got name %q, want %q", got, name)
			}
			if buf.Len() != 0 {
				t.Fatalf("expected reader fully consumed, %d bytes left", buf.Len())
			}
		})
	}
}

// TestWireWriteRequestRejectsInvalidName asserts that an invalid name is
// never written to the wire at all.
func TestWireWriteRequestRejectsInvalidName(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHelloRequest(&buf, "Not Valid!"); err == nil {
		t.Fatal("expected error for invalid name, got nil")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected nothing written for invalid name, got %d bytes", buf.Len())
	}
}

// TestWireReadRequestTable is table-driven over malformed and valid raw frames,
// built by hand so we can exercise cases writeHelloRequest would refuse to
// produce (like an oversized declared length or a mismatched name length).
func TestWireReadRequestTable(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		want    string
		wantErr bool
	}{
		{
			name:  "valid",
			frame: []byte{0x01, 0x03, 'a', 'b', 'c'},
			want:  "abc",
		},
		{
			name:    "empty reader",
			frame:   []byte{},
			wantErr: true,
		},
		{
			name:    "zero length",
			frame:   []byte{0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "length exceeds available bytes",
			frame:   []byte{0x01, 0x0a, 'a', 'b', 'c'}, // N=10, only 3 bytes follow
			wantErr: true,
		},
		{
			name:    "truncated name",
			frame:   []byte{0x01, 0x05, 'a', 'b'}, // N=5, only 2 bytes follow
			wantErr: true,
		},
		{
			name:    "length 64 exceeds max even though bytes follow",
			frame:   append([]byte{0x01, 0x40}, bytes.Repeat([]byte{'a'}, 64)...),
			wantErr: true,
		},
		{
			name:    "length 255 exceeds max",
			frame:   append([]byte{0x01, 0xff}, bytes.Repeat([]byte{'a'}, 255)...),
			wantErr: true,
		},
		{
			name:    "invalid charset uppercase",
			frame:   []byte{0x01, 0x03, 'A', 'B', 'C'},
			wantErr: true,
		},
		{
			name:    "invalid charset underscore",
			frame:   []byte{0x01, 0x03, 'a', '_', 'b'},
			wantErr: true,
		},
		{
			name:    "leading hyphen",
			frame:   []byte{0x01, 0x04, '-', 'a', 'b', 'c'},
			wantErr: true,
		},
		{
			name:    "trailing dot",
			frame:   []byte{0x01, 0x04, 'a', 'b', 'c', '.'},
			wantErr: true,
		},
		{
			name:    "embedded newline",
			frame:   []byte{0x01, 0x03, 'a', '\n', 'c'},
			wantErr: true,
		},
		{
			name:    "embedded NUL",
			frame:   []byte{0x01, 0x03, 'a', 0x00, 'c'},
			wantErr: true,
		},
		{
			name:    "wrong version byte",
			frame:   []byte{0x02, 0x03, 'a', 'b', 'c'},
			wantErr: true,
		},
		{
			name:    "only version byte, no length",
			frame:   []byte{0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readHelloRequest(bytes.NewReader(tt.frame))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got name %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestWireReadRequestMalformedIsErrMalformedFrame asserts that validation
// failures (as opposed to plain I/O failures) are identifiable via
// errors.Is(err, errMalformedFrame), which server.go needs to decide
// whether to answer with statusMalformed before closing.
func TestWireReadRequestMalformedIsErrMalformedFrame(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
	}{
		{"wrong version", []byte{0x02, 0x03, 'a', 'b', 'c'}},
		{"zero length", []byte{0x01, 0x00}},
		{"length too long", []byte{0x01, 0x40}},
		{"invalid charset", []byte{0x01, 0x01, 'A'}},
		{"short read of name", []byte{0x01, 0x05, 'a', 'b'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readHelloRequest(bytes.NewReader(tt.frame))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, errMalformedFrame) {
				t.Fatalf("expected errors.Is(err, errMalformedFrame), got: %v", err)
			}
		})
	}
}

// TestWireReadRequestNeverEchoesPayload asserts that a malformed name's
// raw bytes never appear in the returned error string, since that would be
// a log-injection vector (constraint: never log or embed payload bytes).
func TestWireReadRequestNeverEchoesPayload(t *testing.T) {
	marker := "UNIQUE-CANARY-VALUE"
	frame := append([]byte{0x01, byte(len(marker))}, []byte(marker)...)
	_, err := readHelloRequest(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for invalid charset (uppercase canary), got nil")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error echoed payload bytes: %v", err)
	}
}

// TestWireStatusRoundTrip covers every defined status code through
// writeHelloResponse and readHelloResponse.
func TestWireStatusRoundTrip(t *testing.T) {
	statuses := []status{
		statusOK,
		statusDenied,
		statusBackendUnavailable,
		statusRateLimited,
		statusMalformed,
	}
	for _, status := range statuses {
		t.Run(status.String(), func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeHelloResponse(&buf, status); err != nil {
				t.Fatalf("writeHelloResponse: %v", err)
			}
			got, err := readHelloResponse(&buf)
			if err != nil {
				t.Fatalf("readHelloResponse: %v", err)
			}
			if got != status {
				t.Fatalf("got status %v, want %v", got, status)
			}
		})
	}
}

// TestWireReadResponseUnknownStatus asserts that an unrecognized status
// byte is an error, never a silent success.
func TestWireReadResponseUnknownStatus(t *testing.T) {
	frame := []byte{0x01, 0x05} // 0x05 is not a defined status
	_, err := readHelloResponse(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for unknown status byte, got nil")
	}
	if !errors.Is(err, errMalformedFrame) {
		t.Fatalf("expected errors.Is(err, errMalformedFrame), got: %v", err)
	}
}

// TestWireReadResponseWrongVersion asserts the response frame's version
// byte is validated too.
func TestWireReadResponseWrongVersion(t *testing.T) {
	frame := []byte{0x02, 0x00}
	_, err := readHelloResponse(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

// TestWireWriteResponseRejectsUnknownStatus asserts the server side never
// puts an undefined status byte on the wire.
func TestWireWriteResponseRejectsUnknownStatus(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHelloResponse(&buf, status(0x99)); err == nil {
		t.Fatal("expected error for unknown status, got nil")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected nothing written for unknown status, got %d bytes", buf.Len())
	}
}

// TestWireStatusString covers String() for every defined status plus an
// unrecognized value.
func TestWireStatusString(t *testing.T) {
	tests := []struct {
		status status
		want   string
	}{
		{statusOK, "ok"},
		{statusDenied, "denied"},
		{statusBackendUnavailable, "backend unavailable"},
		{statusRateLimited, "rate limited"},
		{statusMalformed, "malformed request"},
		{status(0x42), "unknown status 0x42"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("status(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

// TestWireValidServiceName covers the charset directly, independent of the
// framing.
func TestWireValidServiceName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"a", true},
		{"a0", true},
		{"a-b-c", true},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
		{"", false},
		{"-abc", false},
		{"ABC", false},
		{"a_b", false},
		{"abc.", false},
		{"ab\nc", false},
		{"ab\x00c", false},
	}
	for _, tt := range tests {
		if got := ValidServiceName(tt.name); got != tt.valid {
			t.Errorf("ValidServiceName(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}

// slowReader dispenses data one byte per Read call, simulating a peer that
// writes its frame one byte at a time. It also records how many bytes were
// read so a test can assert the codec did not over-read.
type slowReader struct {
	data []byte
	pos  int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// TestWireReadRequestSlowReader asserts the codec reads exactly the bytes
// it needs from a byte-at-a-time reader and does not over-read into
// whatever data follows the frame (which, after a 0x00 response, is the
// start of the raw tunnel payload and must not be consumed here). The 5
// second deadline itself is the caller's job on the net.Conn, not this
// codec's; this test only checks the codec's own read behavior.
func TestWireReadRequestSlowReader(t *testing.T) {
	name := "myservice"
	trailing := []byte("THIS-IS-TUNNEL-PAYLOAD-NOT-PART-OF-THE-FRAME")

	frame := []byte{0x01, byte(len(name))}
	frame = append(frame, []byte(name)...)
	data := append(append([]byte{}, frame...), trailing...)

	sr := &slowReader{data: data}
	got, err := readHelloRequest(sr)
	if err != nil {
		t.Fatalf("readHelloRequest: %v", err)
	}
	if got != name {
		t.Fatalf("got %q, want %q", got, name)
	}
	if sr.pos != len(frame) {
		t.Fatalf("codec consumed %d bytes, want exactly %d (the frame length); it over-read or under-read into trailing data", sr.pos, len(frame))
	}
	remaining := sr.data[sr.pos:]
	if !bytes.Equal(remaining, trailing) {
		t.Fatalf("trailing tunnel payload was disturbed: got %q, want %q", remaining, trailing)
	}
}

// TestWireReadRequestNoOverread asserts, using a plain
// bytes.Reader, that readHelloRequest consumes exactly the frame's bytes
// and leaves anything after it untouched in the reader.
func TestWireReadRequestNoOverread(t *testing.T) {
	name := "svc"
	trailing := []byte("more-data-after-the-frame")
	frame := []byte{0x01, byte(len(name))}
	frame = append(frame, []byte(name)...)
	data := append(append([]byte{}, frame...), trailing...)

	r := bytes.NewReader(data)
	got, err := readHelloRequest(r)
	if err != nil {
		t.Fatalf("readHelloRequest: %v", err)
	}
	if got != name {
		t.Fatalf("got %q, want %q", got, name)
	}
	rest := make([]byte, len(trailing))
	if _, err := io.ReadFull(r, rest); err != nil {
		t.Fatalf("reading trailing data: %v", err)
	}
	if !bytes.Equal(rest, trailing) {
		t.Fatalf("got trailing %q, want %q", rest, trailing)
	}
}
