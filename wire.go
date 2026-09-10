package gocloak

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// HelloReadDeadline is the read deadline the server applies while reading
// the hello request from a newly accepted connection, per spec section 4.
// This package never touches net.Conn deadlines itself: the caller sets and
// clears them. Exported so server.go uses this exact spec value instead of
// a fresh magic number.
const HelloReadDeadline = 5 * time.Second

// frameVersion is the only wire protocol version. There is no negotiation:
// any other byte in the version position makes the frame malformed.
const frameVersion byte = 0x01

// maxNameLen is the longest service name the wire protocol allows. The
// length byte can represent up to 255, but a declared length greater than
// this is malformed regardless.
const maxNameLen = 63

// nameRE is the service name charset required by the wire protocol. It is
// the single source of truth for the charset: other code that needs to
// validate a service name should call ValidServiceName rather than
// reimplement this pattern, so the charset cannot drift.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidServiceName reports whether name matches the service name charset
// required by the wire protocol. The charset is restricted so a name can
// never inject control characters into a log line.
func ValidServiceName(name string) bool {
	return nameRE.MatchString(name)
}

// ErrMalformedFrame is the sentinel wrapped into errors returned by
// ReadHelloRequest and ReadHelloResponse when the bytes received do not
// form a valid frame: wrong version, an out-of-range declared length, an
// invalid service name, or an unrecognized status byte. Callers can test
// for it with errors.Is to decide whether to answer with StatusMalformed
// before closing, as opposed to a plain I/O or timeout error, which
// carries no such signal that a response is owed.
var ErrMalformedFrame = errors.New("gocloak: malformed hello frame")

// Status is a hello response status code.
type Status byte

const (
	// StatusOK indicates the request was accepted. The connection becomes
	// a raw bidirectional pipe with no further framing.
	StatusOK Status = 0x00
	// StatusDenied indicates the named service is unknown for this peer.
	StatusDenied Status = 0x01
	// StatusBackendUnavailable indicates the named service is known but
	// its backend could not be reached.
	StatusBackendUnavailable Status = 0x02
	// StatusRateLimited indicates the request was refused by a rate
	// limiter.
	StatusRateLimited Status = 0x03
	// StatusMalformed indicates the server could not parse the request.
	StatusMalformed Status = 0x04
)

// String implements fmt.Stringer for logging. An unrecognized status value
// (which should never occur for a Status this package produced itself)
// renders as its hex byte rather than panicking or guessing.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusDenied:
		return "denied"
	case StatusBackendUnavailable:
		return "backend unavailable"
	case StatusRateLimited:
		return "rate limited"
	case StatusMalformed:
		return "malformed request"
	default:
		return fmt.Sprintf("unknown status 0x%02x", byte(s))
	}
}

// validStatus reports whether s is one of the five defined status codes.
// An unknown status byte is never treated as success.
func validStatus(s Status) bool {
	switch s {
	case StatusOK, StatusDenied, StatusBackendUnavailable, StatusRateLimited, StatusMalformed:
		return true
	default:
		return false
	}
}

// WriteHelloRequest writes a hello request frame naming the service the
// client wants to reach: version byte, length byte, name bytes. name is
// validated with ValidServiceName before anything is written, so an
// invalid name is never put on the wire.
func WriteHelloRequest(w io.Writer, name string) error {
	if !ValidServiceName(name) {
		return errors.New("gocloak: invalid service name")
	}
	frame := make([]byte, 2+len(name))
	frame[0] = frameVersion
	frame[1] = byte(len(name))
	copy(frame[2:], name)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("gocloak: write hello request: %w", err)
	}
	return nil
}

// ReadHelloRequest reads and validates a hello request frame from r. Every
// byte is treated as hostile: the version and declared length are
// validated before any allocation is sized from them, and a short read of
// the name (fewer than the declared N bytes available) is always an error,
// never a partial success. On success it returns the validated service
// name; on failure it never echoes the attacker-supplied name bytes back
// in the returned error.
func ReadHelloRequest(r io.Reader) (string, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", fmt.Errorf("gocloak: read hello request header: %w", err)
	}
	if head[0] != frameVersion {
		return "", fmt.Errorf("%w: unsupported version 0x%02x", ErrMalformedFrame, head[0])
	}

	n := int(head[1])
	if n == 0 || n > maxNameLen {
		return "", fmt.Errorf("%w: invalid name length %d", ErrMalformedFrame, n)
	}

	// n is validated to be within 1..maxNameLen above; only now do we
	// allocate a buffer sized from it.
	nameBytes := make([]byte, n)
	if _, err := io.ReadFull(r, nameBytes); err != nil {
		return "", fmt.Errorf("%w: short read of name", ErrMalformedFrame)
	}

	name := string(nameBytes)
	if !ValidServiceName(name) {
		return "", fmt.Errorf("%w: invalid service name", ErrMalformedFrame)
	}
	return name, nil
}

// WriteHelloResponse writes a hello response frame with the given status:
// version byte, status byte.
func WriteHelloResponse(w io.Writer, status Status) error {
	if !validStatus(status) {
		return fmt.Errorf("gocloak: invalid status 0x%02x", byte(status))
	}
	frame := [2]byte{frameVersion, byte(status)}
	if _, err := w.Write(frame[:]); err != nil {
		return fmt.Errorf("gocloak: write hello response: %w", err)
	}
	return nil
}

// ReadHelloResponse reads and validates a hello response frame from r. An
// unrecognized status byte is always an error, never treated as success:
// the client fails closed on anything it does not recognize.
func ReadHelloResponse(r io.Reader) (Status, error) {
	var frame [2]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		return 0, fmt.Errorf("gocloak: read hello response: %w", err)
	}
	if frame[0] != frameVersion {
		return 0, fmt.Errorf("%w: unsupported version 0x%02x", ErrMalformedFrame, frame[0])
	}
	status := Status(frame[1])
	if !validStatus(status) {
		return 0, fmt.Errorf("%w: unknown status 0x%02x", ErrMalformedFrame, frame[1])
	}
	return status, nil
}
