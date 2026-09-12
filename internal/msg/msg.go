// Package msg implements the message protocol shared by the gocloak-sink
// and gocloak-send example applications: newline-delimited messages, each
// acknowledged with a byte count. It exists so the two example binaries
// stay thin wrappers around logic that is unit-testable without spawning
// either process.
//
// The protocol has nothing to do with the goCloak wire protocol in
// wire.go. It runs on top of whatever net.Conn it is given, tunneled or
// not, and gocloak-sink is a plain TCP service that never imports this
// module's caller, gocloak itself.
package msg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// MaxMessageLen is the largest message this package will read from a
// connection, in bytes, excluding the trailing newline. It bounds every
// read so a peer, malicious or merely broken, cannot make Serve allocate
// without limit. A message longer than this is rejected, never truncated.
const MaxMessageLen = 64 * 1024

// ErrMessageTooLarge is returned when a peer sends a message longer than
// MaxMessageLen before a newline terminates it.
var ErrMessageTooLarge = fmt.Errorf("msg: message exceeds the %d byte limit", MaxMessageLen)

// errIncompleteMessage means the connection reached EOF, or another read
// error, in the middle of a message: the delimiting newline never arrived.
// This is not surfaced to callers of Serve; it is logged and the
// connection is closed, per the sink's job of tolerating a peer that hangs
// up early.
var errIncompleteMessage = errors.New("msg: connection ended before a newline")

// Handler is invoked once per received message. addr is the connection's
// remote address, and message is the message bytes with the trailing
// newline already removed. Handler must not retain message beyond the
// call: the buffer belongs to the caller.
type Handler func(addr string, message []byte)

// Serve accepts connections on ln and, on each, reads newline-delimited
// messages and invokes handler for each one, then writes back
// "ACK <n>\n" where n is the number of message bytes received (excluding
// the newline). Connections are handled concurrently.
//
// Serve blocks until ctx is done, at which point it closes ln, waits for
// every in-flight connection handler to return, and returns ctx.Err(). If
// ln.Accept fails for a reason other than ctx being done, that error is
// returned immediately without waiting for ctx.
func Serve(ctx context.Context, ln net.Listener, handler Handler, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-stopWatch:
		}
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			close(stopWatch)
			wg.Wait()
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ServeConn(conn, handler, logger)
		}()
	}
}

// ServeConn reads newline-delimited messages from one connection until it
// closes or a read fails, invoking handler and acknowledging each message
// in turn. It always closes conn before returning.
//
// A connection that closes mid-message, or fails any other way mid-read,
// is not treated as a crash-worthy error: it is logged at Info level and
// ServeConn returns. A message over MaxMessageLen is logged as a rejection
// and the connection is closed; the oversized bytes already read are
// discarded, never handed to handler.
func ServeConn(conn net.Conn, handler Handler, logger *slog.Logger) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	r := bufio.NewReader(conn)

	for {
		message, err := readMessage(r)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// A clean close between messages: not worth a log line.
			case errors.Is(err, errIncompleteMessage):
				logger.Info("msg: connection closed mid-message", "addr", addr)
			case errors.Is(err, ErrMessageTooLarge):
				logger.Warn("msg: rejected oversized message", "addr", addr)
			default:
				logger.Warn("msg: read failed", "addr", addr, "error", err.Error())
			}
			return
		}

		// The message is printed by handler, which is the sink's whole
		// purpose. It must never also be logged here: that would be the
		// same content at two log sites, one of which a caller might
		// then log again itself.
		handler(addr, message)

		if _, err := fmt.Fprintf(conn, "ACK %d\n", len(message)); err != nil {
			logger.Warn("msg: write ack failed", "addr", addr, "error", err.Error())
			return
		}
	}
}

// readMessage reads one newline-delimited message from r, bounded at
// MaxMessageLen bytes excluding the newline. It never buffers more than
// MaxMessageLen+1 bytes regardless of how much a peer sends: growth stops
// the instant the limit is crossed, so a peer streaming an unterminated
// message cannot make it allocate without bound.
//
// It returns io.EOF when the connection closed cleanly between messages,
// errIncompleteMessage when it closed (or errored) after some message
// bytes were read but before a newline, and ErrMessageTooLarge when the
// limit is crossed before a newline appears.
func readMessage(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return nil, io.EOF
				}
				return nil, errIncompleteMessage
			}
			if len(buf) == 0 {
				return nil, err
			}
			return nil, errIncompleteMessage
		}
		if b == '\n' {
			return buf, nil
		}
		if len(buf) >= MaxMessageLen {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, b)
	}
}

// Send writes message plus a trailing newline to conn, then reads back the
// ack line, returning it (with its newline stripped) and the elapsed time
// from just before the write to just after the ack arrives.
//
// message is rejected before anything is written if it is longer than
// MaxMessageLen, since a sink built on ServeConn would refuse it anyway.
//
// Send reads with its own buffered reader, so calling it more than once on
// the same conn risks losing bytes buffered past the first ack. It is meant
// for the one-message-per-connection shape gocloak-send uses.
func Send(conn net.Conn, message string) (ack string, elapsed time.Duration, err error) {
	if len(message) > MaxMessageLen {
		return "", 0, ErrMessageTooLarge
	}

	start := time.Now()
	if _, err := io.WriteString(conn, message+"\n"); err != nil {
		return "", 0, fmt.Errorf("msg: write message: %w", err)
	}

	line, err := readMessage(bufio.NewReader(conn))
	if err != nil {
		return "", time.Since(start), fmt.Errorf("msg: read ack: %w", err)
	}
	return string(line), time.Since(start), nil
}
