package msg

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// discardLogger is a *slog.Logger that writes nowhere, so tests exercising
// the log-and-move-on paths don't spam test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------------------------------------------------------------------------
// ServeConn + Send round trip
// ---------------------------------------------------------------------------

func TestServeConnRoundTripOverPipe(t *testing.T) {
	server, client := net.Pipe()

	var mu sync.Mutex
	var gotAddr string
	var gotMessage []byte

	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeConn(server, func(addr string, message []byte) {
			mu.Lock()
			gotAddr = addr
			gotMessage = append([]byte(nil), message...)
			mu.Unlock()
		}, discardLogger())
	}()

	ack, elapsed, err := Send(client, "hello from the pipe")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if ack != "ACK 19" {
		t.Fatalf("ack = %q, want %q", ack, "ACK 19")
	}
	if elapsed <= 0 {
		t.Fatalf("elapsed = %v, want > 0", elapsed)
	}

	client.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if string(gotMessage) != "hello from the pipe" {
		t.Fatalf("handler got %q, want %q", gotMessage, "hello from the pipe")
	}
	if gotAddr == "" {
		t.Fatalf("handler got empty addr")
	}
}

// ---------------------------------------------------------------------------
// Serve: concurrent connections
// ---------------------------------------------------------------------------

func TestServeHandlesConcurrentConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	got := map[string]bool{}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- Serve(ctx, ln, func(addr string, message []byte) {
			mu.Lock()
			got[string(message)] = true
			mu.Unlock()
		}, discardLogger())
	}()

	const n = 5
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()
			msgText := "concurrent-" + string(rune('a'+i))
			ack, _, err := Send(conn, msgText)
			if err != nil {
				t.Errorf("send %d: %v", i, err)
				return
			}
			want := "ACK " + itoa(len(msgText))
			if ack != want {
				t.Errorf("send %d: ack = %q, want %q", i, ack, want)
			}
		}(i)
	}
	wg.Wait()

	cancel()
	if err := <-serveDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve returned %v, want context.Canceled", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("got %d distinct messages, want %d: %v", len(got), n, got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ---------------------------------------------------------------------------
// Disconnects and malformed framing
// ---------------------------------------------------------------------------

func TestServeConnSenderDisconnectsMidMessage(t *testing.T) {
	server, client := net.Pipe()

	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeConn(server, func(addr string, message []byte) {
			called <- struct{}{}
		}, discardLogger())
	}()

	// Write a partial message, no newline, then hang up without ever
	// completing it. This must not crash ServeConn or invoke handler.
	if _, err := client.Write([]byte("partial-mess")); err != nil {
		t.Fatalf("write: %v", err)
	}
	client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return after mid-message disconnect")
	}

	select {
	case <-called:
		t.Fatal("handler was invoked for an incomplete message")
	default:
	}
}

func TestServeConnMessageWithNoTrailingNewline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	called := make(chan struct{}, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		ServeConn(conn, func(addr string, message []byte) {
			called <- struct{}{}
		}, discardLogger())
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("no newline here")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close the write side so the server sees EOF without the
	// client tearing down the whole connection first.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	} else {
		conn.Close()
	}

	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return for a message with no trailing newline")
	}
	select {
	case <-called:
		t.Fatal("handler was invoked for a message with no trailing newline")
	default:
	}
	conn.Close()
}

// ---------------------------------------------------------------------------
// Size bounds
// ---------------------------------------------------------------------------

func TestServeConnAcceptsMessageAtExactlyTheLimit(t *testing.T) {
	server, client := net.Pipe()

	var gotLen int
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeConn(server, func(addr string, message []byte) {
			gotLen = len(message)
		}, discardLogger())
	}()

	exact := strings.Repeat("a", MaxMessageLen)
	ack, _, err := Send(client, exact)
	if err != nil {
		t.Fatalf("Send at exact limit: %v", err)
	}
	if ack != "ACK "+itoa(MaxMessageLen) {
		t.Fatalf("ack = %q", ack)
	}
	client.Close()
	<-done

	if gotLen != MaxMessageLen {
		t.Fatalf("handler received %d bytes, want %d", gotLen, MaxMessageLen)
	}
}

func TestServeConnRejectsMessageOverTheLimit(t *testing.T) {
	server, client := net.Pipe()

	handlerCalled := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeConn(server, func(addr string, message []byte) {
			handlerCalled <- struct{}{}
		}, discardLogger())
	}()

	// Write well over the limit, in chunks, with no newline anywhere.
	// If readMessage buffered unboundedly this write loop would still
	// finish fine (net.Pipe is synchronous, not a memory question by
	// itself); what this test proves is that ServeConn stops and closes
	// the connection instead of ever calling handler with truncated or
	// oversized data, and does so without hanging.
	go func() {
		chunk := strings.Repeat("b", 4096)
		for i := 0; i < (MaxMessageLen/4096)+4; i++ {
			if _, err := client.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ServeConn did not return for an oversized message")
	}
	select {
	case <-handlerCalled:
		t.Fatal("handler was invoked for an oversized message")
	default:
	}
	client.Close()
}

func TestReadMessageBoundsAllocationRegardlessOfInputLength(t *testing.T) {
	// A reader that never produces a newline and never ends: if
	// readMessage buffered without bound this would hang or grow memory
	// forever. It must instead return ErrMessageTooLarge as soon as the
	// limit is crossed.
	r := newInfiniteReader('x')
	br := bufio.NewReader(r)

	_, err := readMessage(br)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("readMessage on unbounded input = %v, want ErrMessageTooLarge", err)
	}
}

// infiniteReader yields the same byte forever, simulating a peer that
// streams an unterminated message without limit.
type infiniteReader struct {
	b byte
}

func newInfiniteReader(b byte) *infiniteReader { return &infiniteReader{b: b} }

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Send error paths
// ---------------------------------------------------------------------------

func TestSendRejectsOversizedMessageBeforeWriting(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	oversized := strings.Repeat("c", MaxMessageLen+1)
	_, _, err := Send(client, oversized)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Send with oversized message = %v, want ErrMessageTooLarge", err)
	}
}
