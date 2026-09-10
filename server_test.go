package gocloak

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
//
// Every top-level test name in this file contains "TestServer", because the
// verification command is `go test -run TestServer`, which matches by
// substring: a test named otherwise would be silently skipped, not failed.
// ---------------------------------------------------------------------------

// serverTestDialBudget bounds every tunnel dial in this file. A WireGuard
// handshake is not instant, so dials retry, but they always retry under a
// deadline: a broken handshake must fail the test rather than hang it.
const serverTestDialBudget = 25 * time.Second

// serverTestPeer is one peer of the test deployment: its keypair, its PSK,
// its tunnel address, and what peers.yaml should say about it.
type serverTestPeer struct {
	Name   string
	Priv   Secret
	Pub    string
	PSK    Secret
	IP     netip.Addr
	Limits PeerLimits
	Allow  map[string]string

	// PSKMissing makes the peer's psk reference name an environment
	// variable that is never set, so applying the peer fails on secret
	// resolution.
	PSKMissing bool
}

func serverTestNewPeer(t *testing.T, name, ip string) *serverTestPeer {
	t.Helper()
	priv, pub := deviceTestKeypair(t)
	return &serverTestPeer{
		Name:  name,
		Priv:  priv,
		Pub:   pub,
		PSK:   deviceTestPSK(t),
		IP:    netip.MustParseAddr(ip),
		Allow: map[string]string{},
	}
}

// pskRef is the secret reference peers.yaml carries for this peer. It is an
// env: reference so the whole suite runs with no AWS and no network.
func (p *serverTestPeer) pskRef() SecretRef {
	name := strings.ToUpper(strings.ReplaceAll(p.Name, "-", "_"))
	if p.PSKMissing {
		return SecretRef("env:GOCLOAK_TEST_PSK_NEVER_SET_" + name)
	}
	return SecretRef("env:GOCLOAK_TEST_PSK_" + name)
}

// serverTestWritePeers renders peers.yaml and publishes each PSK under the
// environment variable its reference names.
func serverTestWritePeers(t *testing.T, path string, peers []*serverTestPeer) {
	t.Helper()

	var b strings.Builder
	b.WriteString("peers:\n")
	for _, p := range peers {
		if !p.PSKMissing {
			t.Setenv(strings.TrimPrefix(string(p.pskRef()), "env:"), deviceTestB64(p.PSK))
		}

		fmt.Fprintf(&b, "  - name: %s\n", p.Name)
		fmt.Fprintf(&b, "    public_key: %s\n", p.Pub)
		fmt.Fprintf(&b, "    psk: %s\n", p.pskRef())
		fmt.Fprintf(&b, "    tunnel_ip: %s\n", p.IP)
		if p.Limits.MaxConcurrent != 0 || p.Limits.DialsPerSecond != 0 {
			b.WriteString("    limits:\n")
			if p.Limits.MaxConcurrent != 0 {
				fmt.Fprintf(&b, "      max_concurrent: %d\n", p.Limits.MaxConcurrent)
			}
			if p.Limits.DialsPerSecond != 0 {
				fmt.Fprintf(&b, "      dials_per_second: %d\n", p.Limits.DialsPerSecond)
			}
		}
		if len(p.Allow) > 0 {
			b.WriteString("    allow:\n")
			for _, name := range slices.Sorted(maps.Keys(p.Allow)) {
				fmt.Fprintf(&b, "      %s: %s\n", name, p.Allow[name])
			}
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write peers file: %v", err)
	}
}

// serverTestLog is a concurrency-safe sink for the server's JSON log lines.
type serverTestLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *serverTestLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *serverTestLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// serverTestReload is one delivery of the server's post-reload hook.
type serverTestReload struct {
	res ReloadResult
	err error
}

type serverHarness struct {
	t         *testing.T
	srv       *Server
	peersPath string
	udpPort   int
	serverPub string
	logs      *serverTestLog
	reloads   chan serverTestReload
	runErr    chan error
	cancel    context.CancelFunc
	runDone   bool
}

// waitRun waits for Run to return and hands back its error, so a test can
// assert on a Run that stopped on its own rather than on cancellation.
func (h *serverHarness) waitRun(d time.Duration) error {
	h.t.Helper()
	select {
	case err := <-h.runErr:
		h.runDone = true
		return err
	case <-time.After(d):
		h.t.Fatalf("Run did not return within %v", d)
		return nil
	}
}

// serverTestStart writes peers.yaml, starts a real Server on a real
// WireGuard device over localhost UDP, and tears it all down at test end.
func serverTestStart(t *testing.T, peers ...*serverTestPeer) *serverHarness {
	t.Helper()

	peersPath := filepath.Join(t.TempDir(), "peers.yaml")
	serverTestWritePeers(t, peersPath, peers)

	priv, pub := deviceTestKeypair(t)
	t.Setenv("GOCLOAK_TEST_SERVER_PRIV", deviceTestB64(priv))

	port := deviceTestFreeUDPPort(t)
	srv, err := NewServer(ServerConfig{
		ListenPort: port,
		PrivateKey: "env:GOCLOAK_TEST_SERVER_PRIV",
		TunnelIP:   deviceTestServerIP,
		PeersFile:  peersPath,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	h := &serverHarness{
		t:         t,
		srv:       srv,
		peersPath: peersPath,
		udpPort:   port,
		serverPub: pub,
		logs:      &serverTestLog{},
		reloads:   make(chan serverTestReload, 8),
		runErr:    make(chan error, 1),
	}

	// Test seams, all unexported: no AWS, a capturable logger, and a
	// signal that a reload finished being applied to the live device.
	srv.resolver = &SecretResolver{}
	srv.logger = slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv.onReloadApplied = func(r ReloadResult, err error) {
		select {
		case h.reloads <- serverTestReload{res: r, err: err}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.runErr <- srv.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		if h.runDone {
			return
		}
		select {
		case err := <-h.runErr:
			if err != nil {
				t.Errorf("Run returned %v, want nil after cancellation", err)
			}
		case <-time.After(30 * time.Second):
			t.Errorf("Run did not return within 30s of cancellation")
		}
	})
	return h
}

// client brings up a client device for one peer, pointed at the harness's
// server endpoint.
func (h *serverHarness) client(p *serverTestPeer) *tunnelDevice {
	h.t.Helper()

	d, err := newTunnelDevice(deviceOptions{
		TunnelIP:   p.IP,
		PrivateKey: p.Priv,
		LogLevel:   deviceLogSilent,
	})
	if err != nil {
		h.t.Fatalf("client device for %s: %v", p.Name, err)
	}
	h.t.Cleanup(func() { d.Close() })

	if err := d.AddPeer(devicePeer{
		PublicKey:    h.serverPub,
		PresharedKey: p.PSK,
		AllowedIP:    deviceTestServerIP,
		Endpoint:     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.udpPort)),
	}); err != nil {
		h.t.Fatalf("client add server peer: %v", err)
	}
	return d
}

// awaitReload waits for the server to finish applying one reload.
func (h *serverHarness) awaitReload() serverTestReload {
	h.t.Helper()
	select {
	case r := <-h.reloads:
		return r
	case <-time.After(30 * time.Second):
		h.t.Fatal("no reload was applied within 30s of rewriting peers.yaml")
		return serverTestReload{}
	}
}

var serverTestTunnelAddr = netip.AddrPortFrom(deviceTestServerIP, tunnelServicePort)

// serverTestConnect dials the server through the tunnel, retrying under a
// bounded budget while the WireGuard handshake completes.
func serverTestConnect(t *testing.T, d *tunnelDevice) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), serverTestDialBudget)
	defer cancel()
	c, err := deviceTestDialRetry(ctx, d, serverTestTunnelAddr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// serverTestHello connects and performs the hello exchange, returning the
// live connection and the status the server answered with.
func serverTestHello(t *testing.T, d *tunnelDevice, service string) (net.Conn, Status) {
	t.Helper()
	c := serverTestConnect(t, d)
	if err := WriteHelloRequest(c, service); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	status, err := ReadHelloResponse(c)
	if err != nil {
		t.Fatalf("read hello response: %v", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	return c, status
}

// serverTestHelloUntil retries the hello exchange until the server answers
// with want, under a bounded budget. It exists because a dial attempt that
// the client abandoned mid handshake can leave a connection briefly in
// flight on the server, holding a concurrency slot until the hello deadline
// closes it. Retrying on a refusal costs nothing (a refused connection takes
// no slot) and keeps a limit test off the clock.
func serverTestHelloUntil(t *testing.T, d *tunnelDevice, service string, want Status, budget time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last Status
	for {
		conn, status := serverTestHello(t, d, service)
		if status == want {
			return conn
		}
		conn.Close()
		last = status
		if time.Now().After(deadline) {
			t.Fatalf("status = %v after %v of retrying, want %v", last, budget, want)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// serverTestBackend is a real TCP backend on the host network, which is
// where a real backend lives: the server dials it outside the tunnel.
type serverTestBackend struct {
	addr  netip.AddrPort
	conns atomic.Int64
}

func serverTestNewBackend(t *testing.T, handle func(net.Conn)) *serverTestBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	b := &serverTestBackend{addr: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.conns.Add(1)
			go handle(c)
		}
	}()
	return b
}

func (b *serverTestBackend) String() string { return b.addr.String() }

// serverTestEcho echoes every byte back, so a test can assert bytes moved
// in both directions.
func serverTestEcho(c net.Conn) {
	defer c.Close()
	io.Copy(c, c)
}

// serverTestClosedPort returns an address nothing is listening on.
func serverTestClosedPort(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// ---------------------------------------------------------------------------
// end to end
// ---------------------------------------------------------------------------

// TestServerEndToEndBytesFlowBothWays is the whole path: a real WireGuard
// pair, real netstack TCP, a real backend on the host network, and a client
// that names a granted service and exchanges bytes with it.
func TestServerEndToEndBytesFlowBothWays(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()

	h := serverTestStart(t, peer)
	client := h.client(peer)

	conn, status := serverTestHello(t, client, "primary-db")
	if status != StatusOK {
		t.Fatalf("status = %v, want ok", status)
	}

	if err := conn.SetDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write to backend: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := readFullConn(conn, buf); err != nil {
		t.Fatalf("read from backend: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q from the backend, want %q", buf, "ping")
	}
	if got := backend.conns.Load(); got != 1 {
		t.Fatalf("backend saw %d connections, want 1", got)
	}
}

// TestServerDeniedServiceIsRefusedAndNeverDialsABackend asserts a denial is
// a denial: status 0x01 and not a single byte to any backend.
func TestServerDeniedServiceIsRefusedAndNeverDialsABackend(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()

	h := serverTestStart(t, peer)
	client := h.client(peer)

	_, status := serverTestHello(t, client, "cache")
	if status != StatusDenied {
		t.Fatalf("status = %v, want denied", status)
	}
	if got := backend.conns.Load(); got != 0 {
		t.Fatalf("backend saw %d connections, want 0: a denied request must never reach a backend", got)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "app-01") || !strings.Contains(logs, "cache") {
		t.Fatalf("denial was not logged as a security event with peer and service; logs:\n%s", logs)
	}
}

// TestServerPeerCannotReachAnotherPeersService is the cross-peer case from
// spec section 9: both peers grant the same service name, pointing at
// different backends, and each peer reaches only its own.
func TestServerPeerCannotReachAnotherPeersService(t *testing.T) {
	backendA := serverTestNewBackend(t, func(c net.Conn) { defer c.Close(); c.Write([]byte("AAAA")) })
	backendB := serverTestNewBackend(t, func(c net.Conn) { defer c.Close(); c.Write([]byte("BBBB")) })

	peerA := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peerA.Allow["db"] = backendA.String()
	peerA.Allow["only-a"] = backendA.String()

	peerB := serverTestNewPeer(t, "app-b", "10.99.0.8")
	peerB.Allow["db"] = backendB.String()

	h := serverTestStart(t, peerA, peerB)
	clientA := h.client(peerA)
	clientB := h.client(peerB)

	read4 := func(c net.Conn) string {
		t.Helper()
		if err := c.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buf := make([]byte, 4)
		if _, err := readFullConn(c, buf); err != nil {
			t.Fatalf("read from backend: %v", err)
		}
		return string(buf)
	}

	connA, statusA := serverTestHello(t, clientA, "db")
	if statusA != StatusOK {
		t.Fatalf("peer A status = %v, want ok", statusA)
	}
	if got := read4(connA); got != "AAAA" {
		t.Fatalf("peer A reached %q, want its own backend AAAA", got)
	}

	connB, statusB := serverTestHello(t, clientB, "db")
	if statusB != StatusOK {
		t.Fatalf("peer B status = %v, want ok", statusB)
	}
	if got := read4(connB); got != "BBBB" {
		t.Fatalf("peer B reached %q, want its own backend BBBB", got)
	}

	// A service only peer A is granted is denied to peer B, and peer B
	// never touches peer A's backend.
	before := backendA.conns.Load()
	if _, status := serverTestHello(t, clientB, "only-a"); status != StatusDenied {
		t.Fatalf("peer B asking for peer A's service: status = %v, want denied", status)
	}
	if after := backendA.conns.Load(); after != before {
		t.Fatalf("peer A's backend saw %d new connections from peer B, want 0", after-before)
	}
}

// TestServerBackendUnavailableIsDistinctFromDenied covers spec section 8.2:
// a granted service whose backend is down answers 0x02, not 0x01, so the
// application can tell "denied" from "the database is down".
func TestServerBackendUnavailableIsDistinctFromDenied(t *testing.T) {
	dead := serverTestClosedPort(t)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = dead.String()

	h := serverTestStart(t, peer)
	client := h.client(peer)

	_, status := serverTestHello(t, client, "primary-db")
	if status != StatusBackendUnavailable {
		t.Fatalf("status = %v, want backend unavailable", status)
	}
}

// TestServerMalformedHelloFrameIsAnswered checks that a frame the parser
// rejects gets 0x04 and a close, rather than silence.
func TestServerMalformedHelloFrameIsAnswered(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	// The limiter runs before the hello read, so the peer needs budget to
	// reach the parser at all.
	peer.Limits = PeerLimits{MaxConcurrent: 8, DialsPerSecond: 8}
	h := serverTestStart(t, peer)
	client := h.client(peer)

	conn := serverTestConnect(t, client)
	// Version 0x02 is not a version this protocol has.
	if _, err := conn.Write([]byte{0x02, 0x01, 'x'}); err != nil {
		t.Fatalf("write malformed frame: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp[0] != 0x01 || Status(resp[1]) != StatusMalformed {
		t.Fatalf("response = %#v, want version 0x01 and status malformed", resp)
	}
}

// TestServerSilentPeerIsClosedByTheDeadlineWithNoResponse asserts the other
// half of the malformed rule: a peer that sends nothing at all gets zero
// bytes back. There is nothing to respond to, so nothing is emitted.
func TestServerSilentPeerIsClosedByTheDeadlineWithNoResponse(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	h := serverTestStart(t, peer)
	client := h.client(peer)

	conn := serverTestConnect(t, client)

	// Generously past HelloReadDeadline, so the close is the deadline's
	// doing and the read below is not the thing that gave up first.
	if err := conn.SetReadDeadline(time.Now().Add(HelloReadDeadline + 20*time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("server sent %d bytes (%#v) to a peer that said nothing, want 0", n, buf[:n])
	}
	if err == nil {
		t.Fatal("read returned no error, want the connection to have been closed")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection was still open after %v; the hello read deadline did not close it", HelloReadDeadline)
	}
}

// ---------------------------------------------------------------------------
// rate limits
// ---------------------------------------------------------------------------

// TestServerMaxConcurrentIsEnforced holds one connection open against a
// max_concurrent of 1 and asserts the second is rate limited.
func TestServerMaxConcurrentIsEnforced(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()
	peer.Limits = PeerLimits{MaxConcurrent: 1, DialsPerSecond: 100}

	h := serverTestStart(t, peer)
	client := h.client(peer)

	first := serverTestHelloUntil(t, client, "primary-db", StatusOK, 15*time.Second)
	defer first.Close()

	if _, status := serverTestHello(t, client, "primary-db"); status != StatusRateLimited {
		t.Fatalf("second status = %v, want rate limited", status)
	}
}

// TestServerMaxConcurrentBoundsConnectionsThatSendNothing is the property
// the cap exists for. Every accepted connection costs a goroutine, a
// netstack connection and a file descriptor from the moment it is accepted,
// and a peer that says nothing holds all of that for the whole hello
// deadline. So the cap has to be applied before the hello read: if it were
// applied after, a peer could hold an unbounded number of connections in
// flight and starve every other peer, and max_concurrent would bound
// nothing at all.
func TestServerMaxConcurrentBoundsConnectionsThatSendNothing(t *testing.T) {
	const maxConcurrent = 3

	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()
	peer.Limits = PeerLimits{MaxConcurrent: maxConcurrent, DialsPerSecond: 100}

	h := serverTestStart(t, peer)
	client := h.client(peer)

	// Warm the tunnel up with a completed exchange, so the dials below
	// are immediate and the handshake is not part of the timing.
	serverTestHelloUntil(t, client, "primary-db", StatusOK, 15*time.Second).Close()

	// Open the cap's worth of connections that send nothing at all. Each
	// one sits on the hello deadline, which is five seconds, so they are
	// all still in flight for the assertion below.
	silent := make([]net.Conn, 0, maxConcurrent)
	for i := 0; i < maxConcurrent; i++ {
		silent = append(silent, serverTestConnect(t, client))
	}
	defer func() {
		for _, c := range silent {
			c.Close()
		}
	}()

	// One more connection, this one asking for a service it is granted.
	// The slots are all held by peers that have said nothing, so it must
	// be refused rather than served.
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, status := serverTestHello(t, client, "primary-db")
		conn.Close()
		if status == StatusRateLimited {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection %d status = %v, want rate limited: %d silent connections are in flight against a cap of %d, so the cap is bounding nothing",
				maxConcurrent+1, status, maxConcurrent, maxConcurrent)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Closing the silent connections frees their slots, so the cap is a
	// cap and not a permanent lockout.
	for _, c := range silent {
		c.Close()
	}
	serverTestHelloUntil(t, client, "primary-db", StatusOK, 15*time.Second).Close()
}

// TestServerDialsPerSecondIsEnforced sets a bucket of one dial per second
// and asserts the second dial inside that second is rate limited.
func TestServerDialsPerSecondIsEnforced(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()
	peer.Limits = PeerLimits{MaxConcurrent: 64, DialsPerSecond: 1}

	h := serverTestStart(t, peer)
	client := h.client(peer)

	// A burst of dials against a bucket of one per second: the first is
	// allowed and the bucket is then empty. Four attempts back to back
	// take milliseconds, so the bucket cannot refill in the middle of
	// them, but asserting on the burst rather than on one exact attempt
	// keeps the test off the clock.
	serverTestHelloUntil(t, client, "primary-db", StatusOK, 15*time.Second).Close()

	var statuses []Status
	for i := 0; i < 3; i++ {
		conn, status := serverTestHello(t, client, "primary-db")
		conn.Close()
		statuses = append(statuses, status)
	}

	limited := 0
	for _, st := range statuses {
		if st == StatusRateLimited {
			limited++
		}
	}
	if limited == 0 {
		t.Fatalf("statuses = %v, want at least one rate limited after the bucket emptied", statuses)
	}
}

// TestServerRateLimitIsCheckedBeforePolicy asserts the ordering the brief
// requires: a peer over its limit cannot use denied lookups as a free
// hammer, so an unauthorized service name is answered 0x03, not 0x01.
//
// The cap used is max_concurrent rather than dials_per_second, because a
// held connection is a fact rather than a race against the token bucket's
// refill.
func TestServerRateLimitIsCheckedBeforePolicy(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()
	peer.Limits = PeerLimits{MaxConcurrent: 1, DialsPerSecond: 100}

	h := serverTestStart(t, peer)
	client := h.client(peer)

	first := serverTestHelloUntil(t, client, "primary-db", StatusOK, 15*time.Second)
	defer first.Close()

	if _, status := serverTestHello(t, client, "not-granted"); status != StatusRateLimited {
		t.Fatalf("status = %v, want rate limited: the limiter must run before policy resolution", status)
	}
}

// TestServerLimiterAccounting unit-tests the limiter itself, including the
// refill and the release of a concurrency slot.
func TestServerLimiterAccounting(t *testing.T) {
	l := newPeerLimiter(PeerLimits{MaxConcurrent: 2, DialsPerSecond: 2})
	now := time.Now()

	if reason, ok := l.acquire(now); !ok {
		t.Fatalf("first acquire refused (%s), want allowed", reason)
	}
	if reason, ok := l.acquire(now); !ok {
		t.Fatalf("second acquire refused (%s), want allowed", reason)
	}
	if reason, ok := l.acquire(now); ok || reason != "dials_per_second" {
		t.Fatalf("third acquire = (%s, %v), want refused for dials_per_second", reason, ok)
	}

	// A second later the bucket has refilled, but both concurrency slots
	// are still held.
	later := now.Add(time.Second)
	if reason, ok := l.acquire(later); ok || reason != "max_concurrent" {
		t.Fatalf("acquire with slots full = (%s, %v), want refused for max_concurrent", reason, ok)
	}

	l.release()
	if reason, ok := l.acquire(later.Add(time.Second)); !ok {
		t.Fatalf("acquire after release refused (%s), want allowed", reason)
	}

	// Tokens never accumulate beyond the burst.
	l.release()
	l.release()
	if reason, ok := l.acquire(later.Add(time.Hour)); !ok {
		t.Fatalf("acquire after a long idle refused (%s), want allowed", reason)
	}
	if reason, ok := l.acquire(later.Add(time.Hour)); !ok {
		t.Fatalf("second acquire after a long idle refused (%s), want allowed", reason)
	}
	if reason, ok := l.acquire(later.Add(time.Hour)); ok || reason != "dials_per_second" {
		t.Fatalf("third acquire = (%s, %v), want refused: the bucket must be capped at the burst", reason, ok)
	}
}

// ---------------------------------------------------------------------------
// hot reload and revocation
// ---------------------------------------------------------------------------

// TestServerHotReloadRevokesAPeer rewrites peers.yaml with a peer removed
// and asserts that peer can no longer establish anything, while the peer
// that stayed still can.
func TestServerHotReloadRevokesAPeer(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peerA := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peerA.Allow["db"] = backend.String()
	peerB := serverTestNewPeer(t, "app-b", "10.99.0.8")
	peerB.Allow["db"] = backend.String()

	h := serverTestStart(t, peerA, peerB)
	clientA := h.client(peerA)
	clientB := h.client(peerB)

	// Both peers work before the revocation, so the failure afterwards is
	// attributable to the revocation and not to a broken harness.
	if conn, status := serverTestHello(t, clientA, "db"); status != StatusOK {
		t.Fatalf("peer A before revocation: status = %v, want ok", status)
	} else {
		conn.Close()
	}
	if conn, status := serverTestHello(t, clientB, "db"); status != StatusOK {
		t.Fatalf("peer B before revocation: status = %v, want ok", status)
	} else {
		conn.Close()
	}

	serverTestWritePeers(t, h.peersPath, []*serverTestPeer{peerB})

	got := h.awaitReload()
	if got.res.Err != nil {
		t.Fatalf("reload reported an error: %v", got.res.Err)
	}
	if got.err != nil {
		t.Fatalf("applying the reload to the device failed: %v", got.err)
	}
	if len(got.res.Diff.Removed) != 1 || got.res.Diff.Removed[0].Name != "app-a" {
		t.Fatalf("diff removed %v, want exactly app-a", peerNames(got.res.Diff.Removed))
	}

	// The revoked peer's keypair is gone from the device, so its packets
	// are dropped and the dial can only time out.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := deviceTestDialRetry(ctx, clientA, serverTestTunnelAddr)
	if err == nil {
		conn.Close()
		t.Fatal("the revoked peer still established a connection")
	}

	// The peer that stayed is unaffected.
	if conn, status := serverTestHello(t, clientB, "db"); status != StatusOK {
		t.Fatalf("peer B after revocation: status = %v, want ok", status)
	} else {
		conn.Close()
	}
}

// TestServerRevocationClosesInFlightProxiedConnections covers the server
// side of spec section 8.2's "existing conns error out".
//
// TestSecurityRevokedPeerCanNoLongerConnect closes its connections before it
// revokes, so it proves only that a revoked peer cannot establish anything
// new. It cannot see what happens to a connection that is still proxying at
// the instant of the revocation, and that is the case this test holds open:
// removing the peer stops it sending, but an established connection is a raw
// pipe with its deadlines cleared, so without an explicit reap its backend
// connection and both file descriptors stay open indefinitely and the peer's
// concurrency slot is never returned.
//
// The two assertions are made server side on purpose. The revoked peer's
// keypair is destroyed moments after the reap, so whether the FIN reaches the
// client is a race on the wire and not a property worth asserting. What the
// server owes is that the handler unwound and the backend socket was let go,
// and both of those are observable here without racing anything.
func TestServerRevocationClosesInFlightProxiedConnections(t *testing.T) {
	doomedReleased := make(chan struct{})
	var releaseOnce sync.Once
	doomedBackend := serverTestNewBackend(t, func(c net.Conn) {
		defer c.Close()
		io.Copy(c, c)
		releaseOnce.Do(func() { close(doomedReleased) })
	})
	survivorBackend := serverTestNewBackend(t, serverTestEcho)

	doomed := serverTestNewPeer(t, "app-doomed", "10.99.0.7")
	doomed.Allow["db"] = doomedBackend.String()
	survivor := serverTestNewPeer(t, "app-survivor", "10.99.0.8")
	survivor.Allow["db"] = survivorBackend.String()

	h := serverTestStart(t, doomed, survivor)
	doomedClient := h.client(doomed)
	survivorClient := h.client(survivor)

	// exchange proves the connection is a working proxy, not merely a
	// connection the server said ok to. A reap test whose "before" state
	// never carried bytes proves nothing.
	exchange := func(conn net.Conn, who string) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
			t.Fatalf("%s: set deadline: %v", who, err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("%s: write to backend: %v", who, err)
		}
		buf := make([]byte, 4)
		if _, err := readFullConn(conn, buf); err != nil {
			t.Fatalf("%s: read from backend: %v", who, err)
		}
		if string(buf) != "ping" {
			t.Fatalf("%s: backend echoed %q, want %q", who, buf, "ping")
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			t.Fatalf("%s: clear deadline: %v", who, err)
		}
	}

	doomedConn, status := serverTestHello(t, doomedClient, "db")
	if status != StatusOK {
		t.Fatalf("doomed peer: status = %v, want ok", status)
	}
	exchange(doomedConn, "doomed peer before revocation")

	survivorConn, status := serverTestHello(t, survivorClient, "db")
	if status != StatusOK {
		t.Fatalf("surviving peer: status = %v, want ok", status)
	}
	exchange(survivorConn, "surviving peer before revocation")

	if got := doomedBackend.conns.Load(); got != 1 {
		t.Fatalf("doomed backend saw %d connections, want 1", got)
	}

	// Revoke through the real peers.yaml hot reload path, with both
	// connections still open and still in the middle of their session.
	serverTestWritePeers(t, h.peersPath, []*serverTestPeer{survivor})

	got := h.awaitReload()
	if got.res.Err != nil {
		t.Fatalf("reload reported a parse error: %v", got.res.Err)
	}
	if got.err != nil {
		t.Fatalf("applying the reload to the live device failed: %v", got.err)
	}
	if names := peerNames(got.res.Diff.Removed); len(names) != 1 || names[0] != "app-doomed" {
		t.Fatalf("diff removed %v, want exactly [app-doomed]", names)
	}

	// 1. The backend connection is released, so the file descriptor and
	//    whatever the backend was holding for that session are freed.
	select {
	case <-doomedReleased:
	case <-time.After(20 * time.Second):
		t.Fatal("the revoked peer's backend connection was never released: an in-flight proxied connection outlived the revocation")
	}

	// 2. The handler unwound. handleConn logs this line only after
	//    pipeConns has returned, which happens only once both sides of the
	//    proxy are closed, so the line is proof the peer-side connection
	//    was closed and the concurrency slot returned.
	if !serverTestAwaitLogLine(t, h, `"gocloak: connection closed"`, `"peer":"app-doomed"`, 20*time.Second) {
		t.Fatalf("the revoked peer's connection handler never unwound; logs:\n%s", h.logs.String())
	}

	// The surviving peer is untouched, so the reap closed one peer's
	// connections rather than everything on the device.
	exchange(survivorConn, "surviving peer after revocation")
}

// serverTestAwaitLogLine polls the captured log for a single line containing
// every one of want, and reports whether it appeared within budget.
func serverTestAwaitLogLine(t *testing.T, h *serverHarness, first, second string, budget time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		for line := range strings.SplitSeq(h.logs.String(), "\n") {
			if strings.Contains(line, first) && strings.Contains(line, second) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServerHotReloadAddsAPeer covers the other direction: a peer added to
// the file becomes usable without a restart.
func TestServerHotReloadAddsAPeer(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peerA := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peerA.Allow["db"] = backend.String()
	peerB := serverTestNewPeer(t, "app-b", "10.99.0.8")
	peerB.Allow["db"] = backend.String()

	h := serverTestStart(t, peerA)
	clientB := h.client(peerB)

	serverTestWritePeers(t, h.peersPath, []*serverTestPeer{peerA, peerB})

	got := h.awaitReload()
	if got.res.Err != nil || got.err != nil {
		t.Fatalf("reload failed: res.Err=%v applyErr=%v", got.res.Err, got.err)
	}
	if len(got.res.Diff.Added) != 1 || got.res.Diff.Added[0].Name != "app-b" {
		t.Fatalf("diff added %v, want exactly app-b", peerNames(got.res.Diff.Added))
	}

	if conn, status := serverTestHello(t, clientB, "db"); status != StatusOK {
		t.Fatalf("added peer: status = %v, want ok", status)
	} else {
		conn.Close()
	}
}

// TestServerHotReloadKeepsPreviousPolicyOnABadFile covers spec section 8.2:
// a malformed peers.yaml must neither revoke everyone nor widen access.
func TestServerHotReloadKeepsPreviousPolicyOnABadFile(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()

	h := serverTestStart(t, peer)
	client := h.client(peer)

	if conn, status := serverTestHello(t, client, "primary-db"); status != StatusOK {
		t.Fatalf("before the bad reload: status = %v, want ok", status)
	} else {
		conn.Close()
	}

	if err := os.WriteFile(h.peersPath, []byte("peers:\n  - name: app-01\n    not_a_key: 1\n"), 0o600); err != nil {
		t.Fatalf("write bad peers file: %v", err)
	}

	got := h.awaitReload()
	if got.res.Err == nil {
		t.Fatal("a peers file with an unknown key reloaded successfully, want an error")
	}

	if conn, status := serverTestHello(t, client, "primary-db"); status != StatusOK {
		t.Fatalf("after the bad reload: status = %v, want ok: the previous policy must stay in force", status)
	} else {
		conn.Close()
	}

	if logs := h.logs.String(); !strings.Contains(logs, "reload") {
		t.Fatalf("the failed reload was not logged; logs:\n%s", logs)
	}
}

// ---------------------------------------------------------------------------
// startup, fail closed
// ---------------------------------------------------------------------------

// TestServerStartupFailsWhenThePrivateKeyCannotBeResolved is spec section
// 8.2's first row: an unavailable secret store must stop the server, not
// start it degraded.
func TestServerStartupFailsWhenThePrivateKeyCannotBeResolved(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peersPath := filepath.Join(t.TempDir(), "peers.yaml")
	serverTestWritePeers(t, peersPath, []*serverTestPeer{peer})

	srv, err := NewServer(ServerConfig{
		ListenPort: deviceTestFreeUDPPort(t),
		PrivateKey: "env:GOCLOAK_TEST_KEY_THAT_IS_NOT_SET",
		TunnelIP:   deviceTestServerIP,
		PeersFile:  peersPath,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.resolver = &SecretResolver{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run returned nil, want an error when the private key cannot be resolved")
		}
		if !strings.Contains(err.Error(), "private key") {
			t.Fatalf("Run error = %v, want it to name the private key", err)
		}
		if strings.Contains(err.Error(), "GOCLOAK_TEST_KEY_THAT_IS_NOT_SET") {
			t.Fatalf("Run error echoes the secret reference: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Run did not return; it must fail closed rather than serve")
	}
}

// TestServerStartupFailsWhenAPeerPSKCannotBeResolved is the same rule one
// level down: a peer whose PSK is unavailable must stop startup rather than
// come up without that peer, or worse, without a PSK.
func TestServerStartupFailsWhenAPeerPSKCannotBeResolved(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peersPath := filepath.Join(t.TempDir(), "peers.yaml")
	serverTestWritePeers(t, peersPath, []*serverTestPeer{peer})
	// Take the PSK away after the file is written.
	os.Unsetenv(strings.TrimPrefix(string(peer.pskRef()), "env:"))

	priv, _ := deviceTestKeypair(t)
	t.Setenv("GOCLOAK_TEST_SERVER_PRIV", deviceTestB64(priv))

	srv, err := NewServer(ServerConfig{
		ListenPort: deviceTestFreeUDPPort(t),
		PrivateKey: "env:GOCLOAK_TEST_SERVER_PRIV",
		TunnelIP:   deviceTestServerIP,
		PeersFile:  peersPath,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.resolver = &SecretResolver{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run returned nil, want an error when a peer PSK cannot be resolved")
		}
		if !strings.Contains(err.Error(), "app-01") {
			t.Fatalf("Run error = %v, want it to name the peer", err)
		}
	case <-ctx.Done():
		t.Fatal("Run did not return; it must fail closed rather than serve")
	}
}

// TestServerRefusesToStartOnABadConfig covers the constructor's checks. An
// invalid peers file at startup is the one moment with no previous good
// config to fall back to, so it must refuse to start.
func TestServerRefusesToStartOnABadConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "peers.yaml")
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	serverTestWritePeers(t, good, []*serverTestPeer{peer})

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("peers:\n  - name: app-01\n    surprise: yes\n"), 0o600); err != nil {
		t.Fatalf("write bad peers file: %v", err)
	}

	base := ServerConfig{
		ListenPort: 51820,
		PrivateKey: "env:GOCLOAK_TEST_SERVER_PRIV",
		TunnelIP:   deviceTestServerIP,
		PeersFile:  good,
	}

	cases := []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{"zero port", func(c *ServerConfig) { c.ListenPort = 0 }},
		{"port out of range", func(c *ServerConfig) { c.ListenPort = 70000 }},
		{"empty private key", func(c *ServerConfig) { c.PrivateKey = "" }},
		{"literal private key", func(c *ServerConfig) { c.PrivateKey = "aGVsbG8gd29ybGQ=" }},
		{"zero tunnel ip", func(c *ServerConfig) { c.TunnelIP = netip.Addr{} }},
		{"wrong tunnel ip", func(c *ServerConfig) { c.TunnelIP = netip.MustParseAddr("10.99.0.7") }},
		{"mtu too small", func(c *ServerConfig) { c.MTU = 576 }},
		{"mtu too large", func(c *ServerConfig) { c.MTU = 9000 }},
		{"no peers file", func(c *ServerConfig) { c.PeersFile = "" }},
		{"missing peers file", func(c *ServerConfig) { c.PeersFile = filepath.Join(dir, "nope.yaml") }},
		{"invalid peers file", func(c *ServerConfig) { c.PeersFile = bad }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			srv, err := NewServer(cfg)
			if err == nil {
				t.Fatalf("NewServer accepted %s", tc.name)
			}
			if srv != nil {
				t.Fatal("NewServer returned a non-nil server alongside an error")
			}
		})
	}

	if _, err := NewServer(base); err != nil {
		t.Fatalf("NewServer rejected the control config: %v", err)
	}
}

// TestServerConfigFromFileConfig checks the mapping the daemon uses to get
// from server.yaml to a ServerConfig.
func TestServerConfigFromFileConfig(t *testing.T) {
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.yaml")
	serverPath := filepath.Join(dir, "server.yaml")

	yaml := fmt.Sprintf("listen_port: 51820\nprivate_key: aws:sm:gocloak/server/private\ntunnel_ip: 10.99.0.1\nmtu: 1300\npeers_file: %s\nlog_format: json\n", peersPath)
	if err := os.WriteFile(serverPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write server.yaml: %v", err)
	}

	fc, err := LoadServerConfig(serverPath)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}

	got := ServerConfigFrom(fc)
	want := ServerConfig{
		ListenPort: 51820,
		PrivateKey: "aws:sm:gocloak/server/private",
		TunnelIP:   deviceTestServerIP,
		MTU:        1300,
		PeersFile:  peersPath,
	}
	if got != want {
		t.Fatalf("ServerConfigFrom = %+v, want %+v", got, want)
	}

	if zero := ServerConfigFrom(nil); zero != (ServerConfig{}) {
		t.Fatalf("ServerConfigFrom(nil) = %+v, want the zero config, which NewServer then rejects", zero)
	}
	if _, err := NewServer(ServerConfigFrom(nil)); err == nil {
		t.Fatal("NewServer accepted the zero config")
	}
}

// ---------------------------------------------------------------------------
// identity and logging
// ---------------------------------------------------------------------------

// TestServerRemoteTunnelIPUnmapsIPv4In6 pins the identity derivation.
// netstack hands back a 4-in-6 address, and an unnormalized one would miss
// every policy entry, which fails closed but for the wrong reason.
func TestServerRemoteTunnelIPUnmapsIPv4In6(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
		ok   bool
	}{
		{"ipv4", &net.TCPAddr{IP: net.ParseIP("10.99.0.7"), Port: 1234}, "10.99.0.7", true},
		{"ipv4 in ipv6", &net.TCPAddr{IP: net.ParseIP("::ffff:10.99.0.7"), Port: 1234}, "10.99.0.7", true},
		{"nil address", nil, "", false},
		{"unparsable", serverTestFakeAddr("not-an-address"), "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := remoteTunnelIP(serverTestConnWithAddr{addr: tc.addr})
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got.String() != tc.want {
				t.Fatalf("addr = %s, want %s", got, tc.want)
			}
		})
	}
}

// serverTestFakeAddr is a net.Addr whose String is not an address.
type serverTestFakeAddr string

func (a serverTestFakeAddr) Network() string { return "tcp" }
func (a serverTestFakeAddr) String() string  { return string(a) }

// serverTestConnWithAddr is a net.Conn that only answers RemoteAddr.
type serverTestConnWithAddr struct {
	net.Conn
	addr net.Addr
}

func (c serverTestConnWithAddr) RemoteAddr() net.Addr { return c.addr }

// TestServerUnknownTunnelIPLogsAsLiteralUnknown asserts an address with no
// peer entry never puts attacker-influenced text in a log line.
func TestServerUnknownTunnelIPLogsAsLiteralUnknown(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peersPath := filepath.Join(t.TempDir(), "peers.yaml")
	serverTestWritePeers(t, peersPath, []*serverTestPeer{peer})

	srv, err := NewServer(ServerConfig{
		ListenPort: deviceTestFreeUDPPort(t),
		PrivateKey: "env:GOCLOAK_TEST_SERVER_PRIV",
		TunnelIP:   deviceTestServerIP,
		PeersFile:  peersPath,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if got := srv.peerName(netip.MustParseAddr("10.99.0.200")); got != "unknown" {
		t.Fatalf("peerName for an unconfigured address = %q, want %q", got, "unknown")
	}
}

// TestServerScrubRefRedactsPayloadAndKeepsUnwrap covers the scrubbing that
// keeps a secret reference out of a log line. secret.go wraps the
// underlying os and AWS errors, which repeat the bare path or id without
// the scheme prefix, so scrubbing only the whole reference would leave the
// path in the message.
func TestServerScrubRefRedactsPayloadAndKeepsUnwrap(t *testing.T) {
	if got := scrubRef(nil, "env:X"); got != nil {
		t.Fatalf("scrubRef(nil) = %v, want nil", got)
	}

	path := filepath.Join(t.TempDir(), "psk-that-does-not-exist")
	ref := SecretRef("file:" + path)

	resolver := &SecretResolver{}
	_, err := resolver.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("resolving a missing file succeeded, want an error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("test bug: the unscrubbed error %q does not contain the path, so the assertion below is vacuous", err)
	}

	scrubbed := scrubRef(err, ref)
	if strings.Contains(scrubbed.Error(), path) {
		t.Fatalf("scrubbed error still contains the path: %v", scrubbed)
	}
	if strings.Contains(scrubbed.Error(), string(ref)) {
		t.Fatalf("scrubbed error still contains the reference: %v", scrubbed)
	}
	if !strings.Contains(scrubbed.Error(), redactedRefPlaceholder) {
		t.Fatalf("scrubbed error = %q, want it to carry %q", scrubbed, redactedRefPlaceholder)
	}
	if !errors.Is(scrubbed, os.ErrNotExist) {
		t.Fatalf("errors.Is(scrubbed, os.ErrNotExist) = false: scrubbing must not break the error chain")
	}

	// An env reference, whose payload is the whole tail of the reference.
	envRef := SecretRef("env:GOCLOAK_TEST_REF_NEVER_SET")
	_, enverr := resolver.Resolve(context.Background(), envRef)
	if enverr == nil {
		t.Fatal("resolving an unset variable succeeded, want an error")
	}
	if got := scrubRef(enverr, envRef); strings.Contains(got.Error(), "GOCLOAK_TEST_REF_NEVER_SET") {
		t.Fatalf("scrubbed error still names the variable: %v", got)
	}
}

// TestServerLogsNeverContainKeyMaterial runs a full connection lifecycle
// with a capturing logger and asserts constraint 4 holds across all of it:
// no private key, no PSK, no secret reference, no public key, no payload.
func TestServerLogsNeverContainKeyMaterial(t *testing.T) {
	const payload = "SUPERSECRETPAYLOADBYTES"

	backend := serverTestNewBackend(t, serverTestEcho)

	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	peer.Allow["primary-db"] = backend.String()

	h := serverTestStart(t, peer)
	client := h.client(peer)

	// The whole lifecycle, all of it logged: a granted connection with
	// real bytes, a denial, a malformed frame, a reload, and a reload
	// whose peer PSK cannot be resolved, which is the one path that puts
	// a scrubbed secret reference into a log line.
	conn, status := serverTestHello(t, client, "primary-db")
	if status != StatusOK {
		t.Fatalf("status = %v, want ok", status)
	}
	if err := conn.SetDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := readFullConn(conn, buf); err != nil {
		t.Fatalf("read payload back: %v", err)
	}
	conn.Close()

	if _, status := serverTestHello(t, client, "cache"); status != StatusDenied {
		t.Fatalf("denied status = %v, want denied", status)
	}

	// A malformed frame, which is logged with its own status.
	malformed := serverTestConnect(t, client)
	if _, err := malformed.Write([]byte{0x02, 0x01, 'x'}); err != nil {
		t.Fatalf("write malformed frame: %v", err)
	}
	if err := malformed.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(malformed, resp[:]); err != nil {
		t.Fatalf("read malformed response: %v", err)
	}
	if Status(resp[1]) != StatusMalformed {
		t.Fatalf("malformed status = %v, want malformed", Status(resp[1]))
	}
	malformed.Close()

	// A reload that adds a peer whose PSK reference resolves to nothing.
	// Applying it fails, and the failure is logged with the error from
	// the secret resolver, which is where a reference would leak if it
	// were not scrubbed.
	broken := serverTestNewPeer(t, "app-02", "10.99.0.8")
	broken.PSKMissing = true
	serverTestWritePeers(t, h.peersPath, []*serverTestPeer{peer, broken})

	got := h.awaitReload()
	if got.res.Err != nil {
		t.Fatalf("reload error: %v", got.res.Err)
	}
	if got.err == nil {
		t.Fatal("applying a peer whose PSK cannot be resolved reported success, want an error")
	}
	if strings.Contains(got.err.Error(), string(broken.pskRef())) {
		t.Fatalf("the apply error echoes the secret reference: %v", got.err)
	}

	logs := h.logs.String()
	if logs == "" {
		t.Fatal("no logs were captured, so this test would pass vacuously")
	}

	serverPrivB64 := os.Getenv("GOCLOAK_TEST_SERVER_PRIV")
	forbidden := map[string]string{
		"server private key":    serverPrivB64,
		"server public key":     h.serverPub,
		"peer preshared key":    deviceTestB64(peer.PSK),
		"peer public key":       peer.Pub,
		"peer psk reference":    string(peer.pskRef()),
		"private key reference": "env:GOCLOAK_TEST_SERVER_PRIV",
		"payload":               payload,
		"broken psk reference":  string(broken.pskRef()),
		"broken psk payload":    strings.TrimPrefix(string(broken.pskRef()), "env:"),
	}
	for what, secret := range forbidden {
		if secret == "" {
			t.Fatalf("test bug: %s is empty, so the assertion below is vacuous", what)
		}
		if strings.Contains(logs, secret) {
			t.Fatalf("logs contain the %s; logs:\n%s", what, logs)
		}
	}

	// The fields that must be there, including the scrubbed placeholder,
	// which proves the failing apply really did reach a log line.
	for _, want := range []string{"app-01", "app-02", "primary-db", "bytes_sent", "bytes_received", "duration_ms",
		StatusMalformed.String(), redactedRefPlaceholder} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs do not contain %q; logs:\n%s", want, logs)
		}
	}
}

// TestServerADeadPeerWatchIsFatal asserts the server stops rather than
// keeps serving with a peer list that can no longer change. A watch that
// has died means revocation has stopped working, which is the one failure
// this design can least afford to survive quietly.
func TestServerADeadPeerWatchIsFatal(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	h := serverTestStart(t, peer)

	// One exchange first, so the server is provably up and serving.
	if _, status := serverTestHello(t, h.client(peer), "nothing-granted"); status != StatusDenied {
		t.Fatalf("status = %v, want denied", status)
	}

	// Kill the filesystem watch out from under the watcher.
	if err := h.srv.watcher.Close(); err != nil {
		t.Fatalf("close watcher: %v", err)
	}

	err := h.waitRun(30 * time.Second)
	if err == nil {
		t.Fatal("Run returned nil after the peers file watch died, want an error")
	}
	if !strings.Contains(err.Error(), "watch") {
		t.Fatalf("Run error = %v, want it to name the watch", err)
	}
}

// TestServerRunIsSingleUse asserts a second Run is refused rather than
// bringing up a second device on the same port.
func TestServerRunIsSingleUse(t *testing.T) {
	peer := serverTestNewPeer(t, "app-01", "10.99.0.7")
	h := serverTestStart(t, peer)

	// Complete one exchange first, so the harness's Run is provably the
	// call that took the single-use flag.
	if _, status := serverTestHello(t, h.client(peer), "nothing-granted"); status != StatusDenied {
		t.Fatalf("status = %v, want denied", status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.srv.Run(ctx); err == nil {
		t.Fatal("a second Run returned nil, want an error")
	}
}
