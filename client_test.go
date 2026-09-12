package gocloak

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
//
// Every top-level test name in this file contains "TestClient", because the
// verification command is `go test -run TestClient`, which matches by
// substring: a test named otherwise would be silently skipped, not failed.
// ---------------------------------------------------------------------------

// clientTestDialBudget bounds every successful tunnel dial in this file. A
// WireGuard handshake is not instant, so Dial retries internally, but always
// under a deadline: a broken handshake must fail the test, never hang it.
const clientTestDialBudget = 25 * time.Second

// clientTestFailBudget is the DialTimeout used by the tests that expect a
// handshake to never complete. It is short so the suite stays lean, and far
// longer than a working localhost handshake needs, so a pass is meaningful.
const clientTestFailBudget = 3 * time.Second

// clientTestPrivRef and clientTestPSKRef are the client's secret references.
// They are env: references so the whole suite runs with no AWS and no
// network.
const (
	clientTestPrivRef = SecretRef("env:GOCLOAK_TEST_CLIENT_PRIV")
	clientTestPSKRef  = SecretRef("env:GOCLOAK_TEST_CLIENT_PSK")
)

// clientTestHarness is a real server, a real peer, and the ClientConfig that
// reaches it.
type clientTestHarness struct {
	t    *testing.T
	srv  *serverHarness
	peer *serverTestPeer
	cfg  ClientConfig
}

// clientTestStart brings up a real Server on a real WireGuard device over
// localhost UDP, with one peer whose allow map is the given service to
// backend address mapping, and publishes that peer's key material under the
// environment variables the client's references name.
func clientTestStart(t *testing.T, allow map[string]string, tweaks ...func(*serverTestPeer)) *clientTestHarness {
	t.Helper()

	peer := serverTestNewPeer(t, "app", "10.99.0.7")
	peer.Allow = allow
	// Applied before the server starts, so the peers file the watcher
	// loads is already the one the test wants: rewriting it afterwards
	// races the watch being armed inside Run.
	for _, f := range tweaks {
		f(peer)
	}
	h := serverTestStart(t, peer)

	t.Setenv(strings.TrimPrefix(string(clientTestPrivRef), "env:"), deviceTestB64(peer.Priv))
	t.Setenv(strings.TrimPrefix(string(clientTestPSKRef), "env:"), deviceTestB64(peer.PSK))

	return &clientTestHarness{
		t:    t,
		srv:  h,
		peer: peer,
		cfg: ClientConfig{
			Endpoint:     fmt.Sprintf("127.0.0.1:%d", h.udpPort),
			ServerPubKey: h.serverPub,
			PrivateKey:   clientTestPrivRef,
			PresharedKey: clientTestPSKRef,
			TunnelIP:     peer.IP,
			DialTimeout:  clientTestDialBudget,
		},
	}
}

// client builds a Client from the harness config, with any final tweaks
// applied, and closes it at test end.
func (h *clientTestHarness) client(tweak ...func(*ClientConfig)) *Client {
	h.t.Helper()
	cfg := h.cfg
	for _, f := range tweak {
		f(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		h.t.Fatalf("NewClient: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

// clientTestCtx is a context bounded so no test in this file can hang.
func clientTestCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// end to end
// ---------------------------------------------------------------------------

// TestClientEndToEndBytesFlowBothWays is the whole public path: NewClient,
// Dial, and an application byte exchange with a real backend through a real
// tunnel terminated by a real Server.
func TestClientEndToEndBytesFlowBothWays(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})
	c := h.client()

	ctx := clientTestCtx(t, clientTestDialBudget+10*time.Second)
	conn, err := c.Dial(ctx, "echo")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("read %q through the tunnel, want %q", got, "ping")
	}
}

// TestClientDialContextDrivesARealHTTPClient is the reason DialContext
// exists: a *Client drops into http.Transport unchanged, and a real
// http.Client reaches a real HTTP backend through the tunnel by service name.
func TestClientDialContextDrivesARealHTTPClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	defer backend.Close()

	addr := strings.TrimPrefix(backend.URL, "http://")
	h := clientTestStart(t, map[string]string{"web": addr})
	c := h.client()

	tr := &http.Transport{DialContext: c.DialContext}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: clientTestDialBudget + 10*time.Second}

	resp, err := hc.Get("http://web/greeting")
	if err != nil {
		t.Fatalf("http GET through the tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if want := "hello from /greeting"; string(body) != want {
		t.Fatalf("body %q, want %q", body, want)
	}
}

// ---------------------------------------------------------------------------
// status mapping
// ---------------------------------------------------------------------------

// TestClientDeniedServiceIsADistinctError covers spec section 4: a denial
// and an unhealthy backend are different errors, so an application can tell
// "I am not allowed to talk to this" from "the database is down".
func TestClientDeniedServiceIsADistinctError(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})
	c := h.client()

	ctx := clientTestCtx(t, clientTestDialBudget+10*time.Second)
	conn, err := c.Dial(ctx, "forbidden")
	if err == nil {
		conn.Close()
		t.Fatal("Dial of a service this peer was not granted succeeded, want an error")
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Dial returned %v, want ErrDenied", err)
	}
	if errors.Is(err, ErrBackendUnavailable) {
		t.Fatal("a denial must not also satisfy errors.Is(err, ErrBackendUnavailable)")
	}
	if errors.Is(err, ErrHandshakeTimeout) {
		t.Fatal("a denial must not also satisfy errors.Is(err, ErrHandshakeTimeout)")
	}
}

// TestClientBackendUnavailableIsADistinctError is the other half: a granted
// service whose backend is not listening returns ErrBackendUnavailable, not
// ErrDenied.
func TestClientBackendUnavailableIsADistinctError(t *testing.T) {
	dead := serverTestClosedPort(t)
	h := clientTestStart(t, map[string]string{"db": dead.String()})
	c := h.client()

	ctx := clientTestCtx(t, clientTestDialBudget+30*time.Second)
	conn, err := c.Dial(ctx, "db")
	if err == nil {
		conn.Close()
		t.Fatal("Dial of a service with a dead backend succeeded, want an error")
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Dial returned %v, want ErrBackendUnavailable", err)
	}
	if errors.Is(err, ErrDenied) {
		t.Fatal("a dead backend must not also satisfy errors.Is(err, ErrDenied)")
	}
}

// TestClientStatusErrorsAreDistinctSentinels pins the mapping from every
// wire status to its own sentinel, including the two the end to end tests
// cannot provoke against a real server.
func TestClientStatusErrorsAreDistinctSentinels(t *testing.T) {
	cases := []struct {
		status status
		want   error
	}{
		{statusDenied, ErrDenied},
		{statusBackendUnavailable, ErrBackendUnavailable},
		{statusRateLimited, ErrRateLimited},
		{statusMalformed, ErrMalformedRequest},
	}
	all := []error{ErrDenied, ErrBackendUnavailable, ErrRateLimited, ErrMalformedRequest, ErrHandshakeTimeout}

	for _, tc := range cases {
		err := statusError(tc.status, "svc")
		if err == nil {
			t.Fatalf("statusError(%v) returned nil", tc.status)
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("statusError(%v) = %v, want it to wrap %v", tc.status, err, tc.want)
		}
		for _, other := range all {
			if other == tc.want {
				continue
			}
			if errors.Is(err, other) {
				t.Errorf("statusError(%v) also matches %v; the sentinels must be distinct", tc.status, other)
			}
		}
		if !strings.Contains(err.Error(), "svc") {
			t.Errorf("statusError(%v) = %q, want it to name the service", tc.status, err)
		}
	}

	// statusOK is not an error, and must never be turned into one.
	if err := statusError(statusOK, "svc"); err != nil {
		t.Errorf("statusError(statusOK) = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// ErrHandshakeTimeout
// ---------------------------------------------------------------------------

// TestClientWrongServerPublicKeyTimesOutAndDoesNotHang is spec section 8.1
// from the client's side: a pinned key that does not match the server is
// silence, bounded by DialTimeout, reported as ErrHandshakeTimeout.
func TestClientWrongServerPublicKeyTimesOutAndDoesNotHang(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})

	_, wrongPub := deviceTestKeypair(t)
	c := h.client(func(cfg *ClientConfig) {
		cfg.ServerPubKey = wrongPub
		cfg.DialTimeout = clientTestFailBudget
	})

	clientTestAssertHandshakeTimeout(t, c, "echo")
}

// TestClientWrongPSKTimesOutAndDoesNotHang is the same for the preshared
// key: WireGuard gives no negative feedback, so a wrong PSK is silence too.
func TestClientWrongPSKTimesOutAndDoesNotHang(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})

	t.Setenv("GOCLOAK_TEST_CLIENT_WRONG_PSK", deviceTestB64(deviceTestPSK(t)))
	c := h.client(func(cfg *ClientConfig) {
		cfg.PresharedKey = "env:GOCLOAK_TEST_CLIENT_WRONG_PSK"
		cfg.DialTimeout = clientTestFailBudget
	})

	clientTestAssertHandshakeTimeout(t, c, "echo")
}

// clientTestAssertHandshakeTimeout asserts a Dial fails with
// ErrHandshakeTimeout inside its own DialTimeout, in a goroutine guarded by
// an outer deadline so a Dial that ignored its own bound fails the test
// instead of stalling it.
func clientTestAssertHandshakeTimeout(t *testing.T, c *Client, service string) {
	t.Helper()

	type result struct {
		conn net.Conn
		err  error
		took time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		// A generous outer context: the bound under test is
		// DialTimeout, not this.
		conn, err := c.Dial(clientTestCtx(t, 60*time.Second), service)
		done <- result{conn: conn, err: err, took: time.Since(start)}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			r.conn.Close()
			t.Fatal("Dial succeeded, want ErrHandshakeTimeout")
		}
		if !errors.Is(r.err, ErrHandshakeTimeout) {
			t.Fatalf("Dial returned %v, want ErrHandshakeTimeout", r.err)
		}
		if r.took < clientTestFailBudget {
			t.Errorf("Dial gave up after %v, before its %v DialTimeout", r.took, clientTestFailBudget)
		}
		if r.took > clientTestFailBudget+10*time.Second {
			t.Errorf("Dial took %v, far beyond its %v DialTimeout", r.took, clientTestFailBudget)
		}
	case <-time.After(clientTestFailBudget + 30*time.Second):
		t.Fatal("Dial did not return; it must be bounded by DialTimeout, never open ended")
	}
}

// TestClientWrongKeyAndWrongPSKAreIndistinguishable is the security claim
// the client exists to uphold, pinned as an assertion rather than left to
// hold by accident. Spec section 8.1: the library must not distinguish a
// wrong key from a wrong PSK from a dead endpoint, because any
// distinguishing signal is what a scanner is looking for. Structurally
// there is one path today, so a future change adding a PSK specific detail
// would fail neither of the two tests above; it fails this one.
func TestClientWrongKeyAndWrongPSKAreIndistinguishable(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})

	_, wrongPub := deviceTestKeypair(t)
	wrongKey := h.client(func(cfg *ClientConfig) {
		cfg.ServerPubKey = wrongPub
		cfg.DialTimeout = clientTestFailBudget
	})

	t.Setenv("GOCLOAK_TEST_CLIENT_OTHER_PSK", deviceTestB64(deviceTestPSK(t)))
	wrongPSK := h.client(func(cfg *ClientConfig) {
		cfg.PresharedKey = "env:GOCLOAK_TEST_CLIENT_OTHER_PSK"
		cfg.DialTimeout = clientTestFailBudget
	})

	ctx := clientTestCtx(t, 60*time.Second)

	_, keyErr := wrongKey.Dial(ctx, "echo")
	_, pskErr := wrongPSK.Dial(ctx, "echo")
	if keyErr == nil || pskErr == nil {
		t.Fatalf("want both dials to fail, got key=%v psk=%v", keyErr, pskErr)
	}

	// The duration is the one part that legitimately differs, and it is
	// rounded to 100ms in the message, so both land on the same budget.
	if keyErr.Error() != pskErr.Error() {
		t.Errorf("a wrong server key and a wrong PSK produce different errors, which is the signal spec 8.1 forbids:\n  wrong key: %s\n  wrong psk: %s", keyErr, pskErr)
	}
}

// TestClientHandshakeTimeoutNamesEveryCause pins the message from spec
// section 8.1. Every cause is asserted separately, so a future edit cannot
// quietly drop one and leave an operator without the possibility that was
// actually theirs.
func TestClientHandshakeTimeoutNamesEveryCause(t *testing.T) {
	c := &Client{
		endpointText: "tunnel.example.com:51820",
		dialTimeout:  10 * time.Second,
	}
	err := c.handshakeTimeoutError(10 * time.Second)

	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("handshakeTimeoutError returned %v, want it to wrap ErrHandshakeTimeout", err)
	}

	msg := err.Error()
	for _, want := range []string{
		"no response from tunnel.example.com:51820",
		"10s",
		"does not answer unauthenticated traffic",
		"wrong server public key",
		"wrong client key",
		"revoked peer",
		"wrong PSK",
		"UDP blocked on this network",
		"the endpoint is down",
		"The server cannot tell you which",
		"Check the server log for a peer entry",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("ErrHandshakeTimeout message is missing %q.\nmessage: %s", want, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// local validation
// ---------------------------------------------------------------------------

// TestClientInvalidServiceNameFailsLocally asserts a bad service name is
// refused before anything is opened: the client below points at a blackhole
// with a ten second DialTimeout, so a call that touched the network could
// not possibly return this fast.
func TestClientInvalidServiceNameFailsLocally(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	_, pub := deviceTestKeypair(t)
	t.Setenv("GOCLOAK_TEST_LOCAL_PRIV", deviceTestB64(priv))
	t.Setenv("GOCLOAK_TEST_LOCAL_PSK", deviceTestB64(deviceTestPSK(t)))

	c, err := NewClient(ClientConfig{
		// 198.51.100.0/24 is TEST-NET-2 (RFC 5737): reserved for
		// documentation, so nothing answers and nothing is harmed.
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: pub,
		PrivateKey:   "env:GOCLOAK_TEST_LOCAL_PRIV",
		PresharedKey: "env:GOCLOAK_TEST_LOCAL_PSK",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
		DialTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	for _, name := range []string{"", "UPPER", "-leading", "has space", "has_underscore", strings.Repeat("a", 64), "svc\n"} {
		start := time.Now()
		conn, err := c.Dial(clientTestCtx(t, 30*time.Second), name)
		took := time.Since(start)
		if err == nil {
			conn.Close()
			t.Fatalf("Dial(%q) succeeded, want a local validation error", name)
		}
		if took > time.Second {
			t.Errorf("Dial(%q) took %v; an invalid name must fail locally, without touching the network", name, took)
		}
		if errors.Is(err, ErrHandshakeTimeout) {
			t.Errorf("Dial(%q) returned ErrHandshakeTimeout; a bad name is a local error", name)
		}
	}
}

// TestClientNewClientRejectsBadConfig is the fail closed construction
// battery: every one of these must produce an error and a nil Client, never
// a half usable one.
func TestClientNewClientRejectsBadConfig(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	_, pub := deviceTestKeypair(t)
	t.Setenv("GOCLOAK_TEST_CFG_PRIV", deviceTestB64(priv))
	t.Setenv("GOCLOAK_TEST_CFG_PSK", deviceTestB64(deviceTestPSK(t)))

	base := ClientConfig{
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: pub,
		PrivateKey:   "env:GOCLOAK_TEST_CFG_PRIV",
		PresharedKey: "env:GOCLOAK_TEST_CFG_PSK",
		TunnelIP:     netip.MustParseAddr("10.99.0.9"),
	}

	// The base config itself must be accepted, so every failure below is
	// attributable to the one field it changes.
	ok, err := NewClient(base)
	if err != nil {
		t.Fatalf("NewClient(base): %v", err)
	}
	ok.Close()

	short := base64Key(t, 31)
	long := base64Key(t, 33)

	cases := []struct {
		name  string
		tweak func(*ClientConfig)
	}{
		{"empty endpoint", func(c *ClientConfig) { c.Endpoint = "" }},
		{"endpoint with no port", func(c *ClientConfig) { c.Endpoint = "tunnel.example.com" }},
		{"endpoint with port zero", func(c *ClientConfig) { c.Endpoint = "198.51.100.1:0" }},
		{"endpoint with a named port", func(c *ClientConfig) { c.Endpoint = "198.51.100.1:wireguard" }},
		{"empty server public key", func(c *ClientConfig) { c.ServerPubKey = "" }},
		{"server public key that is not base64", func(c *ClientConfig) { c.ServerPubKey = "not base64!!" }},
		{"server public key of 31 bytes", func(c *ClientConfig) { c.ServerPubKey = short }},
		{"server public key of 33 bytes", func(c *ClientConfig) { c.ServerPubKey = long }},
		{"empty private key reference", func(c *ClientConfig) { c.PrivateKey = "" }},
		{"private key as a literal", func(c *ClientConfig) { c.PrivateKey = SecretRef(deviceTestB64(priv)) }},
		{"private key reference that does not resolve", func(c *ClientConfig) { c.PrivateKey = "env:GOCLOAK_TEST_CFG_NEVER_SET" }},
		{"empty psk reference", func(c *ClientConfig) { c.PresharedKey = "" }},
		{"psk reference that does not resolve", func(c *ClientConfig) { c.PresharedKey = "env:GOCLOAK_TEST_CFG_NEVER_SET" }},
		{"unspecified tunnel ip", func(c *ClientConfig) { c.TunnelIP = netip.Addr{} }},
		{"tunnel ip outside the subnet", func(c *ClientConfig) { c.TunnelIP = netip.MustParseAddr("10.98.0.9") }},
		{"tunnel ip is the server address", func(c *ClientConfig) { c.TunnelIP = netip.MustParseAddr("10.99.0.1") }},
		{"tunnel ip is the network address", func(c *ClientConfig) { c.TunnelIP = netip.MustParseAddr("10.99.0.0") }},
		{"tunnel ip is the broadcast address", func(c *ClientConfig) { c.TunnelIP = netip.MustParseAddr("10.99.0.255") }},
		{"mtu below the minimum", func(c *ClientConfig) { c.MTU = 576 }},
		{"mtu above the maximum", func(c *ClientConfig) { c.MTU = 9000 }},
		{"negative dial timeout", func(c *ClientConfig) { c.DialTimeout = -time.Second }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.tweak(&cfg)
			c, err := NewClient(cfg)
			if err == nil {
				c.Close()
				t.Fatalf("NewClient accepted %s, want an error", tc.name)
			}
			if c != nil {
				c.Close()
				t.Errorf("NewClient returned a non nil Client alongside an error")
			}
		})
	}
}

// TestClientNewClientRejectsUnusableKeyMaterial covers the references that
// resolve but whose contents cannot be a WireGuard key. Construction must
// fail rather than bring up a device that silently never handshakes.
func TestClientNewClientRejectsUnusableKeyMaterial(t *testing.T) {
	_, pub := deviceTestKeypair(t)
	priv, _ := deviceTestKeypair(t)

	cases := []struct {
		name string
		priv string
		psk  string
	}{
		{"private key is not base64", "not base64!!", deviceTestB64(deviceTestPSK(t))},
		{"private key is the wrong length", base64Key(t, 31), deviceTestB64(deviceTestPSK(t))},
		{"psk is not base64", deviceTestB64(priv), "not base64!!"},
		{"psk is the wrong length", deviceTestB64(priv), base64Key(t, 16)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOCLOAK_TEST_BAD_PRIV", tc.priv)
			t.Setenv("GOCLOAK_TEST_BAD_PSK", tc.psk)
			c, err := NewClient(ClientConfig{
				Endpoint:     "198.51.100.1:51820",
				ServerPubKey: pub,
				PrivateKey:   "env:GOCLOAK_TEST_BAD_PRIV",
				PresharedKey: "env:GOCLOAK_TEST_BAD_PSK",
				TunnelIP:     netip.MustParseAddr("10.99.0.9"),
			})
			if err == nil {
				c.Close()
				t.Fatal("NewClient accepted unusable key material, want an error")
			}
			if c != nil {
				c.Close()
				t.Error("NewClient returned a non nil Client alongside an error")
			}
			clientTestAssertNoSecrets(t, err.Error(), tc.priv, tc.psk)
		})
	}
}

// base64Key returns n random bytes, base64 encoded: a key of the wrong
// length, for the construction battery.
func base64Key(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// TestClientCloseIsIdempotentAndDialAfterCloseErrors asserts the two things
// a caller does by accident: closing twice, and dialing a closed client.
// Neither may panic.
func TestClientCloseIsIdempotentAndDialAfterCloseErrors(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})
	c := h.client()

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	start := time.Now()
	conn, err := c.Dial(clientTestCtx(t, 30*time.Second), "echo")
	if err == nil {
		conn.Close()
		t.Fatal("Dial after Close succeeded, want an error")
	}
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Dial after Close returned %v, want ErrClientClosed", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("Dial after Close took %v; a closed client must fail immediately", took)
	}

	if _, err := c.DialContext(clientTestCtx(t, 30*time.Second), "tcp", "echo:80"); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("DialContext after Close returned %v, want ErrClientClosed", err)
	}
}

// TestClientBrokenConnectionErrorsAndIsNotReconnected covers spec section
// 8.2: a net.Conn already handed to the caller must error when it breaks.
// Reconnecting underneath the caller would reorder or duplicate application
// bytes, so the conn stays broken and the application decides whether to
// Dial again.
func TestClientBrokenConnectionErrorsAndIsNotReconnected(t *testing.T) {
	// A backend that reads one request and then hangs up.
	backend := serverTestNewBackend(t, func(c net.Conn) {
		buf := make([]byte, 4)
		io.ReadFull(c, buf)
		c.Close()
	})
	h := clientTestStart(t, map[string]string{"once": backend.String()})
	c := h.client()

	conn, err := c.Dial(clientTestCtx(t, clientTestDialBudget+10*time.Second), "once")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The far end is gone: the read must end, and every later read must
	// keep failing rather than silently resuming on a fresh connection.
	if _, err := io.ReadAll(conn); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read after the backend hung up: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a read on a broken conn succeeded; the client must never reconnect underneath the caller")
	}

	// A fresh Dial is the documented recovery, and it still works.
	conn2, err := c.Dial(clientTestCtx(t, clientTestDialBudget+10*time.Second), "once")
	if err != nil {
		t.Fatalf("Dial after the first conn broke: %v", err)
	}
	conn2.Close()
}

// TestClientHelloIsBoundedByTheDialBudget asserts DialTimeout bounds what
// its documentation says it bounds. It used to bound only the tunnel
// handshake, so a server that accepted the connection and then stalled
// could hold a caller for two further HelloReadDeadlines beyond the budget
// it asked for.
func TestClientHelloIsBoundedByTheDialBudget(t *testing.T) {
	const budget = 200 * time.Millisecond

	// The deadline for one step of the exchange is the sooner of the
	// spec's value and what is left of the budget.
	c := &Client{endpointText: "127.0.0.1:51820", dialTimeout: budget}

	tight, cancelTight := context.WithTimeout(context.Background(), budget)
	defer cancelTight()
	if d := c.helloDeadline(tight); d.After(time.Now().Add(budget + time.Second)) {
		t.Errorf("helloDeadline is %v away on a %v budget; it must not exceed the budget", time.Until(d), budget)
	}

	loose, cancelLoose := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLoose()
	if d := c.helloDeadline(loose); d.After(time.Now().Add(helloReadDeadline)) {
		t.Errorf("helloDeadline is %v away on an hour long budget; it must not exceed helloReadDeadline", time.Until(d))
	}
	if d := c.helloDeadline(loose); d.Before(time.Now().Add(helloReadDeadline - time.Second)) {
		t.Errorf("helloDeadline is only %v away on an hour long budget; it should be helloReadDeadline", time.Until(d))
	}

	// End to end over a pipe: a far end that takes the request and then
	// says nothing at all.
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	go io.ReadFull(remote, make([]byte, 2+len("svc")))

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	err := c.hello(ctx, local, "svc")
	took := time.Since(start)

	if err == nil {
		t.Fatal("hello returned nil against a far end that never answered")
	}
	if took > time.Second {
		t.Errorf("hello took %v against a %v budget; DialTimeout must bound the hello exchange, not just the handshake", took, budget)
	}
}

// TestClientFinishHelloRefusesAConnTheWatchdogIsClosing exercises the
// use-after-return branch directly, because the real window is
// sub-microsecond and no timing test can hit it reliably.
//
// context.AfterFunc's stop reports false when the watchdog has already
// started, which means conn.Close is running in another goroutine. A
// connection in that state must never be returned to the caller: it would
// be a fully established, hello-completed conn that dies underneath the
// application with no error at all.
func TestClientFinishHelloRefusesAConnTheWatchdogIsClosing(t *testing.T) {
	c := &Client{endpointText: "127.0.0.1:51820", dialTimeout: time.Second}

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// stop reports false: the watchdog already fired.
	err := c.finishHello(cancelled, local, func() bool { return false })
	if err == nil {
		t.Fatal("finishHello returned nil when the watchdog had already started; the caller would receive a conn that is being torn down")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("finishHello returned %v, want it to carry the context error", err)
	}

	// stop reports true: the watchdog was unregistered in time, so the
	// conn is safe to hand over and its deadlines are cleared.
	if err := local.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	stopped := false
	if err := c.finishHello(context.Background(), local, func() bool { stopped = true; return true }); err != nil {
		t.Fatalf("finishHello with a stopped watchdog: %v", err)
	}
	if !stopped {
		t.Error("finishHello did not call stop; the watchdog would outlive the exchange")
	}

	// The deadline is cleared, so a read blocks rather than expiring.
	// One byte written from the far end proves the conn is live.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := local.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("read returned %v immediately; the deadline was not cleared", err)
	case <-time.After(1500 * time.Millisecond):
		// Still blocked well past the old one second deadline.
	}
	if _, err := remote.Write([]byte("x")); err != nil {
		t.Fatalf("write from the far end: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read after the deadline was cleared: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not return after the far end wrote")
	}
}

// TestClientDialUnderRepeatedCancellationNeverReturnsADeadConn is the other
// half of the same finding, from the outside: hammer Dial with contexts
// cancelled at randomized offsets around the moment a dial completes, and
// require that every conn Dial returned is actually usable. A connection
// torn down by the watchdog after being returned fails the exchange below.
//
// Two different things are being asserted, with two different strengths.
// Cancelling the context immediately after a successful Dial is
// DETERMINISTIC, and it catches a watchdog left armed past the exchange:
// that connection is closed underneath the byte exchange below and the test
// fails every time. The randomized timer is only a sweep: the real
// use-after-return window is sub-microsecond, so landing in it is luck, and
// this test is not proof that it is closed. The direct proof is
// TestClientFinishHelloRefusesAConnTheWatchdogIsClosing.
func TestClientDialUnderRepeatedCancellationNeverReturnsADeadConn(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	// The default rate cap is 10 dials per second, which this test would
	// spend its whole budget waiting on.
	h := clientTestStart(t, map[string]string{"echo": backend.String()}, func(p *serverTestPeer) {
		p.Limits = peerLimits{MaxConcurrent: 64, DialsPerSecond: 5000}
	})

	c := h.client()

	// The first dial pays for the WireGuard handshake, so it is not
	// representative. Measure the second, once the tunnel is up: that is
	// the duration the cancellations below have to land inside for the
	// exchange to be completing as the watchdog fires.
	warm := clientTestCtx(t, clientTestDialBudget+10*time.Second)
	conn, err := c.Dial(warm, "echo")
	if err != nil {
		t.Fatalf("warm up Dial: %v", err)
	}
	conn.Close()

	start := time.Now()
	conn, err = c.Dial(warm, "echo")
	if err != nil {
		t.Fatalf("second warm up Dial: %v", err)
	}
	conn.Close()
	typical := time.Since(start)
	if typical < time.Millisecond {
		typical = time.Millisecond
	}
	t.Logf("a warm dial takes about %v; cancelling within 0 to %v", typical, 2*typical)

	deadline := time.Now().Add(10 * time.Second)
	var returned, usable int
	for i := 0; i < 300 && time.Now().Before(deadline); i++ {
		ctx, cancel := context.WithCancel(context.Background())
		delay := time.Duration(rand.Int64N(int64(2 * typical)))
		timer := time.AfterFunc(delay, cancel)

		conn, err := c.Dial(ctx, "echo")
		if err != nil {
			timer.Stop()
			cancel()
			continue
		}
		returned++

		// The dial's context is finished the moment Dial returns, so
		// cancel it now, before a single application byte moves. A
		// watchdog left armed past the exchange, or one whose stop
		// result went unchecked, tears the connection down here.
		timer.Stop()
		cancel()

		// The conn was handed over, so it must work, cancelled ctx or
		// not: Dial's context governs the dial, never the lifetime of
		// a connection it returned.
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("iteration %d: set deadline on a returned conn: %v", i, err)
		}
		if _, werr := conn.Write([]byte("ping")); werr != nil {
			t.Fatalf("iteration %d: write on a conn Dial returned: %v", i, werr)
		}
		got := make([]byte, 4)
		if _, rerr := io.ReadFull(conn, got); rerr != nil {
			t.Fatalf("iteration %d: read on a conn Dial returned: %v", i, rerr)
		}
		if string(got) != "ping" {
			t.Fatalf("iteration %d: read %q, want %q", i, got, "ping")
		}
		usable++
		conn.Close()
	}

	t.Logf("%d of %d returned conns were usable", usable, returned)
	if returned < 4 {
		t.Fatalf("only %d dials returned a conn; the test would pass vacuously", returned)
	}
}

// ---------------------------------------------------------------------------
// DialContext
// ---------------------------------------------------------------------------

// TestClientDialContextStripsThePort pins the addr to service name mapping
// spec section 5 describes, without needing a tunnel.
func TestClientDialContextStripsThePort(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"payments:443", "payments"},
		{"payments", "payments"},
		{"payments:80", "payments"},
		{"db-primary:5432", "db-primary"},
		{"[::1]:80", "::1"},
	}
	for _, tc := range cases {
		if got := serviceFromAddr(tc.addr); got != tc.want {
			t.Errorf("serviceFromAddr(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// constraint 4: no key material anywhere
// ---------------------------------------------------------------------------

// TestClientNeverLogsOrReturnsKeyMaterial runs a full client lifecycle with
// the standard logger captured, then asserts that neither the captured log
// nor any error produced along the way carries a private key, a PSK, or a
// secret reference.
func TestClientNeverLogsOrReturnsKeyMaterial(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})

	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"echo": backend.String()})
	c := h.client()

	priv := deviceTestB64(h.peer.Priv)
	psk := deviceTestB64(h.peer.PSK)

	var errs []string

	conn, err := c.Dial(clientTestCtx(t, clientTestDialBudget+10*time.Second), "echo")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	if _, err := c.Dial(clientTestCtx(t, clientTestDialBudget+10*time.Second), "forbidden"); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := c.Dial(clientTestCtx(t, 5*time.Second), "NOT VALID"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if _, err := c.Dial(clientTestCtx(t, 5*time.Second), "echo"); err != nil {
		errs = append(errs, err.Error())
	}

	// A construction failure carries the most risk of echoing a
	// reference, so it is in the same sweep.
	if _, err := NewClient(ClientConfig{
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: h.srv.serverPub,
		PrivateKey:   clientTestPrivRef,
		PresharedKey: "env:GOCLOAK_TEST_CLIENT_NEVER_SET",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
	}); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) < 4 {
		t.Fatalf("collected %d errors, want at least 4; the sweep would pass vacuously", len(errs))
	}

	for _, e := range errs {
		clientTestAssertNoSecrets(t, e, priv, psk)
		if strings.Contains(e, "GOCLOAK_TEST_CLIENT_NEVER_SET") || strings.Contains(e, string(clientTestPrivRef)) {
			t.Errorf("an error carries a secret reference: %s", e)
		}
	}
	clientTestAssertNoSecrets(t, logs.String(), priv, psk)
}

// clientTestAssertNoSecrets asserts text carries neither key in base64 nor
// in the hex the UAPI uses, and no obvious prefix of either.
func clientTestAssertNoSecrets(t *testing.T, text, priv, psk string) {
	t.Helper()
	for _, secret := range []string{priv, psk} {
		if secret == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Errorf("text carries key material in base64: %s", text)
		}
		if hexed, err := keyToHex(secret); err == nil && strings.Contains(text, hexed) {
			t.Errorf("text carries key material in hex: %s", text)
		}
		// A prefix long enough to be identifying, in case something
		// truncates before logging.
		if len(secret) >= 12 && strings.Contains(text, secret[:12]) {
			t.Errorf("text carries a prefix of key material: %s", text)
		}
	}
}

// TestClientConcurrentDialsAreSafe pins that one Client survives many
// goroutines dialing at once, which is exactly what http.Transport does when
// a transport is reused across concurrent requests. The library documents
// DialContext for that use, so the property needs a test.
//
// Note the raised limits: the per-peer dials_per_second cap is what a burst
// hits first, not any client-side constraint.// exactly what http.Transport does when it reuses a transport across
// concurrent requests?
func TestClientConcurrentDialsAreSafe(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	h := clientTestStart(t, map[string]string{"svc": backend.String()}, func(p *serverTestPeer) {
		p.Limits.MaxConcurrent = 64
		p.Limits.DialsPerSecond = 200
	})
	c := h.client()

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), clientTestDialBudget)
			defer cancel()
			conn, err := c.Dial(ctx, "svc")
			if err != nil {
				errs <- err
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Dial failed: %v", err)
	}
}

// TestClientResolverIsConsultedForNonNativeSchemes is the client half of
// the plumbing added when the AWS schemes moved into their own module: a
// ClientConfig.Resolver is what makes a scheme other than file: or env:
// resolvable, and the whole client comes up on key material that came
// through it.
func TestClientResolverIsConsultedForNonNativeSchemes(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	_, pub := deviceTestKeypair(t)
	psk := deviceTestPSK(t)

	asked := map[SecretRef]int{}
	resolver := resolverFunc(func(ctx context.Context, ref SecretRef) ([]byte, error) {
		asked[ref]++
		switch ref {
		case "vault:gocloak/app/private":
			return []byte(deviceTestB64(priv)), nil
		case "vault:gocloak/app/psk":
			return []byte(deviceTestB64(psk)), nil
		}
		return nil, fmt.Errorf("no value for %q", string(ref))
	})

	c, err := NewClient(ClientConfig{
		// TEST-NET-2 (RFC 5737): nothing answers, and NewClient
		// sends no packet anyway.
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: pub,
		PrivateKey:   "vault:gocloak/app/private",
		PresharedKey: "vault:gocloak/app/psk",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
		Resolver:     resolver,
	})
	if err != nil {
		t.Fatalf("NewClient with a Resolver: %v", err)
	}
	defer c.Close()

	if asked["vault:gocloak/app/private"] != 1 || asked["vault:gocloak/app/psk"] != 1 {
		t.Fatalf("resolver calls = %v, want each reference resolved exactly once", asked)
	}
}

// TestClientNonNativeSchemeWithNoResolverFailsClosed is the other half: the
// same config without a Resolver must refuse to build a client rather than
// come up with something improvised in place of a key.
func TestClientNonNativeSchemeWithNoResolverFailsClosed(t *testing.T) {
	_, pub := deviceTestKeypair(t)

	_, err := NewClient(ClientConfig{
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: pub,
		PrivateKey:   "aws:sm:gocloak/app/private",
		PresharedKey: "aws:sm:gocloak/app/psk",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
	})
	if err == nil {
		t.Fatal("NewClient succeeded with an aws:sm: reference and no Resolver")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error should name the private key, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Resolver") {
		t.Errorf("error should say a Resolver is needed, got: %v", err)
	}
	if strings.Contains(err.Error(), "gocloak/app/private") {
		t.Errorf("error echoes the reference payload: %v", err)
	}
}
