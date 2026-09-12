package gocloak

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultDialTimeout is the bound on a Dial when ClientConfig.DialTimeout is
// zero, per spec section 5. It is the whole budget for the call: bringing
// the WireGuard handshake up, opening the in-tunnel control connection, and
// the hello exchange.
const DefaultDialTimeout = 10 * time.Second

// clientSecretResolveTimeout bounds the secret store lookups NewClient does.
// NewClient takes no context (its signature is fixed by spec section 5), so
// the bound is here rather than the caller's: an unreachable secret store
// must fail construction, never hang the process that called it.
const clientSecretResolveTimeout = 30 * time.Second

// clientEndpointResolveTimeout bounds the name resolution of
// ClientConfig.Endpoint, for the same reason.
const clientEndpointResolveTimeout = 10 * time.Second

// clientDialAttemptTimeout bounds one attempt at the in-tunnel TCP
// connection. Attempts are retried until the caller's budget runs out: a
// SYN sent before the WireGuard handshake completes is dropped, and
// abandoning an attempt is cheaper than waiting out netstack's own
// retransmit backoff.
const clientDialAttemptTimeout = 2 * time.Second

// clientDialRetryInterval is the gap between those attempts.
const clientDialRetryInterval = 250 * time.Millisecond

// Errors returned by Dial and DialContext. Each wire status from spec
// section 4 maps to its own sentinel so an application can tell "I am not
// allowed to talk to this" from "the database is down", which is the whole
// reason the protocol carries a status byte at all.
var (
	// ErrHandshakeTimeout means the endpoint never answered. Spec
	// section 8.1: a wrong key, a revoked peer, a wrong PSK and a dead
	// endpoint are indistinguishable by design, and this library does
	// not try to distinguish them, because any distinguishing signal is
	// what a scanner is looking for. The wrapped message names every
	// possibility instead.
	ErrHandshakeTimeout = errors.New("gocloak: handshake timeout")

	// ErrDenied means the service is not in this peer's allow map
	// (status 0x01).
	ErrDenied = errors.New("gocloak: the server denied this service for this peer")

	// ErrBackendUnavailable means the service is granted but the server
	// could not reach its backend (status 0x02).
	ErrBackendUnavailable = errors.New("gocloak: the server could not reach the backend for this service")

	// ErrRateLimited means the server refused the dial under this peer's
	// limits (status 0x03).
	ErrRateLimited = errors.New("gocloak: the server rate limited this peer")

	// ErrMalformedRequest means the server could not parse the hello
	// frame (status 0x04). Against a server running this library it
	// indicates a version mismatch, not a caller mistake.
	ErrMalformedRequest = errors.New("gocloak: the server rejected the hello frame as malformed")

	// ErrClientClosed is returned by Dial and DialContext after Close.
	ErrClientClosed = errors.New("gocloak: client is closed")

	// ErrInvalidServiceName is returned when a service name does not
	// match the wire protocol charset. The offending name is never
	// echoed: it is attacker-shaped input on its way to a log line.
	ErrInvalidServiceName = errors.New("gocloak: invalid service name, want ^[a-z0-9][a-z0-9-]{0,62}$")
)

// ClientConfig is the client's configuration, per spec section 5.
type ClientConfig struct {
	// Endpoint is the server's public UDP address,
	// "tunnel.example.com:51820". A host name is resolved once, at
	// construction; see NewClient for what that means for a name with
	// several addresses and for an address that changes later.
	Endpoint string

	// ServerPubKey is the server's Curve25519 public key, base64
	// encoded, and it is pinned: this is the only key the client will
	// complete a handshake with. There is no certificate authority and
	// nothing to negotiate.
	ServerPubKey string

	// PrivateKey references this peer's Curve25519 private key. It is a
	// reference, not a value, so a literal key in a config struct is a
	// compile-time mistake rather than a runtime leak.
	PrivateKey SecretRef

	// PresharedKey references the 32-byte symmetric key mixed into the
	// handshake. Spec section 7.1 lists it as the post-quantum hedge, so
	// it is required, never optional.
	PresharedKey SecretRef

	// TunnelIP is this peer's address inside 10.99.0.0/24. It must match
	// the allowed_ip the server has for this peer's public key.
	TunnelIP netip.Addr

	// MTU is the tunnel MTU. Zero means DefaultMTU (1280).
	MTU int

	// DialTimeout bounds one Dial. Zero means DefaultDialTimeout (10s).
	DialTimeout time.Duration

	// Resolver resolves secret references whose scheme this package does
	// not implement. Optional: nil means file: and env: only, which is
	// the whole of what this package resolves on its own.
	//
	// It is wired here rather than registered globally on purpose. A
	// database/sql-style global registry would let any imported package
	// install a secret resolver without the program that links it saying
	// so, which is the wrong default for a security library. Whoever
	// builds the config decides where key material comes from.
	Resolver SecretResolver
}

// Client is an application's handle on the tunnel: one WireGuard device,
// one pinned server, and a Dial that returns an ordinary net.Conn to a
// named service behind that server.
//
// A Client is safe for concurrent use. It never re-establishes a connection
// it has already returned; see Dial.
type Client struct {
	// endpointText is how the endpoint is named in an error: the
	// configured string, plus the address it resolved to when those
	// differ. An operator debugging a timeout needs both.
	endpointText string

	// serverAddr is the in-tunnel control address, 10.99.0.1:443.
	serverAddr netip.AddrPort

	dialTimeout time.Duration

	dev *tunnelDevice

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// NewClient validates cfg, resolves the key material, brings up the
// WireGuard device, and pins the server as its only peer. It fails rather
// than returning a half-usable client: an unreachable secret store, key
// material that is not a 32-byte Curve25519 key, an endpoint that does not
// resolve, or a tunnel address outside 10.99.0.0/24 are all refused here,
// and on any failure the partially built device is closed before the error
// is returned.
//
// No packet is sent. The WireGuard handshake happens on the first Dial,
// which is where its failure is reported, per spec section 5.
//
// # Endpoint resolution
//
// The endpoint host is resolved exactly once, here, under a bounded
// context, because the WireGuard bind performs no name resolution.
//
// A name with several addresses yields one endpoint: the first address the
// resolver returns. WireGuard has one endpoint per peer and no failover in
// the protocol, so there is nothing to hand the extra addresses to, and
// trying each in turn would mean sending a handshake initiation to every
// address a name happens to point at. An operator who needs a specific
// address should configure an IP literal, which skips resolution entirely.
//
// An endpoint whose address changes later is not followed. This client goes
// on speaking to the address it resolved at construction; recovering means
// Close and NewClient. Note that the reverse case is handled: a client that
// changes network is WireGuard roaming, and the server relearns the peer's
// endpoint from its first valid authenticated packet (spec section 8.2).
func NewClient(cfg ClientConfig) (*Client, error) {
	host, port, err := splitEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := validPublicKey(cfg.ServerPubKey); err != nil {
		return nil, fmt.Errorf("gocloak: client: server public key %w", err)
	}
	if err := validSecretRef(cfg.PrivateKey); err != nil {
		// The reference is never echoed: an operator who pasted a
		// literal key where a reference belongs must not have it
		// copied into an error and from there into a log line.
		return nil, fmt.Errorf("gocloak: client: private key %w", err)
	}
	if err := validSecretRef(cfg.PresharedKey); err != nil {
		return nil, fmt.Errorf("gocloak: client: preshared key %w", err)
	}
	tunnelIP, err := clientTunnelIP(cfg.TunnelIP)
	if err != nil {
		return nil, err
	}
	if cfg.MTU != 0 && (cfg.MTU < minMTU || cfg.MTU > maxMTU) {
		return nil, fmt.Errorf("gocloak: client: mtu %d is not in %d-%d", cfg.MTU, minMTU, maxMTU)
	}
	if cfg.DialTimeout < 0 {
		return nil, fmt.Errorf("gocloak: client: dial timeout %s is negative", cfg.DialTimeout)
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = DefaultDialTimeout
	}

	endpoint, literal, err := resolveEndpoint(host, port)
	if err != nil {
		return nil, err
	}

	// Spec section 8.2: fail closed when the secret store is
	// unavailable. Both lookups happen before anything is created, so a
	// failure here leaves no device behind.
	ctx, cancel := context.WithTimeout(context.Background(), clientSecretResolveTimeout)
	defer cancel()

	resolver := &secretResolver{external: cfg.Resolver}
	privateKey, err := resolver.Resolve(ctx, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("gocloak: client: private key: %w", scrubRef(err, cfg.PrivateKey))
	}
	psk, err := resolver.Resolve(ctx, cfg.PresharedKey)
	if err != nil {
		return nil, fmt.Errorf("gocloak: client: preshared key: %w", scrubRef(err, cfg.PresharedKey))
	}

	dev, err := newTunnelDevice(deviceOptions{
		TunnelIP:   tunnelIP,
		MTU:        cfg.MTU,
		PrivateKey: privateKey,
		// An ephemeral source port. A client has nothing to listen
		// for: every session it takes part in, it started.
		ListenPort: 0,
		// Explicit: deviceLogSilent is the zero value, so omitting
		// this would discard wireguard-go's asynchronous errors.
		LogLevel: deviceLogError,
		Logf:     clientDeviceLogf,
	})
	if err != nil {
		return nil, err
	}

	if err := dev.AddPeer(devicePeer{
		PublicKey:    cfg.ServerPubKey,
		PresharedKey: psk,
		AllowedIP:    serverTunnelIP,
		Endpoint:     endpoint,
	}); err != nil {
		// The device is closed before the error is returned, so a
		// rejected peer does not leave a device and a bound UDP
		// socket behind.
		dev.Close()
		return nil, err
	}

	endpointText := cfg.Endpoint
	if !literal {
		endpointText = fmt.Sprintf("%s (resolved to %s)", cfg.Endpoint, endpoint)
	}

	return &Client{
		endpointText: endpointText,
		serverAddr:   netip.AddrPortFrom(serverTunnelIP, tunnelServicePort),
		dialTimeout:  dialTimeout,
		dev:          dev,
	}, nil
}

// clientDeviceLogf is the sink for wireguard-go's own error logging. It
// only ever receives wireguard-go's format strings, which carry no key
// material. A library has no logger of its own to hand out, so this goes to
// the standard logger, which an application can redirect.
func clientDeviceLogf(format string, args ...any) {
	log.Printf("gocloak: wireguard: %s", strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
}

// Dial opens a connection to a named service behind the server.
//
// It blocks until the WireGuard handshake completes, so the first call
// surfaces an authentication failure rather than handing back a connection
// that hangs. The whole call, the handshake and the hello exchange both, is
// bounded by ClientConfig.DialTimeout and by ctx, whichever expires first.
// A budget spent waiting on the handshake returns ErrHandshakeTimeout; a
// budget spent after the tunnel came up returns the context's own error,
// because at that point the handshake demonstrably succeeded and spec
// section 8.1 does not apply.
//
// The returned net.Conn is a plain byte pipe to the backend, and it is
// never re-established underneath the caller. Spec section 8.2: a tunnel
// that drops mid-session errors the connections that were on it, because
// transparently reconnecting one would silently reorder or duplicate
// application bytes. The application retries by calling Dial again. The
// device itself may re-handshake, which is WireGuard's business and does
// not swap a connection already handed out.
//
// A service the peer was not granted returns ErrDenied, a granted service
// whose backend is down returns ErrBackendUnavailable, and the remaining
// statuses return ErrRateLimited and ErrMalformedRequest, so the four are
// distinguishable with errors.Is.
func (c *Client) Dial(ctx context.Context, service string) (net.Conn, error) {
	// Validated before anything is opened, so a bad name fails locally
	// without touching the network, and the name that reaches the wire
	// is always within the charset spec section 4 fixes.
	if !ValidServiceName(service) {
		return nil, ErrInvalidServiceName
	}
	if c.closed.Load() {
		return nil, ErrClientClosed
	}

	// One budget for the whole call, not one for the tunnel and another
	// for the hello exchange. context.WithTimeout keeps a parent's
	// earlier deadline, so "DialTimeout or the caller's ctx, whichever
	// is sooner" needs no comparison here.
	budget, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()

	conn, err := c.dialControl(ctx, budget)
	if err != nil {
		return nil, err
	}
	if err := c.hello(budget, conn, service); err != nil {
		// Every failure of the exchange closes the connection here,
		// including the one where the watchdog is already closing it:
		// Close is idempotent, and a connection that is not returned
		// is never left open.
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// hello performs the hello exchange from spec section 4 on an established
// in-tunnel connection: write the service name, read the status, and clear
// the deadlines so the connection becomes a raw pipe.
//
// On any error the connection must be closed by the caller. On success the
// connection is safe to hand to the application: see finishHello for what
// "safe" has to mean here.
func (c *Client) hello(ctx context.Context, conn net.Conn, service string) error {
	// A watchdog, so a ctx that fires during the exchange ends it
	// promptly rather than at the deadline below.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	stopCalled := false
	defer func() {
		// Every path calls stop exactly once: this defer on the
		// error paths, finishHello on the success path.
		if !stopCalled {
			stop()
		}
	}()

	if err := conn.SetWriteDeadline(c.helloDeadline(ctx)); err != nil {
		return fmt.Errorf("gocloak: client: %w", err)
	}
	if err := writeHelloRequest(conn, service); err != nil {
		return c.helloError(ctx, err)
	}
	// The response read gets its own deadline, so a server that accepted
	// the request and then went quiet is bounded by the spec's value
	// rather than by whatever was left of the write's budget.
	if err := conn.SetReadDeadline(c.helloDeadline(ctx)); err != nil {
		return fmt.Errorf("gocloak: client: %w", err)
	}
	status, err := readHelloResponse(conn)
	if err != nil {
		return c.helloError(ctx, err)
	}
	if err := statusError(status, service); err != nil {
		return err
	}

	stopCalled = true
	return c.finishHello(ctx, conn, stop)
}

// finishHello unregisters the watchdog and prepares a connection to be
// handed to the application.
//
// The result of stop is load bearing. Per the context package's contract,
// stop reports false when the watchdog has ALREADY STARTED, which here
// means conn.Close is running, or about to run, in another goroutine. In
// that case the connection is being torn down and must not be returned:
// doing so would hand the caller an established, hello-completed connection
// that dies underneath it with no error, which surfaces in production only
// as an unexplained reset. The window is sub-microsecond, which is exactly
// why it has to be handled here rather than found in a test.
//
// It is a separate function so that branch can be exercised directly.
func (c *Client) finishHello(ctx context.Context, conn net.Conn, stop func() bool) error {
	if !stop() {
		return c.helloError(ctx, ctx.Err())
	}
	// Spec section 4: deadlines are cleared after the response. From
	// here the connection is a raw pipe, and a long idle session is
	// legitimate.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("gocloak: client: %w", err)
	}
	return nil
}

// helloDeadline is the deadline for one step of the hello exchange: the
// spec's value, or the remaining budget when that is sooner. Without the
// second half, DialTimeout would bound only the tunnel handshake and a
// server that accepted the connection and then stalled could hold a caller
// for helloReadDeadline beyond the budget it asked for, twice over.
func (c *Client) helloDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(helloReadDeadline)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		return d
	}
	return deadline
}

// DialContext exists so a *Client drops into http.Transport.DialContext and
// any driver that accepts a dialer. Per spec section 5 it ignores network
// and treats addr as the service name with any ":port" suffix stripped: the
// tunnel carries exactly one transport, and the port an application puts in
// a URL describes the backend, which the client never learns.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.Dial(ctx, serviceFromAddr(addr))
}

// Close shuts the tunnel down. Every connection on it breaks. It is safe to
// call more than once, and a Dial afterwards returns ErrClientClosed rather
// than panicking.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.closeOnce.Do(func() {
		if c.dev != nil {
			c.closeErr = c.dev.Close()
		}
	})
	return c.closeErr
}

// dialControl opens the in-tunnel TCP connection to the server's control
// port, retrying while the WireGuard handshake completes.
//
// Retrying is what makes Dial block on the handshake: until the tunnel is
// up, the SYN is dropped and no connection can be made, and once it is up
// the first attempt succeeds. budget is the whole call's bound, already the
// sooner of DialTimeout and the caller's ctx, so a handshake that never
// completes fails rather than hangs. ctx is the caller's own, used only to
// tell a cancellation apart from an expiry.
func (c *Client) dialControl(ctx, budget context.Context) (net.Conn, error) {
	start := time.Now()

	for {
		attemptCtx, attemptCancel := context.WithTimeout(budget, clientDialAttemptTimeout)
		conn, err := c.dev.Net().DialContextTCPAddrPort(attemptCtx, c.serverAddr)
		attemptCancel()
		if err == nil {
			return conn, nil
		}

		select {
		case <-budget.Done():
			// A caller who cancelled gets their own error back:
			// nothing timed out, they changed their mind.
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, fmt.Errorf("gocloak: client: dial %s: %w", c.endpointText, ctx.Err())
			}
			return nil, c.handshakeTimeoutError(handshakeBound(budget, start))
		case <-time.After(clientDialRetryInterval):
		}
	}
}

// handshakeBound is how long the client was prepared to wait: the budget's
// deadline, not the elapsed time it took to give up.
//
// Reporting the bound is what spec section 8.1's "after <d>" names, and it
// keeps the message byte for byte identical whatever the cause was. A
// measured elapsed time varies a little with the failure, and a message
// that varies with the failure is the beginning of exactly the
// distinguishing signal section 8.1 exists to deny.
//
// Both branches round to 100ms for the same reason. At 1ms resolution a
// scheduling delay over 500 microseconds between the deadline stamp and
// start reports 2.999s where another dial reports 3s, and that one
// character is a difference the message must not carry.
//
// budget always carries a deadline, since Dial builds it with
// context.WithTimeout. The fallback is for a caller that is not Dial.
func handshakeBound(budget context.Context, start time.Time) time.Duration {
	if deadline, ok := budget.Deadline(); ok {
		return deadline.Sub(start).Round(100 * time.Millisecond)
	}
	return time.Since(start).Round(100 * time.Millisecond)
}

// handshakeTimeoutError is the message spec section 8.1 fixes. Every
// possibility is named because the server, by design, will not say which
// one it was: silence to an unauthenticated party is a designed property of
// the endpoint, not an oversight, and narrowing this message is exactly the
// signal a scanner wants.
func (c *Client) handshakeTimeoutError(waited time.Duration) error {
	return fmt.Errorf("%w: no response from %s after %s. "+
		"The endpoint does not answer unauthenticated traffic, so this means one of: "+
		"wrong server public key, wrong client key, revoked peer, wrong PSK, "+
		"UDP blocked on this network, or the endpoint is down. "+
		"The server cannot tell you which. Check the server log for a peer entry",
		ErrHandshakeTimeout, c.endpointText, waited)
}

// helloError wraps a failure during the hello exchange. A cancelled or
// expired context is reported as such, because the watchdog above closes
// the connection on cancellation and the resulting I/O error would
// otherwise be reported as the server's fault.
func (c *Client) helloError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("gocloak: client: hello exchange with %s: %w", c.endpointText, ctxErr)
	}
	return fmt.Errorf("gocloak: client: hello exchange with %s: %w", c.endpointText, err)
}

// statusError maps a hello response status to its sentinel. statusOK is the
// only status that is not an error; an unrecognized one never reaches here,
// because readHelloResponse rejects it as a malformed frame.
//
// The service name is safe to echo: it passed ValidServiceName, whose
// charset exists so a name can never inject control characters into a log
// line.
func statusError(status status, service string) error {
	switch status {
	case statusOK:
		return nil
	case statusDenied:
		return fmt.Errorf("%w: %s", ErrDenied, service)
	case statusBackendUnavailable:
		return fmt.Errorf("%w: %s", ErrBackendUnavailable, service)
	case statusRateLimited:
		return fmt.Errorf("%w: %s", ErrRateLimited, service)
	case statusMalformed:
		return fmt.Errorf("%w: %s", ErrMalformedRequest, service)
	default:
		// Unreachable via readHelloResponse. Fail closed anyway: an
		// unknown status is never a success.
		return fmt.Errorf("gocloak: client: %s: unexpected status %s", service, status)
	}
}

// serviceFromAddr turns a dialer address into a service name by stripping
// any ":port" suffix. An addr with no port is already the name.
func serviceFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// splitEndpoint splits a "host:port" endpoint. The port must be a number in
// 1-65535: net.SplitHostPort accepts a service name like "https", and
// looking one up would make the tunnel's own address depend on /etc/services.
func splitEndpoint(endpoint string) (host string, port uint16, err error) {
	if endpoint == "" {
		return "", 0, errors.New("gocloak: client: endpoint is required")
	}
	h, p, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, fmt.Errorf("gocloak: client: endpoint %q must be host:port: %w", endpoint, err)
	}
	if h == "" {
		return "", 0, fmt.Errorf("gocloak: client: endpoint %q has no host", endpoint)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("gocloak: client: endpoint %q must end in a port number in 1-65535", endpoint)
	}
	return h, uint16(n), nil
}

// resolveEndpoint turns a host and port into the AddrPort the WireGuard
// bind needs, and reports whether the host was already an IP literal.
//
// See NewClient for what happens with several addresses and with an address
// that changes later.
func resolveEndpoint(host string, port uint16) (addr netip.AddrPort, literal bool, err error) {
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return netip.AddrPortFrom(ip.Unmap(), port), true, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientEndpointResolveTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("gocloak: client: resolve endpoint %q: %w", host, err)
	}
	if len(ips) == 0 {
		// Deny by default: a resolver that returned nothing is not a
		// reason to fall back to anything.
		return netip.AddrPort{}, false, fmt.Errorf("gocloak: client: endpoint %q resolved to no addresses", host)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), port), false, nil
}

// clientTunnelIP validates this peer's tunnel address against spec section
// 3.2. The server's address, the network address and the broadcast address
// are all refused: none of them can be a peer, and a client configured with
// one would fail later as an unexplained silence rather than here as a
// sentence.
func clientTunnelIP(addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, errors.New("gocloak: client: tunnel ip is required")
	}
	ip := addr.Unmap()
	if !tunnelSubnet.Contains(ip) {
		return netip.Addr{}, fmt.Errorf("gocloak: client: tunnel ip %s is outside the tunnel subnet %s", ip, tunnelSubnet)
	}
	if ip == serverTunnelIP {
		return netip.Addr{}, fmt.Errorf("gocloak: client: tunnel ip %s is the server address (spec section 3.2)", ip)
	}
	if ip == tunnelSubnet.Masked().Addr() || ip == subnetBroadcast(tunnelSubnet) {
		return netip.Addr{}, fmt.Errorf("gocloak: client: tunnel ip %s is not a host address in %s", ip, tunnelSubnet)
	}
	return ip, nil
}
