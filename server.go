package gocloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelServicePort is the TCP port the server listens on inside the
// tunnel, per spec section 3.3. It is not configurable: the tunnel is a
// private address space with exactly one service in it, and a knob here
// would only be a way to deploy a client and a server that cannot talk.
const tunnelServicePort = 443

// backendDialTimeout bounds the dial to a real backend. Without it a
// blackholed backend address would pin a peer's concurrency slot until the
// operating system gave up, which is minutes.
const backendDialTimeout = 10 * time.Second

// secretResolveTimeout bounds one secret store lookup during a hot reload.
// The reload runs in the watcher's goroutine, so an unbounded lookup would
// stall every later reload, and revocation with it.
const secretResolveTimeout = 30 * time.Second

// unknownPeerName is what a tunnel address with no peer entry logs as. It
// is a literal, never the address and never anything else the connecting
// party influenced.
const unknownPeerName = "unknown"

// ServerConfig is the server's configuration, per spec section 5.
type ServerConfig struct {
	// ListenPort is the UDP port WireGuard binds on the public
	// interface. It is the only port this process opens to the internet.
	ListenPort int

	// PrivateKey references the server's Curve25519 private key. It is a
	// reference, not a value: the key is resolved at startup and lives in
	// memory only.
	PrivateKey SecretRef

	// TunnelIP is the server's address inside the tunnel, 10.99.0.1.
	TunnelIP netip.Addr

	// MTU is the tunnel MTU. Zero means DefaultMTU (1280).
	MTU int

	// PeersFile is the path to peers.yaml. It is watched and hot
	// reloaded, so a revocation takes effect without a restart.
	PeersFile string
}

// ServerConfigFrom maps the validated content of server.yaml onto a
// ServerConfig, so a daemon can load a file and run without restating
// every field. A nil argument yields the zero ServerConfig, which NewServer
// then rejects: there is no path where a missing config starts a server.
//
// ServerFileConfig.LogFormat is deliberately not carried over: spec
// section 5's ServerConfig has no such field. NewServer instead logs
// through slog.Default(), so a daemon that wants log_format to take
// effect sets the process-wide default (cmd/gocloak's serve command does
// this) before calling NewServer; absent that, slog.Default() is JSON,
// matching constraint 4's baseline.
func ServerConfigFrom(fc *ServerFileConfig) ServerConfig {
	if fc == nil {
		return ServerConfig{}
	}
	return ServerConfig{
		ListenPort: fc.ListenPort,
		PrivateKey: fc.PrivateKey,
		TunnelIP:   fc.TunnelIP,
		MTU:        fc.MTU,
		PeersFile:  fc.PeersFile,
	}
}

// Server terminates WireGuard tunnels, authorizes every connection against
// the peer policy, and proxies authorized connections to real backends.
//
// A Server is created by NewServer and used exactly once, by Run.
type Server struct {
	cfg ServerConfig

	// logger is the structured JSON logger every line goes through.
	// Constraint 4: peer name, service name, status and byte counts only.
	logger *slog.Logger

	// resolver resolves secret references. It is created on demand in Run
	// so a test can substitute one that needs no AWS.
	resolver *SecretResolver

	// onReloadApplied, if non-nil, is called after a reload has been
	// applied to the live device, with the watcher's result and the error
	// from applying it. It exists for tests; nothing in production sets
	// it.
	onReloadApplied func(ReloadResult, error)

	started atomic.Bool

	// baseCtx is Run's context, used by the watcher goroutine to bound
	// secret store lookups during a reload.
	baseCtx context.Context

	dev     *tunnelDevice
	watcher *PeerWatcher

	// mu guards the per-peer maps below, which are rebuilt on reload and
	// read by every connection.
	mu        sync.Mutex
	peerNames map[netip.Addr]string
	limiters  map[netip.Addr]*peerLimiter

	// secretMu guards pskCache. It is separate from mu so a slow secret
	// store lookup never blocks a connection's peer name lookup.
	secretMu sync.Mutex
	pskCache map[SecretRef]Secret

	wg sync.WaitGroup
}

// NewServer validates cfg and returns a Server ready to Run. It fails
// rather than returning a half-usable server: an out-of-range port, a
// private key that is a literal instead of a reference, a tunnel address
// that is not the server's, and a peers file that is missing or invalid are
// all refused here. Spec section 8.2: never start on an unvalidated peer
// list.
//
// NewServer does not contact the secret store and does not open a socket.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("gocloak: server: listen port %d is not in 1-65535", cfg.ListenPort)
	}
	if err := validSecretRef(cfg.PrivateKey); err != nil {
		// The reference is never echoed: an operator who pasted a
		// literal key where a reference belongs must not have it
		// copied into an error and from there into a log line.
		return nil, fmt.Errorf("gocloak: server: private key: %w", err)
	}
	if !cfg.TunnelIP.IsValid() {
		return nil, errors.New("gocloak: server: tunnel ip is required")
	}
	if cfg.TunnelIP.Unmap() != serverTunnelIP {
		return nil, fmt.Errorf("gocloak: server: tunnel ip must be %s (spec section 3.2)", serverTunnelIP)
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < MinMTU || cfg.MTU > MaxMTU {
		return nil, fmt.Errorf("gocloak: server: mtu %d is not in %d-%d", cfg.MTU, MinMTU, MaxMTU)
	}
	if cfg.PeersFile == "" {
		return nil, errors.New("gocloak: server: peers file is required")
	}
	cfg.TunnelIP = cfg.TunnelIP.Unmap()

	// Load the peers file once here so an invalid one refuses to start.
	// Run loads it again through the watcher, which is the copy that
	// stays in force; this pass exists purely to fail early and loudly.
	if _, err := LoadPeersConfig(cfg.PeersFile); err != nil {
		return nil, err
	}

	return &Server{
		cfg:       cfg,
		logger:    slog.Default(),
		peerNames: map[netip.Addr]string{},
		limiters:  map[netip.Addr]*peerLimiter{},
		pskCache:  map[SecretRef]Secret{},
	}, nil
}

// Run brings up the WireGuard device, applies the peer list, and serves the
// tunnel until ctx is cancelled. It returns nil on cancellation.
//
// Every startup failure is fatal and returns an error: an unreachable
// secret store, an unresolvable PSK, a device that will not come up, or a
// listener that will not bind. None of them start a degraded server.
func (s *Server) Run(ctx context.Context) (err error) {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("gocloak: server: Run has already been called")
	}
	s.baseCtx = ctx

	if s.resolver == nil {
		r, rerr := NewSecretResolver(ctx)
		if rerr != nil {
			return fmt.Errorf("gocloak: server: secret resolver: %w", rerr)
		}
		s.resolver = r
	}

	privateKey, kerr := s.resolveSecret(ctx, s.cfg.PrivateKey)
	if kerr != nil {
		return fmt.Errorf("gocloak: server: private key: %w", kerr)
	}

	// The watcher reloads and validates peers.yaml on every change and
	// keeps the previous good config in force when a reload fails.
	watcher, werr := NewPeerWatcher(s.cfg.PeersFile, s.handleReload)
	if werr != nil {
		return werr
	}
	s.watcher = watcher
	defer watcher.Close()

	// Registered before the device so it runs after the device is closed:
	// closing the device breaks every live connection, which is what lets
	// the in-flight handlers finish.
	defer s.wg.Wait()

	dev, derr := newTunnelDevice(deviceOptions{
		TunnelIP:   s.cfg.TunnelIP,
		MTU:        s.cfg.MTU,
		PrivateKey: privateKey,
		ListenPort: s.cfg.ListenPort,
		// Explicit: deviceLogSilent is the zero value, so omitting
		// this would discard wireguard-go's asynchronous errors.
		LogLevel: deviceLogError,
		Logf:     s.deviceLogf,
	})
	if derr != nil {
		return derr
	}
	s.dev = dev
	defer dev.Close()

	// Apply the initial peer list. A peer that cannot be applied stops
	// startup: a server that came up missing a peer, or with a peer that
	// has no PSK, is not the configuration the operator approved.
	initial := watcher.Config()
	for _, p := range initial.Peers {
		if aerr := s.applyPeer(ctx, p, false); aerr != nil {
			return aerr
		}
	}
	s.refreshPeers(initial)

	ln, lerr := dev.Net().ListenTCPAddrPort(netip.AddrPortFrom(s.cfg.TunnelIP, tunnelServicePort))
	if lerr != nil {
		return fmt.Errorf("gocloak: server: listen on %s:%d: %w", s.cfg.TunnelIP, tunnelServicePort, lerr)
	}
	defer ln.Close()

	runCtx, cancel := context.WithCancel(ctx)

	// The watcher goroutine is waited for before the device is closed, so
	// a reload can never apply a peer to a closed device.
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- watcher.Run(runCtx)
		// A dead watch means revocation has stopped working, which is
		// fatal: stop serving rather than serve with a peer list that
		// can no longer change.
		cancel()
	}()

	// These two defers are ordered deliberately. Deferred calls run in
	// reverse order, so cancel runs first and the wait second: waiting
	// first would hang forever on the path where Run returns with its
	// context still live, which is exactly the path a fatal accept error
	// takes.
	defer func() {
		watchErr := <-watchDone
		if err == nil && watchErr != nil {
			err = watchErr
		}
	}()
	defer cancel()

	// Unblock Accept on shutdown.
	go func() {
		<-runCtx.Done()
		ln.Close()
	}()

	s.logger.Info("gocloak: server listening",
		"listen_port", s.cfg.ListenPort,
		"tunnel_ip", s.cfg.TunnelIP.String(),
		"mtu", s.cfg.MTU,
		"peers_file", s.cfg.PeersFile,
		"peers", len(initial.Peers))

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("gocloak: server: accept: %w", aerr)
		}
		s.wg.Add(1)
		go s.handleConn(runCtx, conn)
	}
}

// deviceLogf is the sink for wireguard-go's own error logging. It only ever
// receives wireguard-go's format strings, which never carry key material.
func (s *Server) deviceLogf(format string, args ...any) {
	s.logger.Error("gocloak: wireguard", "message", strings.TrimRight(fmt.Sprintf(format, args...), "\n"))
}

// ---------------------------------------------------------------------------
// connection handling
// ---------------------------------------------------------------------------

// handleConn serves one accepted tunnel connection: derive the peer
// identity, read the hello frame, apply the peer's rate limits, resolve the
// policy, dial the backend, and pipe.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	start := time.Now()

	// Spec section 3.2: cryptokey routing guarantees a packet sourced
	// from 10.99.0.N came from the keypair bound to that address, so the
	// remote address is the authenticated identity. Nothing the peer
	// sends contributes to it.
	peerIP, ok := remoteTunnelIP(conn)
	if !ok {
		s.logger.Error("gocloak: dropped a connection whose remote address could not be parsed")
		return
	}
	peer := s.peerName(peerIP)

	// Limits are applied before the hello frame is read, not just before
	// the policy is consulted. The connection already costs a goroutine, a
	// netstack connection and a file descriptor by the time it is
	// accepted, and the hello read can sit on its deadline for five
	// seconds. Checking after that read would let a peer that connects and
	// says nothing hold an unbounded number of connections in flight, so
	// max_concurrent would bound nothing and one peer could starve every
	// other, which is precisely the abuse spec 8.2 names the cap for.
	//
	// The service name is not known here, so the two refusal lines below
	// carry no service field. That is the correct trade: the cap must be
	// applied at the moment the resource is committed.
	limiter, known := s.limiterFor(peerIP)
	if !known {
		// The peer's tunnel address is not in the peer list currently
		// in force. Cryptokey routing should already have dropped its
		// packets; reaching here means the peer was revoked mid
		// connection, or a RemovePeer failed and left a revoked keypair
		// live on the device.
		//
		// Nothing is written back. A status frame is a metered reply,
		// and the limiter is exactly what this path failed to find, so
		// answering here would hand an unmetered two bytes per
		// connection to a peer that is owed nothing. Closing in silence
		// is the fail-closed reading: spec section 7.1 makes silence to
		// an unauthorized party a designed property, not an oversight.
		s.logger.Warn("gocloak: connection from an address with no peer entry, closed without a reply",
			"peer", peer, "duration_ms", millis(start))
		return
	}
	if reason, allowed := limiter.acquire(time.Now()); !allowed {
		_ = s.respond(conn, StatusRateLimited)
		s.logger.Warn("gocloak: rate limited",
			"peer", peer, "status", StatusRateLimited.String(),
			"limit", reason, "duration_ms", millis(start))
		return
	}
	defer limiter.release()

	if err := conn.SetReadDeadline(time.Now().Add(HelloReadDeadline)); err != nil {
		s.logger.Error("gocloak: could not set the hello read deadline", "peer", peer, "error", err.Error())
		return
	}

	service, err := ReadHelloRequest(conn)
	if err != nil {
		if errors.Is(err, ErrMalformedFrame) {
			_ = s.respond(conn, StatusMalformed)
			s.logger.Warn("gocloak: malformed hello frame",
				"peer", peer, "status", StatusMalformed.String(), "duration_ms", millis(start))
			return
		}
		// Not malformed: an I/O error, or the peer sent nothing and
		// the deadline fired. There is nothing to respond to, so
		// nothing is written back. Spec section 7.1: the endpoint's
		// silence is a designed property.
		s.logger.Info("gocloak: connection closed before a hello frame arrived",
			"peer", peer, "duration_ms", millis(start), "error", err.Error())
		return
	}

	// The limiter already ran, above the hello read, so a peer cannot use
	// denied lookups as a free hammer either.
	backend, granted := s.watcher.Policy().Resolve(peerIP, service)
	if !granted {
		_ = s.respond(conn, StatusDenied)
		// Spec section 8.2: a request for a service the peer was not
		// granted is a security event, logged with peer and name.
		s.logger.Warn("gocloak: service denied",
			"peer", peer, "service", service, "status", StatusDenied.String(), "duration_ms", millis(start))
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, backendDialTimeout)
	backendConn, derr := (&net.Dialer{}).DialContext(dialCtx, "tcp", backend.String())
	cancel()
	if derr != nil {
		_ = s.respond(conn, StatusBackendUnavailable)
		s.logger.Warn("gocloak: backend unavailable",
			"peer", peer, "service", service, "status", StatusBackendUnavailable.String(),
			"backend", backend.String(), "duration_ms", millis(start), "error", derr.Error())
		return
	}
	defer backendConn.Close()

	// From here the connection is a live proxy pair, and after the
	// response below it has no deadlines left to expire it. Registering it
	// against the peer's limiter is what lets a revocation reap it: spec
	// section 8.2's "existing conns error out" has to hold when the peer
	// is removed too, not only when the tunnel drops.
	live := &liveConn{peerConn: conn, backendConn: backendConn}
	limiter.track(live)
	defer limiter.untrack(live)

	if err := s.respond(conn, StatusOK); err != nil {
		s.logger.Warn("gocloak: could not write the hello response",
			"peer", peer, "service", service, "duration_ms", millis(start), "error", err.Error())
		return
	}
	// Spec section 4: deadlines are cleared after the response. From here
	// the connection is a raw pipe with no further framing, and a long
	// idle session is legitimate.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.logger.Warn("gocloak: could not clear connection deadlines",
			"peer", peer, "service", service, "error", err.Error())
		return
	}

	sent, received := pipeConns(ctx, conn, backendConn)

	s.logger.Info("gocloak: connection closed",
		"peer", peer,
		"service", service,
		"status", StatusOK.String(),
		"bytes_sent", sent,
		"bytes_received", received,
		"duration_ms", millis(start))
}

// respond writes one hello response frame under a bounded write deadline,
// so a peer that stops reading cannot pin a goroutine forever.
func (s *Server) respond(conn net.Conn, status Status) error {
	if err := conn.SetWriteDeadline(time.Now().Add(HelloReadDeadline)); err != nil {
		return err
	}
	return WriteHelloResponse(conn, status)
}

// pipeConns copies bytes in both directions until either direction ends,
// then closes both sides. It returns the bytes written to the peer and the
// bytes read from the peer.
//
// Neither copy can outlive this call: both connections are closed when the
// first copy finishes, which unblocks the other, and a cancelled context
// closes both from outside.
func pipeConns(ctx context.Context, peerConn, backendConn net.Conn) (toPeer, fromPeer int64) {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			peerConn.Close()
			backendConn.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fromPeer, _ = io.Copy(backendConn, peerConn)
		backendConn.Close()
		peerConn.Close()
	}()
	go func() {
		defer wg.Done()
		toPeer, _ = io.Copy(peerConn, backendConn)
		peerConn.Close()
		backendConn.Close()
	}()
	wg.Wait()

	return toPeer, fromPeer
}

// remoteTunnelIP derives the authenticated peer identity from a connection's
// remote address, normalized with Unmap so an IPv4-in-IPv6 spelling, which
// netstack does hand back, keys the same policy entry as its IPv4 form.
func remoteTunnelIP(conn net.Conn) (netip.Addr, bool) {
	remote := conn.RemoteAddr()
	if remote == nil {
		return netip.Addr{}, false
	}
	if tcp, ok := remote.(*net.TCPAddr); ok {
		addr, ok := netip.AddrFromSlice(tcp.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return addr.Unmap(), true
	}
	ap, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// millis is a connection duration in milliseconds, for the log line.
func millis(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

// peerName maps a tunnel address to the peer name for logging. An address
// with no peer entry is the literal "unknown": a log line never carries
// text the connecting party influenced.
func (s *Server) peerName(ip netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name, ok := s.peerNames[ip.Unmap()]; ok {
		return name
	}
	return unknownPeerName
}

// limiterFor returns the rate limiter for a peer, and reports whether that
// peer is in the peer list currently in force.
func (s *Server) limiterFor(ip netip.Addr) (*peerLimiter, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.limiters[ip.Unmap()]
	return l, ok
}

// refreshPeers rebuilds the name map and the limiter set from the peer list
// now in force. A limiter for a peer that survived the reload is kept, so
// its in-flight connections keep their accounting; a limiter for a peer
// that is gone is dropped, and every connection still proxying for that peer
// is closed.
//
// The close matters: removing the peer from the device stops it sending, but
// an already-established connection is a raw pipe with its deadlines cleared,
// so without this its backend connection and both file descriptors would stay
// open for as long as the backend held them, and the peer's concurrency slot
// would never be returned. Spec section 8.2 requires existing connections to
// error out, on the server side as well as the client side.
func (s *Server) refreshPeers(cfg *PeersConfig) {
	// Populated under the lock, closed after it is released: closing a
	// connection wakes the handler that owns it, and that handler takes
	// the limiter's own lock on its way out.
	var gone []*peerLimiter

	s.mu.Lock()

	names := make(map[netip.Addr]string, len(cfg.Peers))
	limiters := make(map[netip.Addr]*peerLimiter, len(cfg.Peers))
	for _, p := range cfg.Peers {
		ip := p.TunnelIP.Unmap()
		names[ip] = p.Name
		if l, ok := s.limiters[ip]; ok {
			// Limiters are keyed by tunnel address, not by public key,
			// so if one reload removes a peer and adds a different one
			// at the same address, the new peer inherits the old one's
			// live concurrency count and its partly spent bucket. That
			// is deliberate: the count reflects connections that are
			// still open on this device at that address, and the
			// stricter reading is the fail-closed one. The inherited
			// count drains as those connections close.
			l.setLimits(p.Limits)
			limiters[ip] = l
			continue
		}
		limiters[ip] = newPeerLimiter(p.Limits)
	}

	kept := make(map[*peerLimiter]struct{}, len(limiters))
	for _, l := range limiters {
		kept[l] = struct{}{}
	}
	for _, l := range s.limiters {
		if _, ok := kept[l]; !ok {
			gone = append(gone, l)
		}
	}

	s.peerNames = names
	s.limiters = limiters
	s.mu.Unlock()

	for _, l := range gone {
		l.closeLive()
	}
}

// ---------------------------------------------------------------------------
// hot reload
// ---------------------------------------------------------------------------

// handleReload applies one reload to the live device. It runs in the
// watcher's goroutine, which Run waits for before closing the device.
func (s *Server) handleReload(r ReloadResult) {
	if r.Err != nil {
		// Spec section 8.2: the previous good config stays in force
		// and the failure is logged loudly. A typo must neither
		// revoke everyone nor widen access.
		s.logger.Error("gocloak: peers file reload FAILED, the previous peer list is still in force",
			"path", r.Path, "peers_in_force", r.PeerCount, "error", r.Err.Error())
		s.notifyReload(r, nil)
		return
	}

	// refreshPeers runs first, and the ordering is load bearing in both
	// directions.
	//
	// Added peer: applyDiff installs the keypair and the watcher has
	// already swapped in the new policy, so running applyDiff first left a
	// window where a brand new peer could hand shake, be granted its
	// service, and still be refused for having no limiter entry. Building
	// the limiter set first closes that window.
	//
	// Removed peer: still fail closed. The policy swap already happened
	// inside the watcher before this callback, so the removed peer's
	// grants are gone regardless. refreshPeers now drops its limiter and
	// closes its in-flight connections, and every later connection from it
	// hits the no-entry path above and is closed in silence. applyDiff
	// then destroys the keypair. Every step in that window denies; none of
	// them grants.
	//
	// The ordering inside applyDiff is untouched: removals still go first
	// there.
	s.refreshPeers(s.watcher.Config())
	applyErr := s.applyDiff(r.Diff)
	s.pruneSecretCache()

	switch {
	case applyErr != nil:
		s.logger.Error("gocloak: peers file reloaded but NOT fully applied to the device",
			"path", r.Path,
			"peers", r.PeerCount,
			"added", peerNames(r.Diff.Added),
			"removed", peerNames(r.Diff.Removed),
			"changed", peerNames(r.Diff.Changed),
			"error", applyErr.Error())
	case !r.Diff.IsEmpty():
		s.logger.Info("gocloak: peers file reloaded",
			"path", r.Path,
			"peers", r.PeerCount,
			"added", peerNames(r.Diff.Added),
			"removed", peerNames(r.Diff.Removed),
			"changed", peerNames(r.Diff.Changed))
	}

	s.notifyReload(r, applyErr)
}

func (s *Server) notifyReload(r ReloadResult, err error) {
	if s.onReloadApplied != nil {
		s.onReloadApplied(r, err)
	}
}

// applyDiff applies one peer diff to the live device.
//
// Removals go first, always. Revocation must take effect at the earliest
// possible instant, and a failure later in the diff must not have delayed
// it. Every step's error is collected and returned rather than swallowed: a
// revocation that silently failed is the worst outcome this design has.
func (s *Server) applyDiff(d PeerDiff) error {
	if s.dev == nil {
		return errors.New("gocloak: server: reload arrived before the device existed")
	}

	ctx, cancel := context.WithTimeout(s.baseCtx, secretResolveTimeout)
	defer cancel()

	var errs []error

	for _, p := range d.Removed {
		if err := s.dev.RemovePeer(p.PublicKey); err != nil {
			s.logger.Error("gocloak: PEER REVOCATION FAILED, that peer may still have access",
				"peer", p.Name, "error", err.Error())
			errs = append(errs, fmt.Errorf("revoke peer %s: %w", p.Name, err))
			continue
		}
		s.logger.Warn("gocloak: peer revoked", "peer", p.Name)
	}
	for _, p := range d.Added {
		if err := s.applyPeer(ctx, p, false); err != nil {
			s.logger.Error("gocloak: could not add peer", "peer", p.Name, "error", err.Error())
			errs = append(errs, err)
			continue
		}
		s.logger.Info("gocloak: peer added", "peer", p.Name)
	}
	for _, p := range d.Changed {
		if err := s.applyPeer(ctx, p, true); err != nil {
			s.logger.Error("gocloak: could not update peer", "peer", p.Name, "error", err.Error())
			errs = append(errs, err)
			continue
		}
		s.logger.Info("gocloak: peer updated", "peer", p.Name)
	}

	return errors.Join(errs...)
}

// applyPeer resolves a peer's PSK and applies the peer to the device.
// updateOnly=true never creates a peer, which is what a Changed entry
// means: it modifies an existing grant and must not bring one into being.
func (s *Server) applyPeer(ctx context.Context, p PeerConfig, updateOnly bool) error {
	psk, err := s.resolveSecret(ctx, p.PSK)
	if err != nil {
		return fmt.Errorf("gocloak: server: peer %s: psk: %w", p.Name, err)
	}
	dp := devicePeer{
		PublicKey:    p.PublicKey,
		PresharedKey: psk,
		AllowedIP:    p.TunnelIP,
	}
	if updateOnly {
		if err := s.dev.UpdatePeer(dp); err != nil {
			return fmt.Errorf("gocloak: server: peer %s: %w", p.Name, err)
		}
		return nil
	}
	if err := s.dev.AddPeer(dp); err != nil {
		return fmt.Errorf("gocloak: server: peer %s: %w", p.Name, err)
	}
	return nil
}

// resolveSecret resolves a reference, caching the result so a reload does
// not re-hit the secret store for a peer whose reference did not change.
//
// The cache is keyed by reference and lives for the process lifetime, so a
// secret rotated IN PLACE under the same reference is never picked up
// without a restart. Rotate by writing the new value under a new reference
// and pointing peers.yaml at it, which reloads like any other edit.
// Revocation is unaffected either way: it removes the peer from the device
// rather than depending on the value behind a reference.
//
// The returned error never carries the reference itself: secret.go's errors
// name the reference they failed on, and constraint 4 keeps a reference out
// of a log line, so it is scrubbed here rather than at every call site.
func (s *Server) resolveSecret(ctx context.Context, ref SecretRef) (Secret, error) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()

	if sec, ok := s.pskCache[ref]; ok {
		return sec, nil
	}
	sec, err := s.resolver.Resolve(ctx, ref)
	if err != nil {
		return Secret{}, scrubRef(err, ref)
	}
	s.pskCache[ref] = sec
	return sec, nil
}

// pruneSecretCache drops cached key material for references no longer in
// the peer list, so a revoked peer's PSK does not stay resident.
func (s *Server) pruneSecretCache() {
	inUse := map[SecretRef]struct{}{s.cfg.PrivateKey: {}}
	for _, p := range s.watcher.Config().Peers {
		inUse[p.PSK] = struct{}{}
	}

	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	for ref := range s.pskCache {
		if _, ok := inUse[ref]; !ok {
			delete(s.pskCache, ref)
		}
	}
}

// redactedError carries a scrubbed message while keeping the original error
// reachable, so errors.Is and errors.As still work on a scrubbed error.
// Only Error() is redacted; a caller that unwraps deliberately gets the
// original, and a caller that formats or logs gets the scrubbed text.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// scrubRef removes a secret reference from an error message. A reference is
// not key material, but constraint 4 keeps it out of logs, and this error
// is on its way to one.
//
// Both the whole reference and its payload are removed. secret.go wraps the
// underlying os and AWS errors, which repeat the bare path or id without
// the scheme prefix, so scrubbing only the full reference would leave
// "secret: [REDACTED REF]: open /etc/psk: permission denied" with the path
// still in it. Over-redaction is the acceptable direction here: a garbled
// error is a smaller problem than a leaked one.
func scrubRef(err error, ref SecretRef) error {
	if err == nil {
		return nil
	}
	msg := strings.ReplaceAll(err.Error(), string(ref), redactedRefPlaceholder)
	if _, payload, perr := parseSecretRef(ref); perr == nil && payload != "" {
		msg = strings.ReplaceAll(msg, payload, redactedRefPlaceholder)
	}
	return &redactedError{msg: msg, err: err}
}

// redactedRefPlaceholder is what a scrubbed reference reads as in a log.
const redactedRefPlaceholder = "[REDACTED REF]"

// ---------------------------------------------------------------------------
// per-peer limits
// ---------------------------------------------------------------------------

// peerLimiter holds one peer's two caps from spec section 8.2: concurrent
// streams, and dials per second as a token bucket whose burst equals its
// rate.
//
// A dial that is refused for concurrency has already spent its token. That
// is deliberate: a peer hammering a full concurrency cap should not bank a
// full burst for the moment a slot frees up.
//
// It also owns the set of connections currently proxying for that peer, so
// a revocation can reap them. The limiter is the natural home for that set:
// it is already the per-peer object, already created and dropped by
// refreshPeers on exactly the reload boundary a revocation crosses, and
// already the thing that counts a connection as live.
type peerLimiter struct {
	mu            sync.Mutex
	maxConcurrent int
	rate          float64
	burst         float64
	tokens        float64
	last          time.Time
	active        int
	live          map[*liveConn]struct{}
}

// liveConn is one proxied connection: the peer side and the backend side.
// Closing both is what unblocks the io.Copy pair in pipeConns and lets
// handleConn unwind through its own defers.
type liveConn struct {
	peerConn    net.Conn
	backendConn net.Conn
}

func newPeerLimiter(l PeerLimits) *peerLimiter {
	p := &peerLimiter{last: time.Now(), live: map[*liveConn]struct{}{}}
	p.setLimits(l)
	p.mu.Lock()
	p.tokens = p.burst
	p.mu.Unlock()
	return p
}

// setLimits applies a peer's limits, which a hot reload can change. The
// bucket is clamped to the new burst so lowering a limit takes effect
// immediately rather than after the old allowance drains.
func (p *peerLimiter) setLimits(l PeerLimits) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConcurrent = l.MaxConcurrent
	p.rate = float64(l.DialsPerSecond)
	p.burst = float64(l.DialsPerSecond)
	if p.tokens > p.burst {
		p.tokens = p.burst
	}
}

// acquire takes one dial token and one concurrency slot. On refusal it
// names which cap refused, for the log line, and takes no slot.
func (p *peerLimiter) acquire(now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if elapsed := now.Sub(p.last); elapsed > 0 {
		p.last = now
		p.tokens += elapsed.Seconds() * p.rate
		if p.tokens > p.burst {
			p.tokens = p.burst
		}
	}

	if p.tokens < 1 {
		return "dials_per_second", false
	}
	p.tokens--

	// A limit of zero or less denies. Validated config never produces
	// one, so this is the fail-closed reading of an impossible value.
	if p.active >= p.maxConcurrent {
		return "max_concurrent", false
	}
	p.active++
	return "", true
}

// release returns a concurrency slot.
func (p *peerLimiter) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active > 0 {
		p.active--
	}
}

// track registers a proxied connection as live for this peer.
func (p *peerLimiter) track(c *liveConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live[c] = struct{}{}
}

// untrack deregisters a proxied connection that has finished on its own.
func (p *peerLimiter) untrack(c *liveConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.live, c)
}

// closeLive closes both sides of every connection still proxying for this
// peer. It is called when the peer leaves the peer list.
//
// The set is drained under the lock and the closes happen outside it: each
// close wakes the handler that owns that connection, and that handler calls
// untrack and release on its way out, which take this same lock.
func (p *peerLimiter) closeLive() {
	p.mu.Lock()
	conns := make([]*liveConn, 0, len(p.live))
	for c := range p.live {
		conns = append(conns, c)
	}
	clear(p.live)
	p.mu.Unlock()

	for _, c := range conns {
		c.peerConn.Close()
		c.backendConn.Close()
	}
}
