package gocloak

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// security_test.go: the tests that prove the threat model in spec section 7.
//
// Every top-level test name in this file contains "TestSecurity", because the
// verification command is `go test -run TestSecurity`, which matches by
// SUBSTRING: a test named otherwise is silently skipped, not failed.
//
// These tests reuse the device harness (device_test.go) and the server
// harness (server_test.go) rather than duplicating them. Nothing in either
// file is modified or weakened by this one.
// ---------------------------------------------------------------------------

// WireGuard message type numbers, from the protocol and from
// golang.zx2c4.com/wireguard/device/noise-protocol.go. They are duplicated
// here as untyped constants rather than imported, because the point of these
// tests is to read the bytes on the wire independently of the library that
// produced them.
const (
	wgTypeInitiation = 1
	wgTypeResponse   = 2
	// type 3 is a cookie reply, which the server only sends under load.
	wgTypeTransport = 4

	wgInitiationSize = 148
	wgResponseSize   = 92
)

// securityHandshakeWindow is how long a failing handshake is observed for.
// wireguard-go retransmits a handshake initiation every RekeyTimeout (5s)
// plus up to 334ms of jitter, so this window contains at least three
// initiation attempts. That matters: the claim under test is sustained
// silence, not that a single packet happened to go unanswered.
const securityHandshakeWindow = 12 * time.Second

// securityGrace is the quiet period observed after the client device is shut
// down, to catch a response that arrived late.
const securityGrace = 2 * time.Second

// securityProbeWait is how long a single raw UDP probe waits for an answer
// before concluding that none is coming.
const securityProbeWait = 3 * time.Second

// ---------------------------------------------------------------------------
// the UDP relay: the byte-counting mechanism for tests 1 and 2
// ---------------------------------------------------------------------------

// securityFlow is the packet census for one direction through the relay.
type securityFlow struct {
	Bytes   int64
	Packets int64
	ByType  map[uint32]int64
}

func (f *securityFlow) add(p []byte) {
	f.Bytes += int64(len(p))
	f.Packets++
	if f.ByType == nil {
		f.ByType = map[uint32]int64{}
	}
	f.ByType[securityMsgType(p)]++
}

func (f securityFlow) clone() securityFlow {
	out := securityFlow{Bytes: f.Bytes, Packets: f.Packets, ByType: map[uint32]int64{}}
	for k, v := range f.ByType {
		out.ByType[k] = v
	}
	return out
}

// securityMsgType reads the WireGuard message type, a little-endian uint32 in
// the first four bytes. A packet too short to carry one is reported as
// 0xffffffff so it can never be mistaken for a real type.
func securityMsgType(p []byte) uint32 {
	if len(p) < 4 {
		return 0xffffffff
	}
	return binary.LittleEndian.Uint32(p[:4])
}

// securityRelay is a UDP man in the middle between a client device and the
// server's WireGuard port. It forwards in both directions and counts every
// byte and every packet in each direction, which is what turns "the dial
// failed" into "the server sent exactly N bytes back".
//
// It is the observation point a network attacker would have: it sees only
// ciphertext and packet framing, and it never touches key material.
type securityRelay struct {
	down   *net.UDPConn   // faces the client; this is the address clients dial
	up     *net.UDPConn   // faces the server
	server netip.AddrPort // the real WireGuard port
	addr   netip.AddrPort // where a client points its Endpoint

	mu       sync.Mutex
	client   netip.AddrPort
	toServer securityFlow
	toClient securityFlow
}

func securityNewRelay(t *testing.T, serverPort int) *securityRelay {
	t.Helper()

	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	down, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatalf("relay client-side socket: %v", err)
	}
	up, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		down.Close()
		t.Fatalf("relay server-side socket: %v", err)
	}

	r := &securityRelay{
		down:   down,
		up:     up,
		server: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(serverPort)),
		addr:   down.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
	r.addr = netip.AddrPortFrom(r.addr.Addr().Unmap(), r.addr.Port())

	go r.pumpFromClient()
	go r.pumpFromServer()

	t.Cleanup(func() {
		down.Close()
		up.Close()
	})
	return r
}

func (r *securityRelay) pumpFromClient() {
	buf := make([]byte, 2048)
	for {
		n, from, err := r.down.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]

		r.mu.Lock()
		r.client = from
		r.toServer.add(pkt)
		r.mu.Unlock()

		if _, err := r.up.WriteToUDPAddrPort(pkt, r.server); err != nil {
			return
		}
	}
}

func (r *securityRelay) pumpFromServer() {
	buf := make([]byte, 2048)
	for {
		n, _, err := r.up.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]

		r.mu.Lock()
		r.toClient.add(pkt)
		client := r.client
		r.mu.Unlock()

		if !client.IsValid() {
			continue
		}
		if _, err := r.down.WriteToUDPAddrPort(pkt, client); err != nil {
			return
		}
	}
}

// snapshot returns the census for both directions.
func (r *securityRelay) snapshot() (toServer, toClient securityFlow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.toServer.clone(), r.toClient.clone()
}

// reset zeroes both censuses.
func (r *securityRelay) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.toServer = securityFlow{}
	r.toClient = securityFlow{}
}

// ---------------------------------------------------------------------------
// small shared helpers
// ---------------------------------------------------------------------------

// securityClientDevice brings up a client device with an arbitrary keypair,
// PSK and endpoint. serverHarness.client always uses the peer's real key
// material and the real server port, so it cannot express "wrong key",
// "wrong PSK", or "point at the relay". This does not replace it.
func securityClientDevice(t *testing.T, serverPub string, ip netip.Addr, priv, psk Secret, endpoint netip.AddrPort) *tunnelDevice {
	t.Helper()

	d, err := newTunnelDevice(deviceOptions{
		TunnelIP:   ip,
		PrivateKey: priv,
		LogLevel:   deviceLogSilent,
	})
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	if err := d.AddPeer(devicePeer{
		PublicKey:    serverPub,
		PresharedKey: psk,
		AllowedIP:    deviceTestServerIP,
		Endpoint:     endpoint,
	}); err != nil {
		t.Fatalf("client add server peer: %v", err)
	}
	return d
}

// securityExpectNoTunnel dials through the tunnel for the whole window and
// requires that no connection is ever established. The context deadline is
// what bounds it: this can never hang.
func securityExpectNoTunnel(t *testing.T, d *tunnelDevice, window time.Duration, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()
	conn, err := deviceTestDialRetry(ctx, d, serverTestTunnelAddr)
	if err == nil {
		conn.Close()
		t.Fatalf("%s: a tunnel connection was established, want none", what)
	}
}

// securityProbe sends one UDP payload to dst from a fresh source port and
// returns every byte that comes back within wait. A nil result means the
// endpoint answered nothing at all.
func securityProbe(t *testing.T, dst netip.AddrPort, payload []byte, wait time.Duration) []byte {
	t.Helper()

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("probe socket: %v", err)
	}
	defer c.Close()

	if _, err := c.WriteToUDPAddrPort(payload, dst); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("probe deadline: %v", err)
	}

	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil // deadline: nothing came back
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

// securityCaptureInitiation provokes a client device into emitting a
// handshake initiation and returns the exact bytes it put on the wire. The
// device's endpoint is a UDP socket that forwards nothing, so the captured
// initiation has provably never reached the server: it is unconsumed, which
// is what makes it usable as its own positive control in test 5.
func securityCaptureInitiation(t *testing.T, serverPub string, ip netip.Addr, priv, psk Secret) []byte {
	t.Helper()

	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("capture sink: %v", err)
	}
	defer sink.Close()

	sinkAddr := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	d := securityClientDevice(t, serverPub, ip, priv, psk,
		netip.AddrPortFrom(sinkAddr.Addr().Unmap(), sinkAddr.Port()))
	defer d.Close()

	// Provoke the handshake: a TCP SYN inside the tunnel is what makes the
	// device decide it needs a session. The dial can only fail, and it is
	// bounded by its own context.
	//
	// The provoking dial must outlive the sink read, not the other way
	// round: it is the goroutine holding the dial open that makes the
	// device retransmit, and WireGuard's RekeyTimeout puts a retransmit at
	// about 5.3s. Killing the provoker first would leave the reader
	// waiting for a packet nothing is going to send.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := deviceTestDialRetry(ctx, d, serverTestTunnelAddr); err == nil {
			c.Close()
		}
	}()

	if err := sink.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("capture deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := sink.ReadFromUDPAddrPort(buf)
	cancel()
	<-done
	if err != nil {
		t.Fatalf("no handshake initiation was emitted within 8s: %v", err)
	}

	if n != wgInitiationSize {
		t.Fatalf("captured packet is %d bytes, want a %d byte handshake initiation", n, wgInitiationSize)
	}
	if got := securityMsgType(buf[:n]); got != wgTypeInitiation {
		t.Fatalf("captured packet has message type %d, want %d (initiation)", got, wgTypeInitiation)
	}

	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

// ---------------------------------------------------------------------------
// Test 1: a key the server has never seen gets nothing back at all.
//
// Spec 7.1, first row: "Packets failing MAC1, keyed on the server public key,
// are dropped with zero response. No ICMP, no reset, no timing tell."
//
// This test measures two distinct silences:
//
//   - a syntactically perfect initiation from an unknown static key, which
//     passes MAC1 (MAC1 is keyed on the SERVER's public key, which any client
//     has) and is dropped when the peer lookup finds nothing;
//   - a packet that fails MAC1 outright.
//
// Both must be answered with exactly zero bytes.
// ---------------------------------------------------------------------------

func TestSecurityWrongClientKeyGetsZeroBytesBack(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	peer := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peer.Allow["db"] = backend.String()

	h := serverTestStart(t, peer)
	relay := securityNewRelay(t, h.udpPort)

	// A keypair the server's peers.yaml has never contained.
	strangerPriv, _ := deviceTestKeypair(t)

	// --- the measurement -------------------------------------------------
	//
	// The stranger runs FIRST, before any valid session has ever existed
	// through this relay. That ordering is deliberate: once a peer completes
	// a handshake, the server knows its endpoint and will send keepalives to
	// it, which would contaminate a later zero-bytes measurement.
	stranger := securityClientDevice(t, h.serverPub, peer.IP, strangerPriv, peer.PSK, relay.addr)
	securityExpectNoTunnel(t, stranger, securityHandshakeWindow, "unknown client key")

	// Shut the client down and stay quiet, so a late answer is still counted.
	if err := stranger.Close(); err != nil {
		t.Fatalf("close stranger device: %v", err)
	}
	time.Sleep(securityGrace)

	toServer, toClient := relay.snapshot()

	// The relay must have carried real traffic towards the server, or the
	// zero below means nothing.
	if toServer.ByType[wgTypeInitiation] < 2 {
		t.Fatalf("relay forwarded %d handshake initiations towards the server in %v, want at least 2 "+
			"(one retransmit), so the measurement covers sustained silence rather than a single packet",
			toServer.ByType[wgTypeInitiation], securityHandshakeWindow)
	}

	if toClient.Bytes != 0 || toClient.Packets != 0 {
		t.Fatalf("server sent %d bytes in %d packets back to an unknown client key, want exactly 0; by type: %v",
			toClient.Bytes, toClient.Packets, toClient.ByType)
	}

	// --- a packet that fails MAC1 ----------------------------------------
	//
	// Correct length and correct message type, everything else random, so
	// the MAC1 check itself is what rejects it.
	junk := make([]byte, wgInitiationSize)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("read random: %v", err)
	}
	binary.LittleEndian.PutUint32(junk[:4], wgTypeInitiation)

	serverPort := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.udpPort))
	if reply := securityProbe(t, serverPort, junk, securityProbeWait); reply != nil {
		t.Fatalf("a packet failing MAC1 was answered with %d bytes (type %d), want silence",
			len(reply), securityMsgType(reply))
	}

	// --- the positive control, mandatory ---------------------------------
	//
	// The SAME relay, now carrying the real peer's real key and real PSK,
	// must show a non-zero server-to-client count. Without this, a relay
	// that forwarded nothing would make the zero above vacuous.
	relay.reset()
	good := securityClientDevice(t, h.serverPub, peer.IP, peer.Priv, peer.PSK, relay.addr)
	conn, status := serverTestHello(t, good, "db")
	if status != StatusOK {
		t.Fatalf("positive control: status = %v, want ok", status)
	}
	conn.Close()

	_, ctlToClient := relay.snapshot()
	if ctlToClient.Bytes == 0 {
		t.Fatal("positive control: the server sent 0 bytes back through the relay even for a correct " +
			"key and PSK, so the relay is broken and the zero measured above proves nothing")
	}
	if ctlToClient.ByType[wgTypeResponse] == 0 {
		t.Fatalf("positive control: no handshake response came back through the relay; by type: %v",
			ctlToClient.ByType)
	}
	t.Logf("positive control through the same relay: server sent %d bytes in %d packets, by type %v",
		ctlToClient.Bytes, ctlToClient.Packets, ctlToClient.ByType)
}

// ---------------------------------------------------------------------------
// Test 2: correct key, wrong PSK.
//
// READ THIS BEFORE CHANGING THE ASSERTIONS.
//
// The task brief asks for "same, zero bytes back". That is not what Noise
// IKpsk2 does, and asserting it would be asserting something false. The PSK
// is mixed into the chaining key while the RESPONDER builds message 2
// (wireguard-go, device/noise-protocol.go, CreateMessageResponse). It plays
// no part in message 1. So a client holding the correct static key and the
// wrong PSK sends an initiation the server consumes successfully, and the
// server answers with a handshake response. The client then cannot derive the
// same keys and the session never forms.
//
// Spec 7.2 item 2 says exactly this is expected: "Silent to strangers, not
// steganographic. Anyone already holding the server public key can confirm
// the endpoint exists." A wrong-PSK client is not a stranger.
//
// Measured, on this implementation, over a 12 second window: the server
// answers each initiation with a 92 byte handshake response, and once it has
// learned the peer's endpoint it also sends handshake initiations of its own,
// which the wrong-PSK client answers and the server then cannot consume.
// Every packet in both directions is handshake framing.
//
// What this test proves instead, and it is the property that actually
// matters: the wrong PSK stops the handshake dead, and not one transport data
// packet crosses in either direction for the whole window.
// ---------------------------------------------------------------------------

func TestSecurityWrongPSKNeverCompletesAHandshake(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	peer := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peer.Allow["db"] = backend.String()

	h := serverTestStart(t, peer)
	relay := securityNewRelay(t, h.udpPort)

	// The peer's real private key, a PSK the server does not hold.
	wrongPSK := deviceTestPSK(t)
	if deviceTestB64(wrongPSK) == deviceTestB64(peer.PSK) {
		t.Fatal("the wrong PSK is the right PSK; the test would be vacuous")
	}

	bad := securityClientDevice(t, h.serverPub, peer.IP, peer.Priv, wrongPSK, relay.addr)
	securityExpectNoTunnel(t, bad, securityHandshakeWindow, "correct key, wrong PSK")

	if err := bad.Close(); err != nil {
		t.Fatalf("close wrong-PSK device: %v", err)
	}
	time.Sleep(securityGrace)

	toServer, toClient := relay.snapshot()
	t.Logf("wrong PSK census: client->server %d bytes / %d packets %v, server->client %d bytes / %d packets %v",
		toServer.Bytes, toServer.Packets, toServer.ByType,
		toClient.Bytes, toClient.Packets, toClient.ByType)

	// Guard against a relay that carried nothing: the zero asserted below
	// would then be vacuous. Both sides attempt a handshake here, because a
	// server that has learned a peer's endpoint will initiate too, so this
	// only requires that real handshake traffic crossed in both directions.
	if toServer.ByType[wgTypeInitiation] < 1 || toServer.Packets < 2 {
		t.Fatalf("relay carried %d packets towards the server (%v) in %v, want sustained handshake traffic",
			toServer.Packets, toServer.ByType, securityHandshakeWindow)
	}
	if toClient.Packets < 1 {
		t.Fatal("the server sent nothing at all, so the relay is one-directional and the absence of " +
			"transport data below proves nothing")
	}

	// No session, therefore no transport data, in either direction, for the
	// whole window. This is the assertion that carries the security claim.
	if toClient.ByType[wgTypeTransport] != 0 {
		t.Fatalf("server sent %d transport data packets to a wrong-PSK client, want 0; by type: %v",
			toClient.ByType[wgTypeTransport], toClient.ByType)
	}
	if toServer.ByType[wgTypeTransport] != 0 {
		t.Fatalf("wrong-PSK client sent %d transport data packets, want 0; by type: %v",
			toServer.ByType[wgTypeTransport], toServer.ByType)
	}

	// Everything that did cross is handshake framing. The server never
	// volunteers anything else to a peer it cannot key with.
	for typ, n := range toClient.ByType {
		if typ != wgTypeInitiation && typ != wgTypeResponse {
			t.Fatalf("server sent %d packets of message type %d to a wrong-PSK client, want handshake "+
				"messages only; by type: %v", n, typ, toClient.ByType)
		}
	}

	// --- the positive control, mandatory ---------------------------------
	//
	// The same relay, the same peer, the correct PSK. Transport data packets
	// must appear in both directions, which is what proves the zero counted
	// above is a real absence and not a relay that drops data packets or a
	// census that never learned to see them.
	relay.reset()
	good := securityClientDevice(t, h.serverPub, peer.IP, peer.Priv, peer.PSK, relay.addr)
	conn, status := serverTestHello(t, good, "db")
	if status != StatusOK {
		t.Fatalf("positive control: status = %v, want ok", status)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("positive control: write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
		t.Fatalf("positive control: read deadline: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := readFullConn(conn, buf); err != nil {
		t.Fatalf("positive control: read echo: %v", err)
	}
	conn.Close()

	ctlToServer, ctlToClient := relay.snapshot()
	if ctlToClient.ByType[wgTypeTransport] == 0 || ctlToServer.ByType[wgTypeTransport] == 0 {
		t.Fatalf("positive control: transport packets client->server %d, server->client %d, want both "+
			"non-zero; the relay or the census cannot see data packets, so the zero above proves nothing",
			ctlToServer.ByType[wgTypeTransport], ctlToClient.ByType[wgTypeTransport])
	}
	t.Logf("positive control through the same relay: server->client %d bytes in %d packets, by type %v",
		ctlToClient.Bytes, ctlToClient.Packets, ctlToClient.ByType)
}

// ---------------------------------------------------------------------------
// Test 3: revocation through the hot-reload path.
//
// Spec 7.1: "A peers file change triggers IpcSet with remove=true. The next
// packet from that key is dropped. No restart, no window."
//
// Rewriting peers.yaml is the real revocation mechanism, so that is what this
// test does. The before state is asserted all the way through to backend
// bytes, because a revocation test whose before state never worked proves
// nothing.
// ---------------------------------------------------------------------------

func TestSecurityRevokedPeerCanNoLongerConnect(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)

	doomed := serverTestNewPeer(t, "app-doomed", "10.99.0.7")
	doomed.Allow["db"] = backend.String()
	survivor := serverTestNewPeer(t, "app-survivor", "10.99.0.8")
	survivor.Allow["db"] = backend.String()

	h := serverTestStart(t, doomed, survivor)
	doomedClient := h.client(doomed)
	survivorClient := h.client(survivor)

	// --- before: the service really resolves and bytes really move -------
	exchange := func(d *tunnelDevice, who string) {
		t.Helper()
		conn, status := serverTestHello(t, d, "db")
		if status != StatusOK {
			t.Fatalf("%s: status = %v, want ok", who, status)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("%s: write to backend: %v", who, err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
			t.Fatalf("%s: read deadline: %v", who, err)
		}
		buf := make([]byte, 4)
		if _, err := readFullConn(conn, buf); err != nil {
			t.Fatalf("%s: read from backend: %v", who, err)
		}
		if string(buf) != "ping" {
			t.Fatalf("%s: backend echoed %q, want %q", who, buf, "ping")
		}
	}
	exchange(doomedClient, "before revocation, doomed peer")
	exchange(survivorClient, "before revocation, surviving peer")

	// --- revoke: rewrite peers.yaml without the peer ---------------------
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

	// --- after: the revoked key cannot establish anything ----------------
	//
	// The already-running device first: its keypairs were destroyed with the
	// peer, so an existing tunnel is torn down, not merely denied.
	securityExpectNoTunnel(t, doomedClient, 10*time.Second, "revoked peer, existing device")

	// Then a freshly built device with the same key material, so the claim
	// covers a reconnecting client and not just a stale session.
	fresh := securityClientDevice(t, h.serverPub, doomed.IP, doomed.Priv, doomed.PSK,
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.udpPort)))
	securityExpectNoTunnel(t, fresh, 8*time.Second, "revoked peer, fresh device")

	// The peer that stayed is untouched, so the failures above are
	// attributable to the revocation and not to a server that fell over.
	exchange(survivorClient, "after revocation, surviving peer")
}

// ---------------------------------------------------------------------------
// Test 4: cross-peer denial.
//
// Spec 7.1, blast radius: "A stolen client key reaches only that peer's named
// services."
//
// Both peers grant a service called "db", pointing at DIFFERENT backends, so
// a pass proves the server resolves the name inside the requesting peer's own
// grant map rather than in a global one. Then each peer asks for a name only
// the other holds and must be refused with StatusDenied (0x01).
// ---------------------------------------------------------------------------

func TestSecurityPeerCannotReachAnotherPeersService(t *testing.T) {
	backendA := serverTestNewBackend(t, func(c net.Conn) { defer c.Close(); c.Write([]byte("AAAA")) })
	backendB := serverTestNewBackend(t, func(c net.Conn) { defer c.Close(); c.Write([]byte("BBBB")) })

	peerA := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peerA.Allow["db"] = backendA.String()
	peerA.Allow["only-a"] = backendA.String()

	peerB := serverTestNewPeer(t, "app-b", "10.99.0.8")
	peerB.Allow["db"] = backendB.String()
	peerB.Allow["only-b"] = backendB.String()

	h := serverTestStart(t, peerA, peerB)
	clientA := h.client(peerA)
	clientB := h.client(peerB)

	greeting := func(d *tunnelDevice, service, who string) string {
		t.Helper()
		conn, status := serverTestHello(t, d, service)
		if status != StatusOK {
			t.Fatalf("%s asking for %q: status = %v, want ok", who, service, status)
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(serverTestDialBudget)); err != nil {
			t.Fatalf("%s: read deadline: %v", who, err)
		}
		buf := make([]byte, 4)
		if _, err := readFullConn(conn, buf); err != nil {
			t.Fatalf("%s: read from backend: %v", who, err)
		}
		return string(buf)
	}

	// Same service name, different backends: the name is resolved per peer.
	if got := greeting(clientA, "db", "peer A"); got != "AAAA" {
		t.Fatalf("peer A's %q reached %q, want its own backend AAAA", "db", got)
	}
	if got := greeting(clientB, "db", "peer B"); got != "BBBB" {
		t.Fatalf("peer B's %q reached %q, want its own backend BBBB", "db", got)
	}

	// Each peer asking for the other's exclusive service is refused, and the
	// other peer's backend never sees the connection.
	beforeA := backendA.conns.Load()
	beforeB := backendB.conns.Load()

	if conn, status := serverTestHello(t, clientA, "only-b"); status != StatusDenied {
		conn.Close()
		t.Fatalf("peer A asking for peer B's service: status = %v (0x%02x), want denied (0x01)",
			status, byte(status))
	} else {
		conn.Close()
	}
	if conn, status := serverTestHello(t, clientB, "only-a"); status != StatusDenied {
		conn.Close()
		t.Fatalf("peer B asking for peer A's service: status = %v (0x%02x), want denied (0x01)",
			status, byte(status))
	} else {
		conn.Close()
	}

	if after := backendB.conns.Load(); after != beforeB {
		t.Fatalf("peer B's backend saw %d new connections while peer A was denied, want 0", after-beforeB)
	}
	if after := backendA.conns.Load(); after != beforeA {
		t.Fatalf("peer A's backend saw %d new connections while peer B was denied, want 0", after-beforeA)
	}
}

// ---------------------------------------------------------------------------
// Test 5: a captured handshake initiation, replayed, is rejected.
//
// Spec 7.1, replay resistance: "64-bit nonce with a sliding receive window,
// plus TAI64N handshake timestamps rejecting replayed initiations."
//
// THIS TEST EXERCISES THE TAI64N HALF ONLY. It replays handshake message 1.
// It says nothing about the transport nonce window, which protects data
// packets and is not touched here.
//
// The mechanism, read from wireguard-go device/noise-protocol.go
// (ConsumeMessageInitiation):
//
//	replay := !timestamp.After(handshake.lastTimestamp)
//	flood  := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
//
// HandshakeInitationRate is 20ms. Every replay below is sent at least a
// second after the packet it duplicates, so the flood branch cannot be what
// rejects it, and the rejection is attributable to the TAI64N timestamp.
//
// The control is built in and is the strongest kind available: the SAME bytes
// are accepted on their first delivery and rejected on the second.
// ---------------------------------------------------------------------------

func TestSecurityReplayedHandshakeInitiationIsRejected(t *testing.T) {
	backend := serverTestNewBackend(t, serverTestEcho)
	peer := serverTestNewPeer(t, "app-a", "10.99.0.7")
	peer.Allow["db"] = backend.String()

	h := serverTestStart(t, peer)
	serverPort := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.udpPort))

	// Two valid initiations from the peer's real key material, each captured
	// off a socket that forwards nothing, so neither has ever reached the
	// server. The sleep guarantees distinct TAI64N stamps: wireguard-go
	// whitens the low 24 bits of the nanosecond field, so two stamps taken
	// inside ~16.7ms of each other can be equal.
	first := securityCaptureInitiation(t, h.serverPub, peer.IP, peer.Priv, peer.PSK)
	time.Sleep(100 * time.Millisecond)
	second := securityCaptureInitiation(t, h.serverPub, peer.IP, peer.Priv, peer.PSK)

	if string(first) == string(second) {
		t.Fatal("the two captured initiations are byte identical; the second is not a fresh handshake")
	}

	expectResponse := func(pkt []byte, what string) {
		t.Helper()
		reply := securityProbe(t, serverPort, pkt, securityProbeWait)
		if reply == nil {
			t.Fatalf("%s: the server answered nothing, so this initiation was never acceptable and "+
				"the replay assertion below would be vacuous", what)
		}
		if len(reply) != wgResponseSize || securityMsgType(reply) != wgTypeResponse {
			t.Fatalf("%s: the server answered %d bytes of message type %d, want a %d byte handshake response",
				what, len(reply), securityMsgType(reply), wgResponseSize)
		}
	}

	expectRejection := func(pkt []byte, what string) {
		t.Helper()
		if reply := securityProbe(t, serverPort, pkt, securityProbeWait); reply != nil {
			t.Fatalf("%s: the server answered %d bytes of message type %d, want silence: the replayed "+
				"initiation established a new session", what, len(reply), securityMsgType(reply))
		}
	}

	// First delivery of `first`: accepted. This is the positive control.
	expectResponse(first, "first delivery of initiation 1")

	// Same bytes again, well past the 20ms flood window: rejected by the
	// TAI64N timestamp comparison.
	time.Sleep(time.Second)
	expectRejection(first, "replay of initiation 1")

	// The server is still willing to handshake, so the silence above is
	// about these particular bytes being a duplicate and not about the
	// server having stopped answering.
	expectResponse(second, "first delivery of initiation 2")

	time.Sleep(time.Second)
	expectRejection(second, "replay of initiation 2")

	// An older initiation is still refused after a newer one was accepted:
	// the timestamp is a high-water mark, not a one-shot cache of the last
	// packet seen.
	expectRejection(first, "replay of initiation 1 after initiation 2 was accepted")

	// The tunnel still works for the legitimate client, so none of the above
	// left the server wedged.
	client := h.client(peer)
	conn, status := serverTestHello(t, client, "db")
	if status != StatusOK {
		t.Fatalf("after the replays, the real client got status %v, want ok", status)
	}
	conn.Close()
}
