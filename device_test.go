package gocloak

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// deviceTestKeypair generates a Curve25519 keypair in the base64 form
// operators paste and config.go validates. It deliberately does not shell
// out to the CLI: the library must be testable on its own.
func deviceTestKeypair(t *testing.T) (privKey secret, pubB64 string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	// Curve25519 clamping, as wg(8) genkey does.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	return deviceTestSecret(base64.StdEncoding.EncodeToString(priv[:])),
		base64.StdEncoding.EncodeToString(pub)
}

// deviceTestPSK generates a random 32-byte preshared key, base64 encoded.
func deviceTestPSK(t *testing.T) secret {
	t.Helper()
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return deviceTestSecret(base64.StdEncoding.EncodeToString(psk[:]))
}

// deviceTestSecret wraps a base64 key the way secretResolver.Resolve would.
func deviceTestSecret(b64 string) secret {
	return secret{value: []byte(b64)}
}

// deviceTestB64 returns a secret's base64 text, for assertions only.
func deviceTestB64(s secret) string {
	return string(s.bytes())
}

// deviceTestFreeUDPPort picks a UDP port that is free right now.
func deviceTestFreeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}
	return port
}

var (
	deviceTestServerIP = netip.MustParseAddr("10.99.0.1")
	deviceTestClientIP = netip.MustParseAddr("10.99.0.7")
)

// deviceTestPair brings up a server device and a client device over
// localhost UDP. clientPSK is configured on the client only, so a caller
// can hand it a wrong PSK and watch the handshake fail.
func deviceTestPair(t *testing.T, serverPSK, clientPSK secret) (server, client *tunnelDevice) {
	t.Helper()

	serverPriv, serverPub := deviceTestKeypair(t)
	clientPriv, clientPub := deviceTestKeypair(t)
	port := deviceTestFreeUDPPort(t)

	server, err := newTunnelDevice(deviceOptions{
		TunnelIP:   deviceTestServerIP,
		PrivateKey: serverPriv,
		ListenPort: port,
		LogLevel:   deviceLogSilent,
	})
	if err != nil {
		t.Fatalf("server device: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	if err := server.AddPeer(devicePeer{
		PublicKey:    clientPub,
		PresharedKey: serverPSK,
		AllowedIP:    deviceTestClientIP,
	}); err != nil {
		t.Fatalf("server add peer: %v", err)
	}

	client, err = newTunnelDevice(deviceOptions{
		TunnelIP:   deviceTestClientIP,
		PrivateKey: clientPriv,
		LogLevel:   deviceLogSilent,
	})
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if err := client.AddPeer(devicePeer{
		PublicKey:    serverPub,
		PresharedKey: clientPSK,
		AllowedIP:    deviceTestServerIP,
		Endpoint:     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
	}); err != nil {
		t.Fatalf("client add peer: %v", err)
	}
	return server, client
}

// ---------------------------------------------------------------------------
// key encoding
// ---------------------------------------------------------------------------

// TestDeviceKeyToHex checks the base64 to lowercase hex conversion against a
// known vector. wireguard-go's UAPI encodes keys as hex; operators paste
// base64. Getting this wrong yields a device that never handshakes.
func TestDeviceKeyToHex(t *testing.T) {
	// 32 bytes 0x00..0x1f, base64 encoded.
	const b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	const want = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	got, err := keyToHex(b64)
	if err != nil {
		t.Fatalf("keyToHex: %v", err)
	}
	if got != want {
		t.Fatalf("keyToHex = %q, want %q", got, want)
	}
	if strings.ToLower(got) != got {
		t.Fatalf("keyToHex returned uppercase hex %q", got)
	}
}

// TestDeviceKeyToHexRoundTrip checks the conversion against the standard
// library for a random key, and that surrounding whitespace (a trailing
// newline from a file: secret) is tolerated.
func TestDeviceKeyToHexRoundTrip(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(key[:])
	want := hex.EncodeToString(key[:])

	for _, in := range []string{b64, b64 + "\n", "  " + b64 + " \n"} {
		got, err := keyToHex(in)
		if err != nil {
			t.Fatalf("keyToHex(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("keyToHex(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDeviceKeyToHexRejectsBadInput checks that malformed keys are rejected
// rather than silently producing a device that cannot handshake, and that
// the error never echoes the input.
func TestDeviceKeyToHexRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"not base64", "!!!not base64!!!"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 31))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 33))},
		{"hex not base64", strings.Repeat("ab", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keyToHex(tc.in)
			if err == nil {
				t.Fatalf("keyToHex(%q) = %q, want an error", tc.in, got)
			}
			if tc.in != "" && strings.Contains(err.Error(), tc.in) {
				t.Fatalf("error echoes the input key: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UAPI config rendering
// ---------------------------------------------------------------------------

// TestDeviceIpcConfigAddPeer checks the peer block a device applies: hex
// keys, a /32 allowed IP, replace_allowed_ips so a moved peer's old address
// stops being accepted, and the keepalive from spec section 8.2.
func TestDeviceIpcConfigAddPeer(t *testing.T) {
	_, pub := deviceTestKeypair(t)
	psk := deviceTestPSK(t)
	p := devicePeer{
		PublicKey:    pub,
		PresharedKey: psk,
		AllowedIP:    deviceTestClientIP,
		Endpoint:     netip.MustParseAddrPort("198.51.100.7:51820"),
	}

	cfg, err := p.ipcConfig(false)
	if err != nil {
		t.Fatalf("ipcConfig: %v", err)
	}

	pubHex, _ := keyToHex(pub)
	pskHex, _ := keyToHex(deviceTestB64(psk))
	want := []string{
		"public_key=" + pubHex,
		"preshared_key=" + pskHex,
		"endpoint=198.51.100.7:51820",
		"replace_allowed_ips=true",
		"allowed_ip=10.99.0.7/32",
		"persistent_keepalive_interval=25",
	}
	for _, line := range want {
		if !strings.Contains(cfg, line+"\n") {
			t.Errorf("config is missing line %q", line)
		}
	}
	if strings.Contains(cfg, "update_only") {
		t.Error("AddPeer config must not set update_only")
	}
	if strings.Contains(cfg, pub) || strings.Contains(cfg, deviceTestB64(psk)) {
		t.Error("config carries a base64 key; the UAPI speaks hex only")
	}
}

// TestDeviceIpcConfigUpdateOnly checks that update_only immediately follows
// public_key. wireguard-go applies it positionally: anywhere later and the
// peer would already have been created.
func TestDeviceIpcConfigUpdateOnly(t *testing.T) {
	_, pub := deviceTestKeypair(t)
	p := devicePeer{
		PublicKey:    pub,
		PresharedKey: deviceTestPSK(t),
		AllowedIP:    deviceTestClientIP,
	}

	cfg, err := p.ipcConfig(true)
	if err != nil {
		t.Fatalf("ipcConfig: %v", err)
	}
	pubHex, _ := keyToHex(pub)
	lines := strings.Split(strings.TrimSuffix(cfg, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("config has %d lines, want at least 2", len(lines))
	}
	if lines[0] != "public_key="+pubHex {
		t.Fatalf("first line is %q, want the public key", lines[0])
	}
	if lines[1] != "update_only=true" {
		t.Fatalf("second line is %q, want update_only=true", lines[1])
	}
	if strings.Contains(cfg, "endpoint=") {
		t.Error("a peer with no endpoint must not emit an endpoint line")
	}
}

// TestDeviceIpcConfigRejectsIncompletePeer checks the fail-closed cases: a
// peer with no PSK, no allowed IP, or an allowed IP outside the tunnel
// subnet is refused rather than applied in a weakened form.
func TestDeviceIpcConfigRejectsIncompletePeer(t *testing.T) {
	_, pub := deviceTestKeypair(t)
	psk := deviceTestPSK(t)

	cases := []struct {
		name string
		peer devicePeer
	}{
		{"no public key", devicePeer{PresharedKey: psk, AllowedIP: deviceTestClientIP}},
		{"no preshared key", devicePeer{PublicKey: pub, AllowedIP: deviceTestClientIP}},
		{"no allowed ip", devicePeer{PublicKey: pub, PresharedKey: psk}},
		{"allowed ip outside subnet", devicePeer{
			PublicKey:    pub,
			PresharedKey: psk,
			AllowedIP:    netip.MustParseAddr("192.0.2.10"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if cfg, err := tc.peer.ipcConfig(false); err == nil {
				t.Fatalf("ipcConfig returned %q, want an error", cfg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// construction and lifecycle
// ---------------------------------------------------------------------------

// TestDeviceRejectsBadOptions checks that a device refuses to come up on a
// bad tunnel address, MTU or key rather than coming up misconfigured.
func TestDeviceRejectsBadOptions(t *testing.T) {
	priv, _ := deviceTestKeypair(t)

	cases := []struct {
		name string
		opts deviceOptions
	}{
		{"no tunnel ip", deviceOptions{PrivateKey: priv}},
		{"no private key", deviceOptions{TunnelIP: deviceTestClientIP}},
		{"tunnel ip outside subnet", deviceOptions{
			TunnelIP:   netip.MustParseAddr("192.0.2.10"),
			PrivateKey: priv,
		}},
		{"bad private key", deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: deviceTestSecret("nope")}},
		{"mtu too small", deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: priv, MTU: 576}},
		{"mtu too large", deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: priv, MTU: 9000}},
		{"listen port out of range", deviceOptions{
			TunnelIP:   deviceTestClientIP,
			PrivateKey: priv,
			ListenPort: 70000,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := newTunnelDevice(tc.opts)
			if err == nil {
				d.Close()
				t.Fatal("newTunnelDevice succeeded, want an error")
			}
			if d != nil {
				t.Fatalf("newTunnelDevice returned a device alongside an error: %v", err)
			}
		})
	}
}

// TestDeviceDefaultMTUIs1280 pins the default from spec section 8.2. A
// too-large MTU blackholes TCP silently, which is the hardest failure in
// this project to diagnose.
func TestDeviceDefaultMTUIs1280(t *testing.T) {
	if DefaultMTU != 1280 {
		t.Fatalf("DefaultMTU = %d, want 1280 (spec section 8.2)", DefaultMTU)
	}
	priv, _ := deviceTestKeypair(t)
	d, err := newTunnelDevice(deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: priv})
	if err != nil {
		t.Fatalf("newTunnelDevice: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	mtu, err := d.tun.MTU()
	if err != nil {
		t.Fatalf("tun MTU: %v", err)
	}
	if mtu != DefaultMTU {
		t.Fatalf("tun MTU = %d, want %d", mtu, DefaultMTU)
	}
}

// TestDeviceCloseIsIdempotent checks that Close can be called twice without
// panicking. netstack's TUN closes channels on Close, so a second close of
// the underlying TUN would be a panic, not an error.
func TestDeviceCloseIsIdempotent(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	d, err := newTunnelDevice(deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: priv})
	if err != nil {
		t.Fatalf("newTunnelDevice: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A handle whose construction never got as far as a TUN must also
	// be closeable without panicking.
	empty := &tunnelDevice{}
	if err := empty.Close(); err != nil {
		t.Fatalf("Close on an unbuilt device: %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatalf("second Close on an unbuilt device: %v", err)
	}
}

// TestDeviceConstructionFailureDoesNotLeak checks the partial-construction
// path: a second device asking for a UDP port already held must fail, and
// must not leave a live device or TUN behind. A leak here would show up as
// a panic or a hang on the second close.
func TestDeviceConstructionFailureDoesNotLeak(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	port := deviceTestFreeUDPPort(t)

	first, err := newTunnelDevice(deviceOptions{
		TunnelIP:   deviceTestServerIP,
		PrivateKey: priv,
		ListenPort: port,
	})
	if err != nil {
		t.Fatalf("first device: %v", err)
	}
	t.Cleanup(func() { first.Close() })

	priv2, _ := deviceTestKeypair(t)
	second, err := newTunnelDevice(deviceOptions{
		TunnelIP:   deviceTestClientIP,
		PrivateKey: priv2,
		ListenPort: port,
	})
	if err == nil {
		second.Close()
		t.Skip("this platform allows two UDP binds on the same port; nothing to assert")
	}
	if second != nil {
		t.Fatalf("newTunnelDevice returned a device alongside an error: %v", err)
	}
	if strings.Contains(err.Error(), deviceTestB64(priv2)) {
		t.Fatal("construction error echoes the private key")
	}
}

// TestDeviceUpdatePeerDoesNotCreate checks the fail-closed half of
// update_only: updating a peer that does not exist must leave it
// non-existent, never quietly grant it a place on the device.
func TestDeviceUpdatePeerDoesNotCreate(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	d, err := newTunnelDevice(deviceOptions{TunnelIP: deviceTestServerIP, PrivateKey: priv})
	if err != nil {
		t.Fatalf("newTunnelDevice: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	_, peerPub := deviceTestKeypair(t)
	peer := devicePeer{
		PublicKey:    peerPub,
		PresharedKey: deviceTestPSK(t),
		AllowedIP:    deviceTestClientIP,
	}
	peerHex, err := keyToHex(peerPub)
	if err != nil {
		t.Fatalf("keyToHex: %v", err)
	}

	if err := d.UpdatePeer(peer); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if devicePeerPresent(t, d, peerHex) {
		t.Fatal("UpdatePeer created a peer that did not exist")
	}

	if err := d.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !devicePeerPresent(t, d, peerHex) {
		t.Fatal("AddPeer did not create the peer")
	}

	if err := d.RemovePeer(peerPub); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if devicePeerPresent(t, d, peerHex) {
		t.Fatal("RemovePeer left the peer on the device")
	}
}

// devicePeerPresent reports whether the device holds a peer with the given
// hex public key. It reads the UAPI dump, which also contains the private
// key and PSKs, so the dump itself is never printed or returned.
func devicePeerPresent(t *testing.T, d *tunnelDevice, pubHex string) bool {
	t.Helper()
	dump, err := d.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	return strings.Contains(dump, "public_key="+pubHex+"\n")
}

// TestDeviceRejectsBadPeerKeys checks that applying a peer with an
// unusable key returns the error rather than reporting success. A peer
// reported as applied when it was not means a revocation that silently did
// not take effect.
func TestDeviceRejectsBadPeerKeys(t *testing.T) {
	priv, _ := deviceTestKeypair(t)
	d, err := newTunnelDevice(deviceOptions{TunnelIP: deviceTestServerIP, PrivateKey: priv})
	if err != nil {
		t.Fatalf("newTunnelDevice: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	_, peerPub := deviceTestKeypair(t)

	bad := devicePeer{PublicKey: "not-a-key", PresharedKey: deviceTestPSK(t), AllowedIP: deviceTestClientIP}
	if err := d.AddPeer(devicePeer{PublicKey: peerPub, AllowedIP: deviceTestClientIP}); err == nil {
		t.Error("AddPeer with no preshared key returned nil")
	}
	if err := d.AddPeer(bad); err == nil {
		t.Error("AddPeer with a bad public key returned nil")
	}
	if err := d.UpdatePeer(bad); err == nil {
		t.Error("UpdatePeer with a bad public key returned nil")
	}
	if err := d.RemovePeer("not-a-key"); err == nil {
		t.Error("RemovePeer with a bad public key returned nil")
	}
}

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------

// TestDeviceVerboseLogNeverLeaksKeyMaterial checks constraint 4 on the one
// path that could break it: the UAPI config string contains the private key
// and the PSK, so nothing on the logger path may reproduce it, even at the
// most verbose level.
func TestDeviceVerboseLogNeverLeaksKeyMaterial(t *testing.T) {
	var mu sync.Mutex
	var logged strings.Builder
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&logged, format+"\n", args...)
	}

	priv, _ := deviceTestKeypair(t)
	psk := deviceTestPSK(t)
	_, peerPub := deviceTestKeypair(t)

	d, err := newTunnelDevice(deviceOptions{
		TunnelIP:   deviceTestServerIP,
		PrivateKey: priv,
		LogLevel:   deviceLogVerbose,
		Logf:       logf,
	})
	if err != nil {
		t.Fatalf("newTunnelDevice: %v", err)
	}
	peer := devicePeer{PublicKey: peerPub, PresharedKey: psk, AllowedIP: deviceTestClientIP}
	if err := d.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := d.UpdatePeer(peer); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if err := d.RemovePeer(peerPub); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	privHex, _ := keyToHex(deviceTestB64(priv))
	pskHex, _ := keyToHex(deviceTestB64(psk))

	mu.Lock()
	out := logged.String()
	mu.Unlock()

	if out == "" {
		t.Fatal("verbose logging produced no output; the test would pass vacuously")
	}
	for _, secret := range []struct {
		name  string
		value string
	}{
		{"private key (base64)", deviceTestB64(priv)},
		{"private key (hex)", privHex},
		{"preshared key (base64)", deviceTestB64(psk)},
		{"preshared key (hex)", pskHex},
	} {
		if strings.Contains(out, secret.value) {
			t.Errorf("verbose log leaked the %s", secret.name)
		}
	}
}

// ---------------------------------------------------------------------------
// integration: a real tunnel over localhost UDP
// ---------------------------------------------------------------------------

// TestDeviceTunnelPassesBytesBothWays is the bring-up test: a real
// wireguard-go client and server over localhost UDP with a real netstack
// TCP stack on each side, exercising the Noise_IKpsk2 path with a PSK, and
// bytes crossing in both directions.
func TestDeviceTunnelPassesBytesBothWays(t *testing.T) {
	psk := deviceTestPSK(t)
	server, client := deviceTestPair(t, psk, psk)

	ln, err := server.Net().ListenTCPAddrPort(netip.AddrPortFrom(deviceTestServerIP, 443))
	if err != nil {
		t.Fatalf("listen on 10.99.0.1:443: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serveErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serveErr <- fmt.Errorf("accept: %w", err)
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := readFullConn(c, buf); err != nil {
			serveErr <- fmt.Errorf("server read: %w", err)
			return
		}
		if string(buf) != "ping" {
			serveErr <- fmt.Errorf("server read %q, want %q", buf, "ping")
			return
		}
		if _, err := c.Write([]byte("pong")); err != nil {
			serveErr <- fmt.Errorf("server write: %w", err)
			return
		}
		serveErr <- nil
	}()

	// The handshake is fast but not instant, and the listener has to be
	// wired up on the far side, so retry the dial under a bounded
	// deadline rather than sleeping a fixed amount.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := deviceTestDialRetry(ctx, client, netip.AddrPortFrom(deviceTestServerIP, 443))
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	// Client to server.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// Server to client.
	reply := make([]byte, 4)
	if _, err := readFullConn(conn, reply); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("client read %q, want %q", reply, "pong")
	}

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("server side: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server side did not finish")
	}
}

// TestDeviceWrongPSKBlocksHandshake is the first real test of the core
// security property: correct keys but a wrong preshared key must leave the
// handshake incomplete, so the dial fails within a bounded time rather than
// succeeding or hanging forever.
func TestDeviceWrongPSKBlocksHandshake(t *testing.T) {
	serverPSK := deviceTestPSK(t)
	clientPSK := deviceTestPSK(t)
	if deviceTestB64(serverPSK) == deviceTestB64(clientPSK) {
		t.Fatal("the two random PSKs collided")
	}
	server, client := deviceTestPair(t, serverPSK, clientPSK)

	ln, err := server.Net().ListenTCPAddrPort(netip.AddrPortFrom(deviceTestServerIP, 443))
	if err != nil {
		t.Fatalf("listen on 10.99.0.1:443: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	type result struct {
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		c, err := client.Net().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(deviceTestServerIP, 443))
		if c != nil {
			c.Close()
		}
		done <- result{err: err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("dial succeeded with a wrong preshared key")
		}
		t.Logf("dial failed after %s, as required: %v", time.Since(start).Round(time.Millisecond), r.err)
	case <-time.After(15 * time.Second):
		t.Fatal("dial neither succeeded nor failed; it hung")
	}
}

// deviceTestDialRetry dials through the tunnel, retrying until ctx expires.
// A WireGuard handshake takes a moment, and the first SYN is dropped while
// it completes.
func deviceTestDialRetry(ctx context.Context, d *tunnelDevice, addr netip.AddrPort) (net.Conn, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		c, err := d.Net().DialContextTCPAddrPort(dialCtx, addr)
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, lastErr
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// readFullConn reads exactly len(buf) bytes.
func readFullConn(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
		if m == 0 {
			return n, errors.New("read returned zero bytes")
		}
	}
	return n, nil
}

// TestDeviceLogLevelsMatchWireguard pins the re-exported log levels to
// wireguard-go's own, so a caller picking deviceLogError cannot silently
// select a different level after a dependency bump.
func TestDeviceLogLevelsMatchWireguard(t *testing.T) {
	if deviceLogSilent != device.LogLevelSilent {
		t.Errorf("deviceLogSilent = %d, want %d", deviceLogSilent, device.LogLevelSilent)
	}
	if deviceLogError != device.LogLevelError {
		t.Errorf("deviceLogError = %d, want %d", deviceLogError, device.LogLevelError)
	}
	if deviceLogVerbose != device.LogLevelVerbose {
		t.Errorf("deviceLogVerbose = %d, want %d", deviceLogVerbose, device.LogLevelVerbose)
	}
}

// TestDeviceOptionsFormatRedactsKeys checks constraint 4 at the type level:
// key-bearing fields are secret, so even a careless %+v on the options or on
// a peer prints a placeholder rather than the key.
func TestDeviceOptionsFormatRedactsKeys(t *testing.T) {
	priv, pub := deviceTestKeypair(t)
	psk := deviceTestPSK(t)

	opts := deviceOptions{TunnelIP: deviceTestClientIP, PrivateKey: priv}
	peer := devicePeer{PublicKey: pub, PresharedKey: psk, AllowedIP: deviceTestClientIP}

	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, out := range []string{
			fmt.Sprintf(format, opts),
			fmt.Sprintf(format, peer),
		} {
			if strings.Contains(out, deviceTestB64(priv)) {
				t.Errorf("%s leaked the private key", format)
			}
			if strings.Contains(out, deviceTestB64(psk)) {
				t.Errorf("%s leaked the preshared key", format)
			}
		}
	}
}
