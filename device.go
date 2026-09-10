package gocloak

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Log levels for deviceOptions.LogLevel. They mirror the wireguard-go
// levels so callers do not have to import golang.zx2c4.com/wireguard/device
// just to pick one.
const (
	deviceLogSilent  = device.LogLevelSilent
	deviceLogError   = device.LogLevelError
	deviceLogVerbose = device.LogLevelVerbose
)

// keepaliveInterval is the persistent keepalive applied to every peer, in
// seconds. Spec section 8.2: it keeps NAT bindings alive and makes a dead
// tunnel visible quickly instead of hanging.
const keepaliveInterval = 25

// deviceOptions is everything needed to bring up one userspace WireGuard
// device with a gVisor netstack TCP stack on top of it. Both the client and
// the server build one of these.
type deviceOptions struct {
	// TunnelIP is this device's own address inside 10.99.0.0/24. The
	// server holds 10.99.0.1; every client holds its assigned address.
	TunnelIP netip.Addr

	// MTU is the tunnel MTU. Zero means DefaultMTU (1280, the IPv6
	// minimum). Spec section 8.2: a too-large MTU blackholes TCP
	// silently and is the most common reason a userspace WireGuard
	// setup appears hung.
	MTU int

	// PrivateKey is this device's Curve25519 private key, base64
	// encoded, which is the form wg(8) and wg-quick use and therefore
	// the form an operator stores in a secret store. It is a Secret
	// rather than a string so that a %v or %+v on these options prints
	// a placeholder instead of the key (constraint 4).
	PrivateKey Secret

	// ListenPort is the UDP port to bind. The server sets its
	// configured port; a client passes 0 and gets an ephemeral port.
	ListenPort int

	// LogLevel is one of deviceLogSilent, deviceLogError or
	// deviceLogVerbose. It controls wireguard-go's own logging only.
	// Note that wireguard-go never logs key material at any level, and
	// neither does this file.
	LogLevel int

	// Logf is where wireguard-go's log lines go. Nil means log.Printf.
	Logf func(format string, args ...any)
}

// devicePeer is one WireGuard peer as this package configures it. Keys are
// base64 because that is what peers.yaml carries and what an operator
// pastes; conversion to the hex the UAPI wants happens here, in one place.
type devicePeer struct {
	// PublicKey is the peer's Curve25519 public key, base64 encoded.
	PublicKey string

	// PresharedKey is the 32-byte symmetric key mixed into the chaining
	// key, base64 encoded. It is required, never optional: spec section
	// 7.1 lists the PSK as the post-quantum hedge, so a peer configured
	// without one must fail rather than come up weaker than designed.
	// It is a Secret so a %v on this struct cannot print it.
	PresharedKey Secret

	// AllowedIP is the single tunnel address this peer is permitted to
	// source packets from, always applied as a /32. It is deliberately
	// not a prefix: cryptokey routing is the whole basis of peer
	// identity in spec section 3.2, and there is no case in this design
	// where a peer legitimately owns more than one address.
	AllowedIP netip.Addr

	// Endpoint is the peer's UDP address. The client sets it to the
	// server; the server leaves it zero and learns each client's
	// endpoint from the first valid authenticated packet. It is an
	// AddrPort, not a string, because the wireguard-go bind parses
	// endpoints with netip.ParseAddrPort and performs no name
	// resolution.
	Endpoint netip.AddrPort
}

// tunnelDevice is a running userspace WireGuard device and the netstack TCP
// stack layered on it. It is the transport both the client and the server
// build on: neither of them touches wireguard-go directly.
type tunnelDevice struct {
	tun tun.Device
	dev *device.Device
	net *netstack.Net

	closeOnce sync.Once
	closeErr  error
}

// newTunnelDevice brings up a WireGuard device with no peers and returns a
// handle to it. Peers are applied afterwards with AddPeer or UpdatePeer,
// so the caller controls whether a peer may be created or only updated.
//
// On any failure the partially built device is torn down before the error
// is returned: neither the TUN nor the wireguard-go device is leaked.
func newTunnelDevice(opts deviceOptions) (*tunnelDevice, error) {
	if !opts.TunnelIP.IsValid() {
		return nil, errors.New("gocloak: device: tunnel IP is required")
	}
	if !tunnelSubnet.Contains(opts.TunnelIP) {
		return nil, fmt.Errorf("gocloak: device: tunnel IP %s is outside %s", opts.TunnelIP, tunnelSubnet)
	}
	if opts.ListenPort < 0 || opts.ListenPort > 65535 {
		return nil, fmt.Errorf("gocloak: device: listen port %d is not in 0-65535", opts.ListenPort)
	}

	mtu := opts.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu < MinMTU || mtu > MaxMTU {
		return nil, fmt.Errorf("gocloak: device: mtu %d is not in %d-%d", mtu, MinMTU, MaxMTU)
	}

	privateKey, err := keyToHex(string(opts.PrivateKey.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("gocloak: device: private key: %w", err)
	}

	// No DNS servers: spec section 2 puts DNS resolution inside the
	// tunnel out of scope, so the stack is never given a resolver it
	// could be talked into using.
	tunDev, netStack, err := netstack.CreateNetTUN([]netip.Addr{opts.TunnelIP}, nil, mtu)
	if err != nil {
		return nil, fmt.Errorf("gocloak: device: create netstack tun: %w", err)
	}

	d := &tunnelDevice{tun: tunDev, net: netStack}

	d.dev = device.NewDevice(tunDev, conn.NewDefaultBind(), newDeviceLogger(opts.LogLevel, opts.Logf))

	// The config string below carries the private key. It is never
	// logged, at any level, not even truncated (constraint 4).
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privateKey)
	if opts.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", opts.ListenPort)
	}
	if err := d.dev.IpcSet(b.String()); err != nil {
		d.Close()
		return nil, fmt.Errorf("gocloak: device: configure: %w", err)
	}
	if err := d.dev.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("gocloak: device: bring up: %w", err)
	}
	return d, nil
}

// Net returns the netstack TCP stack bound to this device's tunnel address.
// Dialling and listening both go through it; there is no host networking
// path out of a tunnelDevice.
func (d *tunnelDevice) Net() *netstack.Net {
	return d.net
}

// AddPeer creates a peer, or updates it if a peer with that public key
// already exists.
func (d *tunnelDevice) AddPeer(p devicePeer) error {
	return d.applyPeer(p, false)
}

// UpdatePeer updates an existing peer and will not create one. If no peer
// holds that public key the call is a no-op, which is the fail-closed
// outcome: an entry meant to modify an existing grant must never bring a
// peer into existence.
func (d *tunnelDevice) UpdatePeer(p devicePeer) error {
	return d.applyPeer(p, true)
}

// RemovePeer removes the peer holding publicKey. The next packet from that
// key is dropped, which is the revocation path in spec section 7.1.
// Removing a peer that is not present is not an error.
func (d *tunnelDevice) RemovePeer(publicKey string) error {
	pub, err := keyToHex(publicKey)
	if err != nil {
		return fmt.Errorf("gocloak: device: remove peer: public key: %w", err)
	}
	if err := d.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pub)); err != nil {
		return fmt.Errorf("gocloak: device: remove peer: %w", err)
	}
	return nil
}

// applyPeer builds and applies one peer's UAPI block. Any error from
// IpcSet is returned, never logged and swallowed: a peer reported as
// applied when it was not means a revocation that silently did not happen.
func (d *tunnelDevice) applyPeer(p devicePeer, updateOnly bool) error {
	cfg, err := p.ipcConfig(updateOnly)
	if err != nil {
		return err
	}
	// cfg carries the preshared key. Never log it.
	if err := d.dev.IpcSet(cfg); err != nil {
		return fmt.Errorf("gocloak: device: apply peer: %w", err)
	}
	return nil
}

// ipcConfig renders one peer as a wireguard-go UAPI set block. The returned
// string contains key material and must never reach a log line.
func (p devicePeer) ipcConfig(updateOnly bool) (string, error) {
	pub, err := keyToHex(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("gocloak: device: peer: public key: %w", err)
	}
	psk, err := keyToHex(string(p.PresharedKey.Bytes()))
	if err != nil {
		return "", fmt.Errorf("gocloak: device: peer: preshared key: %w", err)
	}
	if !p.AllowedIP.IsValid() {
		return "", errors.New("gocloak: device: peer: allowed IP is required")
	}
	if !tunnelSubnet.Contains(p.AllowedIP) {
		return "", fmt.Errorf("gocloak: device: peer: allowed IP %s is outside %s", p.AllowedIP, tunnelSubnet)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if updateOnly {
		// Must follow public_key and precede everything else: it is
		// what turns a create into a refusal to create.
		b.WriteString("update_only=true\n")
	}
	fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	if p.Endpoint != (netip.AddrPort{}) {
		if !p.Endpoint.IsValid() || p.Endpoint.Port() == 0 {
			return "", fmt.Errorf("gocloak: device: peer: endpoint %s is not a usable address and port", p.Endpoint)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
	}
	// replace_allowed_ips, not an append: when a peer keeps its key and
	// moves to a new tunnel address, the old address must stop being
	// accepted from that key. Appending would leave the old identity
	// live forever.
	b.WriteString("replace_allowed_ips=true\n")
	fmt.Fprintf(&b, "allowed_ip=%s/32\n", p.AllowedIP)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveInterval)
	return b.String(), nil
}

// Close shuts the device down. It is safe to call more than once and safe
// to call on a device whose construction failed partway.
func (d *tunnelDevice) Close() error {
	d.closeOnce.Do(func() {
		switch {
		case d.dev != nil:
			// device.Close closes the TUN it was given, so the
			// TUN must not also be closed here: netstack's TUN
			// closes channels and would panic on a second close.
			d.dev.Close()
		case d.tun != nil:
			d.closeErr = d.tun.Close()
		}
	})
	return d.closeErr
}

// keyToHex converts a base64 32-byte WireGuard key to the lowercase hex
// encoding wireguard-go's UAPI requires. config.go validates public keys
// and PSK references in base64 because that is the wg(8) format operators
// paste; the UAPI speaks hex only, and a key handed over in the wrong
// encoding produces a device that silently never completes a handshake.
//
// Errors deliberately never echo the key or any part of it.
func keyToHex(b64 string) (string, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return "", errors.New("is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New("is not valid base64")
	}
	if len(raw) != wgKeyLen {
		return "", fmt.Errorf("decodes to %d bytes, want %d", len(raw), wgKeyLen)
	}
	return hex.EncodeToString(raw), nil
}

// newDeviceLogger builds a wireguard-go logger at the requested level. It
// exists instead of device.NewLogger so log lines can be routed into the
// caller's logger rather than hard-wired to stdout.
func newDeviceLogger(level int, logf func(format string, args ...any)) *device.Logger {
	if logf == nil {
		logf = log.Printf
	}
	lg := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	if level >= device.LogLevelVerbose {
		lg.Verbosef = logf
	}
	if level >= device.LogLevelError {
		lg.Errorf = logf
	}
	return lg
}
