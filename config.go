package gocloak

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Configuration defaults and bounds. These are values, not knobs: a config
// file may omit a field and get the default, but there is no way to widen
// the bounds without editing this file.
const (
	// DefaultMTU is the tunnel MTU when server.yaml omits one. Spec
	// section 8.2 fixes it at 1280, the IPv6 minimum, because a too-large
	// MTU blackholes TCP silently.
	DefaultMTU = 1280
	// MinMTU is the smallest accepted MTU: below the IPv6 minimum, the
	// tunnel cannot carry a conforming packet.
	MinMTU = 1280
	// MaxMTU is the largest accepted MTU. A tunnel MTU above a standard
	// Ethernet MTU cannot survive a path across the public internet.
	MaxMTU = 1500

	// DefaultMaxConcurrent is the per-peer concurrent stream cap applied
	// when a peer omits limits.
	DefaultMaxConcurrent = 32
	// DefaultDialsPerSecond is the per-peer dial rate cap applied when a
	// peer omits limits.
	DefaultDialsPerSecond = 10

	// DefaultLogFormat is the log format when server.yaml omits one.
	DefaultLogFormat = "json"

	// wgKeyLen is the length in bytes of a Curve25519 key, which is what
	// a peer's base64 public_key must decode to.
	wgKeyLen = 32
)

// reloadDebounce is how long the watcher waits for a file to stop changing
// before reloading it. One editor save can fire several filesystem events;
// without this, one save triggers several reloads.
const reloadDebounce = 50 * time.Millisecond

// watchRearmInterval is how often the watcher re-adds its directory watch
// and re-checks the file's identity even if no event arrived. A watcher
// that dies silently means revocation stops working, which is the worst
// failure this project has, so the event stream is not the only path to a
// reload.
const watchRearmInterval = 30 * time.Second

// tunnelSubnet is the tunnel address space fixed by spec section 3.2. Every
// peer address must fall inside it, which with the network, broadcast, and
// server addresses excluded is the documented 253-peer cap.
var tunnelSubnet = netip.MustParsePrefix("10.99.0.0/24")

// serverTunnelIP is the server's tunnel address, fixed by spec section 3.2.
// No peer may claim it: a peer sitting on the server address would have its
// grants consulted for traffic that appears to originate from the server.
var serverTunnelIP = netip.MustParseAddr("10.99.0.1")

// ---------------------------------------------------------------------------
// server.yaml
// ---------------------------------------------------------------------------

// serverYAML is the on-disk shape of server.yaml. It is deliberately
// separate from the validated ServerFileConfig: every field here is the raw
// scalar as written by an operator, so parsing and validation happen in one
// place instead of being spread across yaml.Unmarshaler implementations.
type serverYAML struct {
	ListenPort int       `yaml:"listen_port"`
	PrivateKey SecretRef `yaml:"private_key"`
	TunnelIP   string    `yaml:"tunnel_ip"`
	MTU        int       `yaml:"mtu"`
	PeersFile  string    `yaml:"peers_file"`
	LogFormat  string    `yaml:"log_format"`
}

// ServerFileConfig is the validated content of server.yaml. Secret-bearing
// fields hold references, not values: decoding never contacts a secret
// store, so the server resolves PrivateKey at startup and a config test
// needs no AWS.
type ServerFileConfig struct {
	ListenPort int
	PrivateKey SecretRef
	TunnelIP   netip.Addr
	MTU        int
	PeersFile  string
	LogFormat  string
}

// LoadServerConfig reads, decodes and fully validates server.yaml. An
// unrecognized key is a hard error, never a silent ignore: a typo in a
// security-relevant key must fail loudly rather than quietly granting or
// revoking access.
func LoadServerConfig(path string) (*ServerFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: read %s: %w", path, err)
	}

	var raw serverYAML
	if err := decodeStrict(data, &raw); err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: %w", path, err)
	}

	cfg := &ServerFileConfig{
		ListenPort: raw.ListenPort,
		PrivateKey: raw.PrivateKey,
		MTU:        raw.MTU,
		PeersFile:  raw.PeersFile,
		LogFormat:  raw.LogFormat,
	}

	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("gocloak: config: %s: listen_port %d is not in 1-65535", path, cfg.ListenPort)
	}
	if err := validSecretRef(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: private_key: %w", path, err)
	}

	addr, err := parseTunnelIP(raw.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: tunnel_ip: %w", path, err)
	}
	if addr != serverTunnelIP {
		return nil, fmt.Errorf("gocloak: config: %s: tunnel_ip must be the server address %s (spec section 3.2)", path, serverTunnelIP)
	}
	cfg.TunnelIP = addr

	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < MinMTU || cfg.MTU > MaxMTU {
		return nil, fmt.Errorf("gocloak: config: %s: mtu %d is not in %d-%d", path, cfg.MTU, MinMTU, MaxMTU)
	}

	if cfg.PeersFile == "" {
		return nil, fmt.Errorf("gocloak: config: %s: peers_file is required", path)
	}

	if cfg.LogFormat == "" {
		cfg.LogFormat = DefaultLogFormat
	}
	if cfg.LogFormat != "json" && cfg.LogFormat != "text" {
		return nil, fmt.Errorf("gocloak: config: %s: log_format must be json or text", path)
	}

	return cfg, nil
}

// ---------------------------------------------------------------------------
// peers.yaml
// ---------------------------------------------------------------------------

// peersYAML is the on-disk shape of peers.yaml.
type peersYAML struct {
	Peers []peerYAML `yaml:"peers"`
}

type peerYAML struct {
	Name      string            `yaml:"name"`
	PublicKey string            `yaml:"public_key"`
	PSK       SecretRef         `yaml:"psk"`
	TunnelIP  string            `yaml:"tunnel_ip"`
	Limits    limitsYAML        `yaml:"limits"`
	Allow     map[string]string `yaml:"allow"`
}

type limitsYAML struct {
	MaxConcurrent  int `yaml:"max_concurrent"`
	DialsPerSecond int `yaml:"dials_per_second"`
}

// PeerLimits are the per-peer caps from spec section 8.2's abusive peer row.
type PeerLimits struct {
	MaxConcurrent  int
	DialsPerSecond int
}

// PeerConfig is one validated peer entry from peers.yaml. PSK holds a
// reference, never resolved key material, so a PeerConfig can be compared,
// diffed and passed around without any secret in it.
//
// A PeerConfig handed out by a PeerWatcher is immutable by contract: it is
// shared with every other reader of the same reload, so callers must treat
// it, and the Allow map inside it, as read-only.
type PeerConfig struct {
	Name      string
	PublicKey string // base64 Curve25519, validated to decode to 32 bytes
	PSK       SecretRef
	TunnelIP  netip.Addr
	Limits    PeerLimits
	Allow     map[string]netip.AddrPort
}

// equal reports whether two peer entries are identical in every field that
// the server acts on, so an unchanged entry is not reported as changed.
func (p PeerConfig) equal(o PeerConfig) bool {
	return p.Name == o.Name &&
		p.PublicKey == o.PublicKey &&
		p.PSK == o.PSK &&
		p.TunnelIP == o.TunnelIP &&
		p.Limits == o.Limits &&
		maps.Equal(p.Allow, o.Allow)
}

// PeersConfig is the validated content of peers.yaml together with the
// Policy built from it. It is produced whole or not at all: a PeersConfig
// that exists has already passed every check, so there is never a
// half-built value in circulation.
type PeersConfig struct {
	Peers  []PeerConfig
	Policy *Policy
}

// peerNames returns the peer names in order, for logging. Only names, never
// key material, belong in a log line.
func peerNames(peers []PeerConfig) []string {
	names := make([]string, 0, len(peers))
	for _, p := range peers {
		names = append(names, p.Name)
	}
	return names
}

// LoadPeersConfig reads, decodes and fully validates peers.yaml, then builds
// the Policy. Any error means nothing is returned: the caller keeps whatever
// it already had.
//
// An empty peers list is valid and means nobody may connect. An empty file
// is not: a zero-byte peers.yaml is far more likely a truncated write than a
// deliberate revocation of everyone.
func LoadPeersConfig(path string) (*PeersConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: read %s: %w", path, err)
	}

	var raw peersYAML
	if err := decodeStrict(data, &raw); err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: %w", path, err)
	}

	peers := make([]PeerConfig, 0, len(raw.Peers))
	names := make(map[string]struct{}, len(raw.Peers))
	keys := make(map[string]struct{}, len(raw.Peers))
	ips := make(map[netip.Addr]struct{}, len(raw.Peers))

	for i, rp := range raw.Peers {
		p, err := validatePeer(rp)
		if err != nil {
			return nil, fmt.Errorf("gocloak: config: %s: peers[%d]: %w", path, i, err)
		}
		if _, dup := names[p.Name]; dup {
			return nil, fmt.Errorf("gocloak: config: %s: peers[%d]: duplicate peer name %s", path, i, p.Name)
		}
		if _, dup := keys[p.PublicKey]; dup {
			return nil, fmt.Errorf("gocloak: config: %s: peers[%d]: peer %s: duplicate public_key", path, i, p.Name)
		}
		if _, dup := ips[p.TunnelIP]; dup {
			return nil, fmt.Errorf("gocloak: config: %s: peers[%d]: peer %s: duplicate tunnel_ip %s", path, i, p.Name, p.TunnelIP)
		}
		names[p.Name] = struct{}{}
		keys[p.PublicKey] = struct{}{}
		ips[p.TunnelIP] = struct{}{}
		peers = append(peers, p)
	}

	policies := make([]PeerPolicy, 0, len(peers))
	for _, p := range peers {
		policies = append(policies, PeerPolicy{TunnelIP: p.TunnelIP, Allow: p.Allow})
	}
	policy, err := NewPolicy(policies)
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: %w", path, err)
	}

	return &PeersConfig{Peers: peers, Policy: policy}, nil
}

// validatePeer turns one raw YAML peer entry into a validated PeerConfig.
// Every check that can be made without contacting a secret store is made
// here, at load time, so a bad entry can never reach a lookup.
func validatePeer(rp peerYAML) (PeerConfig, error) {
	// The peer name reaches log lines, so it is held to the same charset
	// as a service name: no control characters, no spaces, nothing that
	// could forge a second field in a log record.
	if rp.Name == "" {
		return PeerConfig{}, errors.New("name is required")
	}
	if !ValidServiceName(rp.Name) {
		return PeerConfig{}, errors.New("name must match [a-z0-9][a-z0-9-]{0,62}")
	}

	if err := validPublicKey(rp.PublicKey); err != nil {
		return PeerConfig{}, fmt.Errorf("peer %s: public_key: %w", rp.Name, err)
	}
	if err := validSecretRef(rp.PSK); err != nil {
		return PeerConfig{}, fmt.Errorf("peer %s: psk: %w", rp.Name, err)
	}

	addr, err := parseTunnelIP(rp.TunnelIP)
	if err != nil {
		return PeerConfig{}, fmt.Errorf("peer %s: tunnel_ip: %w", rp.Name, err)
	}
	if !tunnelSubnet.Contains(addr) {
		return PeerConfig{}, fmt.Errorf("peer %s: tunnel_ip %s is outside the tunnel subnet %s", rp.Name, addr, tunnelSubnet)
	}
	if addr == serverTunnelIP {
		return PeerConfig{}, fmt.Errorf("peer %s: tunnel_ip %s is the server address", rp.Name, addr)
	}
	if addr == tunnelSubnet.Masked().Addr() || addr == subnetBroadcast(tunnelSubnet) {
		return PeerConfig{}, fmt.Errorf("peer %s: tunnel_ip %s is not a host address in %s", rp.Name, addr, tunnelSubnet)
	}

	limits := PeerLimits{
		MaxConcurrent:  rp.Limits.MaxConcurrent,
		DialsPerSecond: rp.Limits.DialsPerSecond,
	}
	if limits.MaxConcurrent < 0 || limits.DialsPerSecond < 0 {
		return PeerConfig{}, fmt.Errorf("peer %s: limits must not be negative", rp.Name)
	}
	if limits.MaxConcurrent == 0 {
		limits.MaxConcurrent = DefaultMaxConcurrent
	}
	if limits.DialsPerSecond == 0 {
		limits.DialsPerSecond = DefaultDialsPerSecond
	}

	allow := make(map[string]netip.AddrPort, len(rp.Allow))
	for name, backend := range rp.Allow {
		if !ValidServiceName(name) {
			// The name is not echoed: it has not passed validation, so
			// it must not reach a log or error line.
			return PeerConfig{}, fmt.Errorf("peer %s: allow: invalid service name", rp.Name)
		}
		ap, err := netip.ParseAddrPort(backend)
		if err != nil {
			// Names are not resolved anywhere in this project, so a
			// hostname here is an error, not a lookup.
			return PeerConfig{}, fmt.Errorf("peer %s: allow: %s: backend must be a literal ip:port", rp.Name, name)
		}
		if !ap.IsValid() || ap.Port() == 0 {
			return PeerConfig{}, fmt.Errorf("peer %s: allow: %s: backend port must not be zero", rp.Name, name)
		}
		allow[name] = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}

	return PeerConfig{
		Name:      rp.Name,
		PublicKey: rp.PublicKey,
		PSK:       rp.PSK,
		TunnelIP:  addr,
		Limits:    limits,
		Allow:     allow,
	}, nil
}

// decodeStrict decodes exactly one YAML document into v with unknown keys
// rejected. An empty stream and a second document are both errors: the
// first is a truncated file, the second would let a stray "---" hide a
// whole peer list.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty document")
		}
		return sanitizeYAMLError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return errors.New("file contains more than one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return sanitizeYAMLError(err)
	}
	return nil
}

// sanitizeYAMLError strips scalar values out of yaml.v3's type-mismatch
// messages, which embed the first seven characters of the offending value.
// None of the four secret-bearing fields is int-typed, so none can trigger
// one, but a key pasted into mtu, listen_port or a limits field would put a
// prefix of that key into an error and from there into a log line, and
// constraint 4 is unqualified.
//
// Classification is per message, because yaml.v3 appends three distinct
// classes into one TypeError. See sanitizeYAMLMessage: unknown-field and
// already-set messages are kept verbatim, a duplicate mapping key keeps both
// its line numbers but loses the key, and everything else keeps only its
// line number.
func sanitizeYAMLError(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		// Parser errors report structure (a missing colon, a bad
		// indent), not scalar values.
		return err
	}
	msgs := make([]string, 0, len(te.Errors))
	for _, m := range te.Errors {
		msgs = append(msgs, sanitizeYAMLMessage(m))
	}
	return errors.New("yaml: " + strings.Join(msgs, "; "))
}

// Markers for the three message classes yaml.v3 appends into one TypeError.
// They differ in whether they can carry text taken from the document, which
// is the only thing that decides whether a message may be kept verbatim.
const (
	// yamlDupKeyPrefix and yamlDupKeySuffix bracket
	// "mapping key %#v already defined at line %d". The key is arbitrary
	// document text (under allow: it is operator-supplied, and this fires
	// during decode, before ValidServiceName ever runs), so the key is
	// redacted and only the two line numbers survive.
	yamlDupKeyPrefix = "mapping key "
	yamlDupKeySuffix = " already defined at line "

	// yamlUnknownFieldMarker matches "field %s not found in type %s", the
	// unknown-key diagnostic that makes a typo in a security-relevant key
	// findable.
	yamlUnknownFieldMarker = " not found in type "

	// yamlFieldSetMarker matches "field %s already set in type %s". That
	// name is a resolved struct field, so it comes from this file's own
	// struct tags and never from the document: a key the struct does not
	// have would have produced the unknown-field message instead.
	yamlFieldSetMarker = " already set in type "
)

// sanitizeYAMLMessage redacts one message from a yaml.v3 TypeError, keeping
// as much diagnostic structure as can be kept without echoing document text.
func sanitizeYAMLMessage(m string) string {
	prefix := yamlLinePrefix(m)
	rest := m[len(prefix):]

	// The duplicate-key class is tested FIRST and by prefix, not by a
	// loose substring. Its key is arbitrary document text, so a key
	// containing the marker of another class would otherwise be
	// classified into that class and kept verbatim. The other two classes
	// begin "field ", so they can never be mistaken for this one.
	if strings.HasPrefix(rest, yamlDupKeyPrefix) {
		// LastIndex, not Index: a key that itself contains the suffix
		// must not truncate the message early. The real suffix is
		// always the last one.
		if i := strings.LastIndex(rest, yamlDupKeySuffix); i >= 0 {
			return prefix + yamlDupKeyPrefix + "(redacted)" + rest[i:]
		}
	}

	// Neither of these embeds a value, so both keep their line numbers,
	// their key or field name, and their type name.
	if strings.Contains(rest, yamlUnknownFieldMarker) || strings.Contains(rest, yamlFieldSetMarker) {
		return m
	}

	// Everything else in a TypeError is a type mismatch, whose text
	// embeds the first seven characters of the offending scalar.
	return prefix + "value is not valid for this field (value redacted)"
}

// yamlLinePrefix returns the "line N: " prefix of a yaml.v3 error message,
// which is the only part of a type-mismatch message safe to keep.
func yamlLinePrefix(msg string) string {
	if !strings.HasPrefix(msg, "line ") {
		return ""
	}
	i := strings.Index(msg, ": ")
	if i < 0 {
		return ""
	}
	return msg[:i+2]
}

// parseTunnelIP parses a tunnel address and normalizes it. An IPv4-in-IPv6
// mapped spelling does not compare equal to its plain IPv4 form under
// netip.Addr equality, so Unmap runs here, once, before the address is used
// as a map key or handed to NewPolicy. Without it, two spellings of one
// address would slip past the duplicate check.
func parseTunnelIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, errors.New("is required")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errors.New("is not a valid ip address")
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, errors.New("must not be the unspecified address")
	}
	return addr, nil
}

// subnetBroadcast returns the all-ones host address of an IPv4 prefix.
func subnetBroadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// validPublicKey checks that a peer public key is base64 that decodes to
// exactly 32 bytes. This is the key itself, not a reference, so it is
// validated here in full.
func validPublicKey(s string) error {
	if s == "" {
		return errors.New("is required")
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return errors.New("is not valid base64")
	}
	if len(key) != wgKeyLen {
		return fmt.Errorf("decodes to %d bytes, want %d", len(key), wgKeyLen)
	}
	return nil
}

// validSecretRef checks a secret reference's syntax without resolving it.
// Decoding config must never contact a secret store: references are
// resolved at server startup, so a config test needs no AWS and a reload
// cannot block on the network.
func validSecretRef(ref SecretRef) error {
	if ref == "" {
		return errors.New("is required")
	}
	// The reference itself is never echoed. An operator who pastes a
	// literal key where a reference belongs must not have that value
	// copied into an error message and from there into a log line.
	if _, _, err := parseSecretRef(ref); err != nil {
		return errors.New("must be one of aws:sm:<id>, aws:ssm:<name>, file:<path>, env:<VAR>")
	}
	return nil
}

// ---------------------------------------------------------------------------
// hot reload
// ---------------------------------------------------------------------------

// PeerDiff is the change between the peer list previously in force and the
// one just loaded, keyed by public key because that is the identity the
// WireGuard device uses. A peer that keeps its key and changes anything
// else is Changed; a peer that gets a new key appears as one Removed (with
// its old key) plus one Added.
type PeerDiff struct {
	Added   []PeerConfig
	Removed []PeerConfig // the previous entries, so their old keys are available
	// Changed carries only the NEW entry, not the previous one, so a
	// consumer cannot compute an old-versus-new allowed-ip delta from it
	// and must apply it with replace_allowed_ips=true. That is the correct
	// WireGuard idiom regardless: it makes the device's allowed-ip set
	// match the file rather than accumulate stale entries.
	Changed []PeerConfig
}

// IsEmpty reports whether the reload changed nothing.
func (d PeerDiff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// diffPeers computes the change from prev to next, keyed by public key.
func diffPeers(prev, next []PeerConfig) PeerDiff {
	prevByKey := make(map[string]PeerConfig, len(prev))
	for _, p := range prev {
		prevByKey[p.PublicKey] = p
	}
	nextByKey := make(map[string]struct{}, len(next))
	for _, p := range next {
		nextByKey[p.PublicKey] = struct{}{}
	}

	var d PeerDiff
	for _, p := range next {
		old, ok := prevByKey[p.PublicKey]
		switch {
		case !ok:
			d.Added = append(d.Added, p)
		case !old.equal(p):
			d.Changed = append(d.Changed, p)
		}
	}
	for _, p := range prev {
		if _, ok := nextByKey[p.PublicKey]; !ok {
			d.Removed = append(d.Removed, p)
		}
	}
	return d
}

// ReloadResult reports the outcome of one reload attempt. It carries what a
// log line may say (a path, a count, peer names) and what the server needs
// to apply the change to the live WireGuard device (the diff). It never
// carries key material.
type ReloadResult struct {
	Path string
	// Err is nil on success. On any error the previous good config stays
	// in force: nothing is cleared and nothing is partially applied.
	Err error
	// PeerCount is the number of peers now in force, which on an error is
	// the previous count.
	PeerCount int
	// Diff is empty on an error.
	Diff PeerDiff
}

// PeerWatcher holds the peer list currently in force and swaps in a new one
// when peers.yaml changes. The swap is atomic: a reader either sees the
// whole previous config or the whole new one, never a mixture, and never a
// half-built value.
type PeerWatcher struct {
	path     string
	dir      string
	base     string
	onReload func(ReloadResult)

	cur atomic.Pointer[PeersConfig]

	// mu serializes reload attempts (a filesystem event and an explicit
	// Reload can race). Readers never take it: they go through cur.
	mu   sync.Mutex
	seen fileID

	fsw       *fsnotify.Watcher
	closeOnce sync.Once
}

// fileID is a cheap identity for the watched file, used by the periodic
// re-arm to notice a change whose event was missed.
type fileID struct {
	size    int64
	modTime time.Time
}

func statFileID(path string) fileID {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}
	}
	return fileID{size: fi.Size(), modTime: fi.ModTime()}
}

// NewPeerWatcher loads path, builds the first Policy, and arms a filesystem
// watch. It fails if the initial file is missing or invalid: startup is the
// one moment with no previous good config to fall back to, and spec section
// 8.2 requires never starting on a stale or unvalidated peer list.
//
// onReload, if non-nil, is called after every reload attempt, successful or
// not, from the watcher's own goroutine. If nil, results are logged with
// slog.Default() instead, so a failed reload is never silent.
//
// Call Run to service filesystem events. Call Close when done, even if Run
// is never called.
func NewPeerWatcher(path string, onReload func(ReloadResult)) (*PeerWatcher, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: %s: %w", path, err)
	}

	// Stat before reading, never after: a write landing between the read
	// and the stat would otherwise look like the file that was read, and
	// the periodic re-arm would never notice it.
	id := statFileID(abs)
	cfg, err := LoadPeersConfig(abs)
	if err != nil {
		return nil, err
	}

	w := &PeerWatcher{
		path:     abs,
		dir:      filepath.Dir(abs),
		base:     filepath.Base(abs),
		onReload: onReload,
		seen:     id,
	}
	w.cur.Store(cfg)

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("gocloak: config: watch %s: %w", path, err)
	}
	// The parent directory is watched, not the file. Editors and deploy
	// scripts replace a file rather than writing in place; a watch held on
	// the file's inode survives the rename but stops seeing the path, and
	// does so silently, which would stop revocation forever.
	if err := fsw.Add(w.dir); err != nil {
		fsw.Close()
		return nil, fmt.Errorf("gocloak: config: watch %s: %w", w.dir, err)
	}
	w.fsw = fsw

	return w, nil
}

// Policy returns the policy currently in force. It is lock-free and always
// returns a fully-formed Policy, so a reader may call it concurrently with
// a reload. Hold the returned pointer for the duration of one decision
// rather than calling twice, so a decision cannot straddle a swap.
func (w *PeerWatcher) Policy() *Policy {
	return w.cur.Load().Policy
}

// Config returns the peer configuration currently in force. The returned
// value and everything reachable from it is read-only.
func (w *PeerWatcher) Config() *PeersConfig {
	return w.cur.Load()
}

// Reload re-reads and re-validates the peers file, then swaps it in. The
// entire file is parsed, validated and turned into a new Policy before
// anything is swapped, so a malformed or invalid file leaves the previous
// config in force: a typo neither revokes everyone nor widens access.
//
// It is safe to call concurrently with readers and with the watcher's own
// reloads. It is exported so a server can also reload on SIGHUP.
func (w *PeerWatcher) Reload() ReloadResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reloadLocked()
}

func (w *PeerWatcher) reloadLocked() ReloadResult {
	// Record what was read before reading it: on failure this stops the
	// periodic re-arm from retrying the same broken file every tick.
	id := statFileID(w.path)

	cfg, err := LoadPeersConfig(w.path)
	if err != nil {
		w.seen = id
		return ReloadResult{Path: w.path, Err: err, PeerCount: len(w.cur.Load().Peers)}
	}

	prev := w.cur.Load()
	diff := diffPeers(prev.Peers, cfg.Peers)
	// The new config is complete here: parsed, validated, and with its
	// Policy built. Only now is it published, in one atomic store.
	w.cur.Store(cfg)
	w.seen = id

	return ReloadResult{Path: w.path, PeerCount: len(cfg.Peers), Diff: diff}
}

// report hands a reload result to the callback, or logs it if there is none.
func (w *PeerWatcher) report(r ReloadResult) {
	if w.onReload != nil {
		w.onReload(r)
		return
	}
	if r.Err != nil {
		slog.Error("gocloak: peers file reload failed, previous config still in force",
			"path", r.Path, "peers_in_force", r.PeerCount, "error", r.Err)
		return
	}
	if r.Diff.IsEmpty() {
		return
	}
	slog.Info("gocloak: peers file reloaded",
		"path", r.Path,
		"peers", r.PeerCount,
		"added", peerNames(r.Diff.Added),
		"removed", peerNames(r.Diff.Removed),
		"changed", peerNames(r.Diff.Changed))
}

// Run services filesystem events until ctx is cancelled, reloading the peers
// file when it changes. It returns nil on cancellation and an error if the
// watch itself fails, which the caller must treat as fatal: a dead watch
// means revocation has stopped working.
func (w *PeerWatcher) Run(ctx context.Context) error {
	debounce := time.NewTimer(reloadDebounce)
	stopTimer(debounce)
	defer stopTimer(debounce)

	rearm := time.NewTicker(watchRearmInterval)
	defer rearm.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-w.fsw.Events:
			if !ok {
				return errors.New("gocloak: config: peers file watch closed")
			}
			if filepath.Base(ev.Name) != w.base {
				continue
			}
			if ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove) {
				// The file was replaced or deleted. The directory
				// watch should have survived, but re-adding it is
				// cheap and idempotent, and a silently dead watch
				// is the failure this project can least afford.
				w.rearmWatch()
			}
			resetTimer(debounce, reloadDebounce)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return errors.New("gocloak: config: peers file watch closed")
			}
			slog.Error("gocloak: peers file watch error", "path", w.path, "error", err)
			w.rearmWatch()
			resetTimer(debounce, reloadDebounce)

		case <-debounce.C:
			w.report(w.Reload())

		case <-rearm.C:
			// Belt and braces: re-add the watch and reload if the
			// file changed without an event reaching us.
			w.rearmWatch()
			w.mu.Lock()
			changed := statFileID(w.path) != w.seen
			var r ReloadResult
			if changed {
				r = w.reloadLocked()
			}
			w.mu.Unlock()
			if changed {
				w.report(r)
			}
		}
	}
}

// rearmWatch re-adds the directory watch. fsnotify treats a repeated Add as
// a refresh, so this is safe to call on every suspicious event.
func (w *PeerWatcher) rearmWatch() {
	if err := w.fsw.Add(w.dir); err != nil {
		slog.Error("gocloak: could not re-arm peers file watch, revocation may have stopped",
			"dir", w.dir, "error", err)
	}
}

// Close releases the filesystem watch. It is idempotent.
func (w *PeerWatcher) Close() error {
	var err error
	w.closeOnce.Do(func() { err = w.fsw.Close() })
	return err
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	stopTimer(t)
	t.Reset(d)
}
