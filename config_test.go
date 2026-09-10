package gocloak

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testKey returns a valid base64 32-byte key, distinct per fill byte, so a
// test can talk about "a different public key" without hardcoding blobs.
func testKey(fill byte) string {
	var k [32]byte
	for i := range k {
		k[i] = fill
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func tempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, content)
	return path
}

// validServerYAML is spec section 6's server.yaml verbatim.
const validServerYAML = `listen_port: 51820
private_key: aws:sm:gocloak/server/private
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: /etc/gocloak/peers.yaml
log_format: json
`

// onePeerYAML renders a single-peer peers.yaml with the shape of spec
// section 6's example.
func onePeerYAML(name, pubKey, tunnelIP, service, backend string) string {
	return fmt.Sprintf(`peers:
  - name: %s
    public_key: %s
    psk: aws:sm:gocloak/peers/%s
    tunnel_ip: %s
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      %s: %s
`, name, pubKey, name, tunnelIP, service, backend)
}

func TestConfigServerDecode(t *testing.T) {
	cfg, err := LoadServerConfig(tempFile(t, "server.yaml", validServerYAML))
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", cfg.ListenPort)
	}
	if cfg.PrivateKey != SecretRef("aws:sm:gocloak/server/private") {
		t.Errorf("PrivateKey = %q", string(cfg.PrivateKey))
	}
	if cfg.TunnelIP != netip.MustParseAddr("10.99.0.1") {
		t.Errorf("TunnelIP = %v, want 10.99.0.1", cfg.TunnelIP)
	}
	if cfg.MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", cfg.MTU)
	}
	if cfg.PeersFile != "/etc/gocloak/peers.yaml" {
		t.Errorf("PeersFile = %q", cfg.PeersFile)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q", cfg.LogFormat)
	}
}

func TestConfigServerUnknownKeyRejected(t *testing.T) {
	// A typo in a security-relevant key must fail loudly, not be ignored.
	yaml := validServerYAML + "privatekey: aws:sm:oops\n"
	_, err := LoadServerConfig(tempFile(t, "server.yaml", yaml))
	if err == nil {
		t.Fatal("want error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "privatekey") {
		t.Errorf("error should name the unknown key, got: %v", err)
	}
}

func TestConfigServerDefaults(t *testing.T) {
	yaml := `listen_port: 51820
private_key: env:GOCLOAK_KEY
tunnel_ip: 10.99.0.1
peers_file: /etc/gocloak/peers.yaml
`
	cfg, err := LoadServerConfig(tempFile(t, "server.yaml", yaml))
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.MTU != DefaultMTU {
		t.Errorf("MTU = %d, want default %d", cfg.MTU, DefaultMTU)
	}
	if cfg.LogFormat != DefaultLogFormat {
		t.Errorf("LogFormat = %q, want default %q", cfg.LogFormat, DefaultLogFormat)
	}
}

func TestConfigServerRejects(t *testing.T) {
	base := `listen_port: 51820
private_key: aws:sm:gocloak/server/private
tunnel_ip: 10.99.0.1
peers_file: /etc/gocloak/peers.yaml
`
	replace := func(old, new string) string { return strings.Replace(base, old, new, 1) }

	cases := []struct {
		name string
		yaml string
	}{
		{"empty document", ""},
		{"missing listen_port", replace("listen_port: 51820\n", "")},
		{"listen_port out of range", replace("51820", "70000")},
		{"missing private_key", replace("private_key: aws:sm:gocloak/server/private\n", "")},
		{"private_key not a secret ref", replace("aws:sm:gocloak/server/private", "hunter2")},
		{"private_key unknown scheme", replace("aws:sm:gocloak/server/private", "vault:secret/x")},
		{"missing tunnel_ip", replace("tunnel_ip: 10.99.0.1\n", "")},
		{"tunnel_ip unparseable", replace("10.99.0.1", "not-an-ip")},
		{"tunnel_ip unspecified", replace("10.99.0.1", "0.0.0.0")},
		{"tunnel_ip outside tunnel subnet", replace("10.99.0.1", "192.0.2.10")},
		{"tunnel_ip not the server address", replace("10.99.0.1", "10.99.0.7")},
		{"missing peers_file", replace("peers_file: /etc/gocloak/peers.yaml\n", "")},
		{"mtu below minimum", base + "mtu: 576\n"},
		{"mtu above maximum", base + "mtu: 9000\n"},
		{"unknown log_format", base + "log_format: syslog\n"},
		{"two documents", base + "---\n" + base},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadServerConfig(tempFile(t, "server.yaml", tc.yaml)); err == nil {
				t.Fatalf("want error, got nil")
			}
		})
	}
}

func TestConfigServerMissingFile(t *testing.T) {
	if _, err := LoadServerConfig(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("want error for a missing file, got nil")
	}
}

func TestConfigPeersDecode(t *testing.T) {
	yaml := fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: aws:sm:gocloak/peers/app-01
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: 192.0.2.10:3306
      cache: 192.0.2.11:6379
`, testKey(1))

	cfg, err := LoadPeersConfig(tempFile(t, "peers.yaml", yaml))
	if err != nil {
		t.Fatalf("LoadPeersConfig: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.Name != "app-01" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.PublicKey != testKey(1) {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if p.PSK != SecretRef("aws:sm:gocloak/peers/app-01") {
		t.Errorf("PSK = %q", string(p.PSK))
	}
	if p.TunnelIP != netip.MustParseAddr("10.99.0.7") {
		t.Errorf("TunnelIP = %v", p.TunnelIP)
	}
	if p.Limits.MaxConcurrent != 32 || p.Limits.DialsPerSecond != 10 {
		t.Errorf("Limits = %+v", p.Limits)
	}
	if got := p.Allow["primary-db"]; got != netip.MustParseAddrPort("192.0.2.10:3306") {
		t.Errorf("Allow[primary-db] = %v", got)
	}
	if got := p.Allow["cache"]; got != netip.MustParseAddrPort("192.0.2.11:6379") {
		t.Errorf("Allow[cache] = %v", got)
	}

	// The Policy built from the file is the thing the server consults.
	backend, ok := cfg.Policy.Resolve(netip.MustParseAddr("10.99.0.7"), "primary-db")
	if !ok || backend != netip.MustParseAddrPort("192.0.2.10:3306") {
		t.Errorf("Policy.Resolve = %v, %v", backend, ok)
	}
	if _, ok := cfg.Policy.Resolve(netip.MustParseAddr("10.99.0.8"), "primary-db"); ok {
		t.Error("Policy resolved an unknown peer")
	}
}

func TestConfigPeersLimitsDefault(t *testing.T) {
	yaml := fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: env:PSK_APP01
    tunnel_ip: 10.99.0.7
    allow: {}
`, testKey(1))
	cfg, err := LoadPeersConfig(tempFile(t, "peers.yaml", yaml))
	if err != nil {
		t.Fatalf("LoadPeersConfig: %v", err)
	}
	if got := cfg.Peers[0].Limits.MaxConcurrent; got != DefaultMaxConcurrent {
		t.Errorf("MaxConcurrent = %d, want %d", got, DefaultMaxConcurrent)
	}
	if got := cfg.Peers[0].Limits.DialsPerSecond; got != DefaultDialsPerSecond {
		t.Errorf("DialsPerSecond = %d, want %d", got, DefaultDialsPerSecond)
	}
}

func TestConfigPeersEmptyListAccepted(t *testing.T) {
	// An empty peers list means nobody may connect. That is the
	// fail-closed direction and must not be an error.
	for _, yaml := range []string{"peers: []\n", "peers:\n"} {
		cfg, err := LoadPeersConfig(tempFile(t, "peers.yaml", yaml))
		if err != nil {
			t.Fatalf("LoadPeersConfig(%q): %v", yaml, err)
		}
		if len(cfg.Peers) != 0 {
			t.Errorf("len(Peers) = %d, want 0", len(cfg.Peers))
		}
		if cfg.Policy == nil {
			t.Fatal("Policy is nil for an empty peer list")
		}
		if _, ok := cfg.Policy.Resolve(netip.MustParseAddr("10.99.0.7"), "primary-db"); ok {
			t.Error("empty policy granted access")
		}
	}
}

func TestConfigPeersUnknownKeyRejected(t *testing.T) {
	cases := map[string]string{
		"top level": `peers: []
peerz:
  - name: app-01
`,
		"peer entry": fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: env:PSK
    tunnel_ip: 10.99.0.7
    alow:
      primary-db: 192.0.2.10:3306
`, testKey(1)),
		"limits": fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: env:PSK
    tunnel_ip: 10.99.0.7
    limits:
      max_concurent: 32
`, testKey(1)),
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPeersConfig(tempFile(t, "peers.yaml", yaml)); err == nil {
				t.Fatal("want error for unknown key, got nil")
			}
		})
	}
}

func TestConfigPeersRejects(t *testing.T) {
	two := func(a, b string) string {
		return "peers:\n" + a + b
	}
	entry := func(name, pubKey, tunnelIP string) string {
		return fmt.Sprintf(`  - name: %s
    public_key: %s
    psk: env:PSK
    tunnel_ip: %s
    allow:
      primary-db: 192.0.2.10:3306
`, name, pubKey, tunnelIP)
	}

	cases := []struct {
		name string
		yaml string
	}{
		{"empty document", ""},
		{"duplicate peer name", two(entry("app-01", testKey(1), "10.99.0.7"), entry("app-01", testKey(2), "10.99.0.8"))},
		{"duplicate tunnel ip", two(entry("app-01", testKey(1), "10.99.0.7"), entry("app-02", testKey(2), "10.99.0.7"))},
		{"duplicate tunnel ip via v4-mapped spelling", two(entry("app-01", testKey(1), "10.99.0.7"), entry("app-02", testKey(2), "::ffff:10.99.0.7"))},
		{"duplicate public key", two(entry("app-01", testKey(1), "10.99.0.7"), entry("app-02", testKey(1), "10.99.0.8"))},
		{"missing name", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "name: app-01\n    ", "", 1)},
		{"invalid peer name charset", "peers:\n" + entry("App 01", testKey(1), "10.99.0.7")},
		{"missing public_key", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "public_key: "+testKey(1), `public_key: ""`, 1)},
		{"public_key not base64", "peers:\n" + entry("app-01", "not!base64!", "10.99.0.7")},
		{"public_key wrong length", "peers:\n" + entry("app-01", base64.StdEncoding.EncodeToString(make([]byte, 31)), "10.99.0.7")},
		{"missing psk", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "    psk: env:PSK\n", "", 1)},
		{"psk unknown scheme", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "env:PSK", "vault:psk", 1)},
		{"tunnel_ip unparseable", "peers:\n" + entry("app-01", testKey(1), "not-an-ip")},
		{"tunnel_ip unspecified", "peers:\n" + entry("app-01", testKey(1), "0.0.0.0")},
		{"tunnel_ip outside tunnel subnet", "peers:\n" + entry("app-01", testKey(1), "10.98.0.7")},
		{"tunnel_ip is the server address", "peers:\n" + entry("app-01", testKey(1), "10.99.0.1")},
		{"tunnel_ip is the subnet address", "peers:\n" + entry("app-01", testKey(1), "10.99.0.0")},
		{"tunnel_ip is the broadcast address", "peers:\n" + entry("app-01", testKey(1), "10.99.0.255")},
		{"invalid service name", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "primary-db", "Primary_DB", 1)},
		{"backend unparseable", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "192.0.2.10:3306", "db.internal:3306", 1)},
		{"backend missing port", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "192.0.2.10:3306", "192.0.2.10", 1)},
		{"backend zero port", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "192.0.2.10:3306", "192.0.2.10:0", 1)},
		{"negative limit", strings.Replace("peers:\n"+entry("app-01", testKey(1), "10.99.0.7"), "    allow:", "    limits:\n      max_concurrent: -1\n    allow:", 1)},
		{"two documents", "peers: []\n---\npeers: []\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadPeersConfig(tempFile(t, "peers.yaml", tc.yaml)); err == nil {
				t.Fatalf("want error, got nil.\nyaml:\n%s", tc.yaml)
			}
		})
	}
}

// newTestWatcher starts a PeerWatcher over path, runs it, and returns the
// watcher plus a channel of reload results.
func newTestWatcher(t *testing.T, path string) (*PeerWatcher, <-chan ReloadResult) {
	t.Helper()
	results := make(chan ReloadResult, 64)
	w, err := NewPeerWatcher(path, func(r ReloadResult) {
		select {
		case results <- r:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewPeerWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := w.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		w.Close()
	})
	return w, results
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConfigWatcherInitialLoadFailsClosed(t *testing.T) {
	// Never start on a broken peer list: startup is the one place where
	// there is no previous good config to keep.
	path := tempFile(t, "peers.yaml", "peerz: []\n")
	if _, err := NewPeerWatcher(path, nil); err == nil {
		t.Fatal("want error for a malformed initial peers file, got nil")
	}
	if _, err := NewPeerWatcher(filepath.Join(t.TempDir(), "absent.yaml"), nil); err == nil {
		t.Fatal("want error for a missing initial peers file, got nil")
	}
}

func TestConfigHotReloadHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))

	w, results := newTestWatcher(t, path)

	if _, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.8"), "cache"); ok {
		t.Fatal("policy granted access before the peer existed")
	}

	writeFile(t, path, onePeerYAML("app-02", testKey(2), "10.99.0.8", "cache", "192.0.2.11:6379"))

	waitFor(t, "the new peer to be resolvable", func() bool {
		_, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.8"), "cache")
		return ok
	})

	// The revoked peer is gone the moment the swap happens.
	if _, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.7"), "primary-db"); ok {
		t.Error("revoked peer still resolves after reload")
	}

	var got ReloadResult
	waitFor(t, "a successful reload result", func() bool {
		for {
			select {
			case r := <-results:
				if r.Err == nil && r.PeerCount == 1 && len(r.Diff.Added) == 1 {
					got = r
					return true
				}
			default:
				return false
			}
		}
	})
	if names := peerNames(got.Diff.Added); len(names) != 1 || names[0] != "app-02" {
		t.Errorf("Diff.Added names = %v, want [app-02]", names)
	}
	if names := peerNames(got.Diff.Removed); len(names) != 1 || names[0] != "app-01" {
		t.Errorf("Diff.Removed names = %v, want [app-01]", names)
	}
}

func TestConfigHotReloadMalformedKeepsPreviousPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	good := onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306")
	writeFile(t, path, good)

	w, results := newTestWatcher(t, path)
	before := w.Policy()

	writeFile(t, path, "peers:\n  - name: app-01\n    pubic_key: oops\n")

	var failed ReloadResult
	waitFor(t, "a failed reload result", func() bool {
		select {
		case r := <-results:
			if r.Err != nil {
				failed = r
				return true
			}
			return false
		default:
			return false
		}
	})
	if failed.PeerCount != 1 {
		t.Errorf("PeerCount = %d, want the previous count 1", failed.PeerCount)
	}
	if !failed.Diff.IsEmpty() {
		t.Errorf("Diff = %+v, want empty on a failed reload", failed.Diff)
	}

	// The old policy is still in force: not cleared, not partially applied.
	backend, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.7"), "primary-db")
	if !ok || backend != netip.MustParseAddrPort("192.0.2.10:3306") {
		t.Fatalf("previous policy no longer resolves after a malformed reload: %v, %v", backend, ok)
	}
	if w.Policy() != before {
		t.Error("policy pointer changed on a failed reload")
	}
	if len(w.Config().Peers) != 1 {
		t.Errorf("Config().Peers = %d, want the previous 1", len(w.Config().Peers))
	}

	// And a later good write still gets picked up.
	writeFile(t, path, onePeerYAML("app-02", testKey(2), "10.99.0.8", "cache", "192.0.2.11:6379"))
	waitFor(t, "recovery after a malformed file", func() bool {
		_, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.8"), "cache")
		return ok
	})
}

func TestConfigHotReloadSurvivesRename(t *testing.T) {
	// Editors and deploy scripts replace a file rather than writing in
	// place. A watch registered on the file itself dies here silently,
	// which would stop revocation forever.
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))

	w, _ := newTestWatcher(t, path)

	for i, spec := range []struct {
		ip      string
		service string
	}{
		{"10.99.0.8", "cache"},
		{"10.99.0.9", "queue"},
	} {
		tmp := filepath.Join(dir, fmt.Sprintf("peers.yaml.tmp%d", i))
		writeFile(t, tmp, onePeerYAML(fmt.Sprintf("app-%02d", i+2), testKey(byte(i+2)), spec.ip, spec.service, "192.0.2.11:6379"))
		if err := os.Rename(tmp, path); err != nil {
			t.Fatalf("rename: %v", err)
		}
		waitFor(t, "the renamed-in file to be applied (round "+fmt.Sprint(i)+")", func() bool {
			_, ok := w.Policy().Resolve(netip.MustParseAddr(spec.ip), spec.service)
			return ok
		})
	}
}

func TestConfigHotReloadDebounced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))

	var mu sync.Mutex
	var reloads int
	w, err := NewPeerWatcher(path, func(ReloadResult) {
		mu.Lock()
		reloads++
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewPeerWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx) }()
	defer func() { cancel(); <-done; w.Close() }()

	for i := 0; i < 10; i++ {
		writeFile(t, path, onePeerYAML("app-02", testKey(2), "10.99.0.8", "cache", "192.0.2.11:6379"))
	}
	waitFor(t, "the burst to be applied", func() bool {
		_, ok := w.Policy().Resolve(netip.MustParseAddr("10.99.0.8"), "cache")
		return ok
	})
	time.Sleep(3 * reloadDebounce)
	mu.Lock()
	n := reloads
	mu.Unlock()
	if n > 3 {
		t.Errorf("burst of 10 writes caused %d reloads, want a debounced handful", n)
	}
}

func TestConfigHotReloadConcurrentReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))

	w, _ := newTestWatcher(t, path)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := w.Policy()
				if p == nil {
					t.Error("Policy() returned nil during a reload")
					return
				}
				p.Resolve(netip.MustParseAddr("10.99.0.7"), "primary-db")
				w.Config()
			}
		}()
	}

	for i := 0; i < 50; i++ {
		writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))
		if r := w.Reload(); r.Err != nil {
			t.Errorf("Reload: %v", r.Err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

func TestConfigReloadDiffByPublicKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.yaml")
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "primary-db", "192.0.2.10:3306"))

	w, err := NewPeerWatcher(path, nil)
	if err != nil {
		t.Fatalf("NewPeerWatcher: %v", err)
	}
	defer w.Close()

	// Same public key, different grant: a change, not an add plus remove.
	writeFile(t, path, onePeerYAML("app-01", testKey(1), "10.99.0.7", "cache", "192.0.2.11:6379"))
	r := w.Reload()
	if r.Err != nil {
		t.Fatalf("Reload: %v", r.Err)
	}
	if len(r.Diff.Added) != 0 || len(r.Diff.Removed) != 0 || len(r.Diff.Changed) != 1 {
		t.Fatalf("Diff = %+v, want one Changed", r.Diff)
	}
	if r.Diff.Changed[0].Allow["cache"] != netip.MustParseAddrPort("192.0.2.11:6379") {
		t.Errorf("Changed entry carries the old grant: %+v", r.Diff.Changed[0])
	}

	// An identical file is not a change at all.
	r = w.Reload()
	if r.Err != nil {
		t.Fatalf("Reload: %v", r.Err)
	}
	if !r.Diff.IsEmpty() {
		t.Errorf("Diff = %+v, want empty for an unchanged file", r.Diff)
	}

	// A new key for the same name is a remove plus an add, which is what
	// the WireGuard device needs to be told.
	writeFile(t, path, onePeerYAML("app-01", testKey(9), "10.99.0.7", "cache", "192.0.2.11:6379"))
	r = w.Reload()
	if r.Err != nil {
		t.Fatalf("Reload: %v", r.Err)
	}
	if len(r.Diff.Added) != 1 || len(r.Diff.Removed) != 1 || len(r.Diff.Changed) != 0 {
		t.Fatalf("Diff = %+v, want one Added and one Removed", r.Diff)
	}
	if r.Diff.Removed[0].PublicKey != testKey(1) {
		t.Errorf("Removed entry should carry the OLD public key, got %q", r.Diff.Removed[0].PublicKey)
	}
}

func TestConfigWatcherCloseIsIdempotent(t *testing.T) {
	path := tempFile(t, "peers.yaml", "peers: []\n")
	w, err := NewPeerWatcher(path, nil)
	if err != nil {
		t.Fatalf("NewPeerWatcher: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Run after Close must not hang or panic.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := w.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run after Close = %v, want a non-timeout error", err)
	}
}

func TestConfigSecretRefNotEchoedInError(t *testing.T) {
	// An operator who pastes a literal key where a reference belongs must
	// not have that value copied into an error message, and from there
	// into a log line.
	literal := "SUPERSECRETKEYMATERIAL"
	yaml := strings.Replace(validServerYAML, "aws:sm:gocloak/server/private", literal, 1)
	_, err := LoadServerConfig(tempFile(t, "server.yaml", yaml))
	if err == nil {
		t.Fatal("want error for a private_key that is not a reference, got nil")
	}
	if strings.Contains(err.Error(), literal) {
		t.Errorf("error echoes the private_key value: %v", err)
	}

	peers := fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: %s
    tunnel_ip: 10.99.0.7
    allow: {}
`, testKey(1), literal)
	_, err = LoadPeersConfig(tempFile(t, "peers.yaml", peers))
	if err == nil {
		t.Fatal("want error for a psk that is not a reference, got nil")
	}
	if strings.Contains(err.Error(), literal) {
		t.Errorf("error echoes the psk value: %v", err)
	}
}

func TestConfigYAMLTypeErrorRedactsValue(t *testing.T) {
	// yaml.v3's type-mismatch errors embed the first seven characters of
	// the offending scalar. A key pasted into an int field must not put a
	// prefix of that key into an error, and from there into a log line.
	const secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123456"

	containsAnyPrefix := func(msg string) string {
		for n := 3; n <= len(secret); n++ {
			if strings.Contains(msg, secret[:n]) {
				return secret[:n]
			}
		}
		return ""
	}

	cases := map[string]string{
		"peers limits.max_concurrent": fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: env:PSK
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: %s
    allow: {}
`, testKey(1), secret),
		"peers limits.dials_per_second": fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: env:PSK
    tunnel_ip: 10.99.0.7
    limits:
      dials_per_second: %s
    allow: {}
`, testKey(1), secret),
		"whole file pasted where peers belong": secret + "\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPeersConfig(tempFile(t, "peers.yaml", yaml))
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if leaked := containsAnyPrefix(err.Error()); leaked != "" {
				t.Errorf("error leaks the value prefix %q: %v", leaked, err)
			}
		})
	}

	for _, field := range []string{"mtu", "listen_port"} {
		t.Run("server "+field, func(t *testing.T) {
			yaml := strings.Replace(validServerYAML, field+": ", field+": "+secret+" #", 1)
			_, err := LoadServerConfig(tempFile(t, "server.yaml", yaml))
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if leaked := containsAnyPrefix(err.Error()); leaked != "" {
				t.Errorf("error leaks the value prefix %q: %v", leaked, err)
			}
		})
	}
}
