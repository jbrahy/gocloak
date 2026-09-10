package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// runCLI runs the CLI dispatcher in-process and returns its exit code and
// captured stdout/stderr, so a test can assert on the real command surface
// without shelling out to `go run`.
func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// keygenOutput holds the fields parsed out of a successful keygen run's
// stdout.
type keygenOutput struct {
	PublicKeyB64 string
	PSKB64       string
	KeyPath      string
	PSKPath      string
}

func parseKeygenOutput(t *testing.T, stdout string) keygenOutput {
	t.Helper()
	var out keygenOutput
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "public_key: "):
			out.PublicKeyB64 = strings.TrimPrefix(line, "public_key: ")
		case strings.HasPrefix(line, "psk: "):
			out.PSKB64 = strings.TrimPrefix(line, "psk: ")
		case strings.HasPrefix(line, "private key written to: "):
			out.KeyPath = strings.TrimPrefix(line, "private key written to: ")
		case strings.HasPrefix(line, "psk written to: "):
			out.PSKPath = strings.TrimPrefix(line, "psk written to: ")
		}
	}
	if out.PublicKeyB64 == "" || out.PSKB64 == "" || out.KeyPath == "" || out.PSKPath == "" {
		t.Fatalf("keygen stdout missing an expected field:\n%s", stdout)
	}
	return out
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not valid base64: %q: %v", s, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

func TestKeygenProducesValidKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runCLI("keygen", "--name", "app-01", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}
	out := parseKeygenOutput(t, stdout)

	pub := decodeB64(t, out.PublicKeyB64)
	if len(pub) != 32 {
		t.Errorf("public key is %d bytes, want 32", len(pub))
	}
	psk := decodeB64(t, out.PSKB64)
	if len(psk) != 32 {
		t.Errorf("psk is %d bytes, want 32", len(psk))
	}

	keyPath := filepath.Join(dir, "app-01.key")
	if out.KeyPath != keyPath {
		t.Errorf("KeyPath = %q, want %q", out.KeyPath, keyPath)
	}
	privB64, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}
	priv := decodeB64(t, string(privB64))
	if len(priv) != 32 {
		t.Errorf("private key is %d bytes, want 32", len(priv))
	}

	pskFileB64, err := os.ReadFile(filepath.Join(dir, "app-01.psk"))
	if err != nil {
		t.Fatalf("read psk file: %v", err)
	}
	if string(pskFileB64) != out.PSKB64 {
		t.Errorf("psk file content %q does not match printed psk %q", pskFileB64, out.PSKB64)
	}
}

// TestKeygenDerivedPublicKeyMatchesPrinted is the important one: it proves
// the generated keypair actually works by deriving the public key
// independently with curve25519.X25519 from the private key written to
// disk, and checking it reproduces exactly the public key keygen printed.
func TestKeygenDerivedPublicKeyMatchesPrinted(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runCLI("keygen", "--name", "app-02", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}
	out := parseKeygenOutput(t, stdout)

	privB64, err := os.ReadFile(filepath.Join(dir, "app-02.key"))
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}
	priv := decodeB64(t, string(privB64))

	derivedPub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519: %v", err)
	}
	derivedPubB64 := base64.StdEncoding.EncodeToString(derivedPub)

	if derivedPubB64 != out.PublicKeyB64 {
		t.Fatalf("independently derived public key %q does not match printed public key %q", derivedPubB64, out.PublicKeyB64)
	}
}

func TestKeygenPrivateKeyFileIsMode0600(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runCLI("keygen", "--name", "app-03", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}
	info, err := os.Stat(filepath.Join(dir, "app-03.key"))
	if err != nil {
		t.Fatalf("stat private key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key file mode = %#o, want 0600", perm)
	}
}

func TestKeygenPSKFileIsMode0600(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runCLI("keygen", "--name", "app-04", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}
	info, err := os.Stat(filepath.Join(dir, "app-04.psk"))
	if err != nil {
		t.Fatalf("stat psk file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("psk file mode = %#o, want 0600", perm)
	}
}

// TestKeygenRefusesToOverwriteAnExistingKeyFile: clobbering a peer's
// existing private key would be a self-inflicted outage, so a second
// keygen for the same name in the same directory must fail rather than
// silently replace the file.
func TestKeygenRefusesToOverwriteAnExistingKeyFile(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runCLI("keygen", "--name", "app-05", "--dir", dir)
	if code != 0 {
		t.Fatalf("first keygen exited %d, stderr: %s", code, stderr)
	}
	before, err := os.ReadFile(filepath.Join(dir, "app-05.key"))
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}

	code, _, stderr = runCLI("keygen", "--name", "app-05", "--dir", dir)
	if code == 0 {
		t.Fatal("second keygen for an existing name exited 0, want non-zero")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr does not mention the existing file: %q", stderr)
	}

	after, err := os.ReadFile(filepath.Join(dir, "app-05.key"))
	if err != nil {
		t.Fatalf("read private key file after refused overwrite: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("private key file content changed after a refused overwrite")
	}
}

// TestKeygenRefusesToOverwriteAnExistingPSKFile mirrors the key-file case
// for the PSK file.
func TestKeygenRefusesToOverwriteAnExistingPSKFile(t *testing.T) {
	dir := t.TempDir()
	// Pre-create only the .psk file, so keygen writes the .key file
	// successfully and then must fail on the PSK file without silently
	// leaving a key file with no matching PSK undetected by the caller.
	if err := os.WriteFile(filepath.Join(dir, "app-06.psk"), []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("seed existing psk file: %v", err)
	}

	code, _, stderr := runCLI("keygen", "--name", "app-06", "--dir", dir)
	if code == 0 {
		t.Fatal("keygen over an existing psk file exited 0, want non-zero")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr does not mention the existing file: %q", stderr)
	}

	content, err := os.ReadFile(filepath.Join(dir, "app-06.psk"))
	if err != nil {
		t.Fatalf("read psk file: %v", err)
	}
	if string(content) != "preexisting" {
		t.Fatal("existing psk file content was changed")
	}
}

// TestKeygenPrivateKeyNeverOnStdout checks that the private key value never
// reaches stdout, in either its file's base64 form or its raw bytes.
func TestKeygenPrivateKeyNeverOnStdout(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runCLI("keygen", "--name", "app-07", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}

	privB64, err := os.ReadFile(filepath.Join(dir, "app-07.key"))
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}
	if strings.Contains(stdout, string(privB64)) {
		t.Fatal("stdout contains the private key's base64 encoding")
	}

	priv := decodeB64(t, string(privB64))
	if bytes.Contains([]byte(stdout), priv) {
		t.Fatal("stdout contains the private key's raw bytes")
	}
}

// TestKeygenTwoRunsProduceDifferentKeys is a smoke test against a broken
// entropy source: two successive runs must not produce the same private
// key, public key, or PSK.
func TestKeygenTwoRunsProduceDifferentKeys(t *testing.T) {
	dir := t.TempDir()

	code, stdout1, stderr := runCLI("keygen", "--name", "peer-a", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen peer-a exited %d, stderr: %s", code, stderr)
	}
	code, stdout2, stderr := runCLI("keygen", "--name", "peer-b", "--dir", dir)
	if code != 0 {
		t.Fatalf("keygen peer-b exited %d, stderr: %s", code, stderr)
	}

	out1 := parseKeygenOutput(t, stdout1)
	out2 := parseKeygenOutput(t, stdout2)

	if out1.PublicKeyB64 == out2.PublicKeyB64 {
		t.Error("two keygen runs produced the same public key")
	}
	if out1.PSKB64 == out2.PSKB64 {
		t.Error("two keygen runs produced the same psk")
	}

	priv1, err := os.ReadFile(filepath.Join(dir, "peer-a.key"))
	if err != nil {
		t.Fatalf("read peer-a private key: %v", err)
	}
	priv2, err := os.ReadFile(filepath.Join(dir, "peer-b.key"))
	if err != nil {
		t.Fatalf("read peer-b private key: %v", err)
	}
	if bytes.Equal(priv1, priv2) {
		t.Error("two keygen runs produced the same private key")
	}
}

// TestKeygenClampPrivateKeyBitPattern checks clampPrivateKey against known
// bit patterns rather than generated randomness, so the assertion is exact
// and deterministic.
func TestKeygenClampPrivateKeyBitPattern(t *testing.T) {
	allOnes := bytes.Repeat([]byte{0xFF}, 32)
	clampPrivateKey(allOnes)
	if allOnes[0] != 0xF8 {
		t.Errorf("byte 0 = %#x, want %#x (low 3 bits cleared)", allOnes[0], 0xF8)
	}
	if allOnes[31] != 0x7F {
		t.Errorf("byte 31 = %#x, want %#x (high bit cleared, second-highest set)", allOnes[31], 0x7F)
	}

	allZeros := make([]byte, 32)
	clampPrivateKey(allZeros)
	if allZeros[0] != 0x00 {
		t.Errorf("byte 0 = %#x, want %#x", allZeros[0], 0x00)
	}
	if allZeros[31] != 0x40 {
		t.Errorf("byte 31 = %#x, want %#x (second-highest bit set)", allZeros[31], 0x40)
	}
	for i := 1; i < 31; i++ {
		if allZeros[i] != 0x00 {
			t.Errorf("byte %d = %#x, want unchanged 0x00", i, allZeros[i])
		}
	}
}

// TestKeygenGeneratedKeyIsClamped checks that a key produced by the real
// generator, not a hand-built bit pattern, satisfies the X25519 clamping
// contract.
func TestKeygenGeneratedKeyIsClamped(t *testing.T) {
	priv, _, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	if priv[0]&0x07 != 0 {
		t.Errorf("byte 0 low 3 bits not cleared: %#x", priv[0])
	}
	if priv[31]&0x80 != 0 {
		t.Errorf("byte 31 high bit not cleared: %#x", priv[31])
	}
	if priv[31]&0x40 == 0 {
		t.Errorf("byte 31 second-highest bit not set: %#x", priv[31])
	}
}

func TestKeygenRequiresName(t *testing.T) {
	code, _, stderr := runCLI("keygen", "--dir", t.TempDir())
	if code == 0 {
		t.Fatal("keygen without --name exited 0, want non-zero")
	}
	if !strings.Contains(stderr, "--name") {
		t.Errorf("stderr does not mention --name: %q", stderr)
	}
}

func TestKeygenRejectsInvalidName(t *testing.T) {
	code, _, stderr := runCLI("keygen", "--name", "not a valid name!", "--dir", t.TempDir())
	if code == 0 {
		t.Fatal("keygen with an invalid --name exited 0, want non-zero")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

// TestKeygenDefaultDirIsWorkingDirectory checks that omitting --dir writes
// the key files into the process's current directory.
func TestKeygenDefaultDirIsWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	code, stdout, stderr := runCLI("keygen", "--name", "app-08")
	if code != 0 {
		t.Fatalf("keygen exited %d, stderr: %s", code, stderr)
	}
	out := parseKeygenOutput(t, stdout)
	wantPath := filepath.Join(dir, "app-08.key")
	if out.KeyPath != wantPath {
		t.Errorf("KeyPath = %q, want %q", out.KeyPath, wantPath)
	}
	if _, err := os.Stat(filepath.Join(dir, "app-08.key")); err != nil {
		t.Errorf("key file not found in working directory: %v", err)
	}
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

const validServeServerYAML = `listen_port: 51820
private_key: %s
tunnel_ip: 10.99.0.1
peers_file: %s
`

func writeValidPeersYAML(t *testing.T, path string) {
	t.Helper()
	// An empty peers list is a valid, fully-parsed peers.yaml: nobody may
	// connect, which is a legitimate starting state.
	if err := os.WriteFile(path, []byte("peers: []\n"), 0o600); err != nil {
		t.Fatalf("write peers.yaml: %v", err)
	}
}

func TestServeExitsNonZeroOnMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runCLI("serve", "--config", filepath.Join(dir, "does-not-exist.yaml"))
	if code == 0 {
		t.Fatal("serve with a missing config exited 0, want non-zero")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestServeExitsNonZeroOnMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	// bogus_key is not a known field of server.yaml, which config.go
	// rejects with KnownFields(true) rather than silently ignoring it.
	malformed := "listen_port: 51820\nprivate_key: env:GOCLOAK_CMD_TEST_UNUSED\ntunnel_ip: 10.99.0.1\npeers_file: /tmp/unused.yaml\nbogus_key: true\n"
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
		t.Fatalf("write malformed server.yaml: %v", err)
	}

	code, _, stderr := runCLI("serve", "--config", path)
	if code == 0 {
		t.Fatal("serve with a malformed config exited 0, want non-zero")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

// TestServeExitsNonZeroOnUnresolvableSecret checks the fail-closed startup
// path: a syntactically valid config whose private key reference cannot be
// resolved (an unset environment variable, requiring no AWS and no
// network) must exit non-zero rather than start degraded.
func TestServeExitsNonZeroOnUnresolvableSecret(t *testing.T) {
	os.Unsetenv("GOCLOAK_CMD_TEST_NEVER_SET")

	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.yaml")
	writeValidPeersYAML(t, peersPath)

	serverPath := filepath.Join(dir, "server.yaml")
	content := fmt.Sprintf(validServeServerYAML, "env:GOCLOAK_CMD_TEST_NEVER_SET", peersPath)
	if err := os.WriteFile(serverPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write server.yaml: %v", err)
	}

	code, _, stderr := runCLI("serve", "--config", serverPath)
	if code == 0 {
		t.Fatal("serve with an unresolvable secret exited 0, want non-zero")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestServeRequiresConfigFlag(t *testing.T) {
	code, _, stderr := runCLI("serve")
	if code == 0 {
		t.Fatal("serve without --config exited 0, want non-zero")
	}
	if !strings.Contains(stderr, "--config") {
		t.Errorf("stderr does not mention --config: %q", stderr)
	}
}

// ---------------------------------------------------------------------------
// log_format
// ---------------------------------------------------------------------------

// TestNewLogHandlerSelectsFormat: log_format is the resolution of the
// carried task-7 requirement. ServerConfigFrom deliberately drops it
// because the library's own request logs are always JSON, so serve
// consumes it itself to configure the daemon's own logger. This checks
// that consumption actually happens for both accepted values and that an
// unrecognized value fails closed instead of silently defaulting.
func TestNewLogHandlerSelectsFormat(t *testing.T) {
	var buf bytes.Buffer

	jsonHandler, err := newLogHandler("json", &buf)
	if err != nil {
		t.Fatalf("newLogHandler(json): %v", err)
	}
	if _, ok := jsonHandler.(*slog.JSONHandler); !ok {
		t.Errorf("newLogHandler(json) returned %T, want *slog.JSONHandler", jsonHandler)
	}

	textHandler, err := newLogHandler("text", &buf)
	if err != nil {
		t.Fatalf("newLogHandler(text): %v", err)
	}
	if _, ok := textHandler.(*slog.TextHandler); !ok {
		t.Errorf("newLogHandler(text) returned %T, want *slog.TextHandler", textHandler)
	}

	if _, err := newLogHandler("xml", &buf); err == nil {
		t.Fatal("newLogHandler(xml) succeeded, want an error")
	}
}

// TestServeUsesConfiguredLogFormat exercises the resolution end to end: a
// server.yaml with log_format: text produces daemon output in slog's text
// form (key=value) rather than JSON, even though the request-handling
// server always logs JSON to its own stream.
func TestServeUsesConfiguredLogFormat(t *testing.T) {
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.yaml")
	writeValidPeersYAML(t, peersPath)

	serverPath := filepath.Join(dir, "server.yaml")
	content := fmt.Sprintf(validServeServerYAML, "env:GOCLOAK_CMD_TEST_TEXT_FORMAT_UNSET", peersPath) + "log_format: text\n"
	if err := os.WriteFile(serverPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write server.yaml: %v", err)
	}
	os.Unsetenv("GOCLOAK_CMD_TEST_TEXT_FORMAT_UNSET")

	_, _, stderr := runCLI("serve", "--config", serverPath)
	if !strings.Contains(stderr, "msg=") {
		t.Errorf("stderr does not look like slog text output: %q", stderr)
	}
	if strings.Contains(stderr, `"msg"`) {
		t.Errorf("stderr looks like JSON output despite log_format: text: %q", stderr)
	}
}
