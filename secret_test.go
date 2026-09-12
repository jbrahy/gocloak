package gocloak

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResolver is a stand-in for a caller-supplied SecretResolver, the way
// github.com/jbrahy/gocloak/awssecrets is one in production. Tests use it so
// the delegation path can be exercised with no store, no credentials and no
// network.
type fakeResolver struct {
	// values maps a whole reference to what resolving it returns.
	values map[SecretRef]string
	// err, when non-nil, is returned for any reference not in values.
	err error
	// calls records every reference the resolver was asked for, so a test
	// can assert that file: and env: never reach it.
	calls []SecretRef
}

func (f *fakeResolver) ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error) {
	f.calls = append(f.calls, ref)
	if v, ok := f.values[ref]; ok {
		return []byte(v), nil
	}
	if f.err != nil {
		return nil, f.err
	}
	return nil, fmt.Errorf("fakeResolver: no value for %q", string(ref))
}

// failingResolver fails the test if it is ever consulted. It is how the
// "core never delegates file: or env:" rule is asserted.
type failingResolver struct{ t *testing.T }

func (f failingResolver) ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error) {
	f.t.Helper()
	f.t.Fatalf("resolver was consulted for %q, which this package resolves itself", string(ref))
	return nil, nil
}

func TestSecretResolve(t *testing.T) {
	tmpDir := t.TempDir()

	okFile := filepath.Join(tmpDir, "ok-secret")
	if err := os.WriteFile(okFile, []byte("file-secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	looseFile := filepath.Join(tmpDir, "loose-secret")
	if err := os.WriteFile(looseFile, []byte("file-secret-value"), 0o644); err != nil {
		t.Fatal(err)
	}
	missingFile := filepath.Join(tmpDir, "does-not-exist")

	t.Setenv("GOCLOAK_TEST_SECRET", "env-secret-value")

	// working delegates the two AWS schemes the awssecrets module
	// implements, which is what a program wiring that module in has.
	working := &secretResolver{external: &fakeResolver{values: map[SecretRef]string{
		"aws:sm:gocloak/server/private":   "sm-secret-value",
		"aws:ssm:/gocloak/server/private": "ssm-secret-value",
		"vault:secret/gocloak":            "vault-secret-value",
	}}}

	failing := &secretResolver{external: &fakeResolver{err: errors.New("access denied")}}

	// bare has no Resolver at all: file: and env: work, everything else
	// is an error rather than a fallback.
	bare := &secretResolver{}

	tests := []struct {
		name     string
		ref      SecretRef
		resolver *secretResolver
		want     string
		wantErr  bool
	}{
		{name: "aws sm delegated", ref: "aws:sm:gocloak/server/private", resolver: working, want: "sm-secret-value"},
		{name: "aws sm resolver error", ref: "aws:sm:gocloak/server/private", resolver: failing, wantErr: true},
		{name: "aws ssm delegated", ref: "aws:ssm:/gocloak/server/private", resolver: working, want: "ssm-secret-value"},
		{name: "aws ssm resolver error", ref: "aws:ssm:/gocloak/server/private", resolver: failing, wantErr: true},
		{name: "third party scheme delegated", ref: "vault:secret/gocloak", resolver: working, want: "vault-secret-value"},
		{name: "aws sm with no resolver", ref: "aws:sm:gocloak/server/private", resolver: bare, wantErr: true},
		{name: "aws ssm with no resolver", ref: "aws:ssm:/gocloak/server/private", resolver: bare, wantErr: true},
		{name: "third party scheme with no resolver", ref: "vault:secret/gocloak", resolver: bare, wantErr: true},
		{name: "file success", ref: SecretRef("file:" + okFile), resolver: working, want: "file-secret-value"},
		{name: "file rejects 0644", ref: SecretRef("file:" + looseFile), resolver: working, wantErr: true},
		{name: "file missing", ref: SecretRef("file:" + missingFile), resolver: working, wantErr: true},
		{name: "file success with no resolver", ref: SecretRef("file:" + okFile), resolver: bare, want: "file-secret-value"},
		{name: "env success", ref: "env:GOCLOAK_TEST_SECRET", resolver: working, want: "env-secret-value"},
		{name: "env unset", ref: "env:GOCLOAK_TEST_SECRET_UNSET", resolver: working, wantErr: true},
		{name: "env success with no resolver", ref: "env:GOCLOAK_TEST_SECRET", resolver: bare, want: "env-secret-value"},
		{name: "unknown scheme", ref: "ftp:example.com/secret", resolver: bare, wantErr: true},
		{name: "empty reference", ref: "", resolver: working, wantErr: true},
		{name: "missing colon", ref: "nocolonhere", resolver: working, wantErr: true},
		{name: "empty payload file", ref: "file:", resolver: working, wantErr: true},
		{name: "empty payload env", ref: "env:", resolver: working, wantErr: true},
		{name: "empty payload aws sm", ref: "aws:sm:", resolver: working, wantErr: true},
		{name: "unknown aws subscheme", ref: "aws:kms:foo", resolver: working, wantErr: true},
		{name: "scheme with an uppercase letter", ref: "AWS:sm:foo", resolver: working, wantErr: true},
		{name: "scheme starting with a digit", ref: "1file:/tmp/x", resolver: working, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.resolver.Resolve(context.Background(), tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Resolve(%q) = %v, want error", tt.ref, got)
				}
				if len(got.bytes()) != 0 {
					t.Fatalf("Resolve(%q) returned key material alongside an error", tt.ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tt.ref, err)
			}
			if string(got.bytes()) != tt.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tt.ref, got.bytes(), tt.want)
			}
		})
	}
}

// TestSecretNativeSchemesNeverReachTheResolver pins the resolution order:
// file: and env: are resolved in this package and a configured Resolver is
// never consulted for them, so a Resolver cannot take over the two schemes
// that need no dependency to resolve.
func TestSecretNativeSchemesNeverReachTheResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("file-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCLOAK_TEST_NATIVE", "env-value")

	r := &secretResolver{external: failingResolver{t: t}}

	got, err := r.Resolve(context.Background(), SecretRef("file:"+path))
	if err != nil {
		t.Fatalf("Resolve(file:) unexpected error: %v", err)
	}
	if string(got.bytes()) != "file-value" {
		t.Fatalf("Resolve(file:) = %q, want %q", got.bytes(), "file-value")
	}

	got, err = r.Resolve(context.Background(), "env:GOCLOAK_TEST_NATIVE")
	if err != nil {
		t.Fatalf("Resolve(env:) unexpected error: %v", err)
	}
	if string(got.bytes()) != "env-value" {
		t.Fatalf("Resolve(env:) = %q, want %q", got.bytes(), "env-value")
	}
}

// TestSecretUnknownSchemeWithNoResolverExplainsItself covers the error an
// operator actually hits after the AWS schemes moved out of this module: it
// has to name what this package does resolve and say that anything else
// needs a Resolver, without echoing the payload, which may be a pasted
// secret.
func TestSecretUnknownSchemeWithNoResolverExplainsItself(t *testing.T) {
	const payload = "gocloak/server/private"
	r := &secretResolver{}

	_, err := r.Resolve(context.Background(), SecretRef("aws:sm:"+payload))
	if err == nil {
		t.Fatal("resolving an aws:sm: reference with no Resolver succeeded, want an error")
	}
	msg := err.Error()
	for _, want := range []string{"file:", "env:", "Resolver", "awssecrets"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
	if strings.Contains(msg, payload) {
		t.Errorf("error echoes the reference payload, which may be a pasted secret: %v", err)
	}
}

// TestSecretResolverErrorDoesNotCarryKeyMaterial proves this package never
// puts a resolved value into an error, including the case of a Resolver
// that hands back both a value and an error.
func TestSecretResolverErrorDoesNotCarryKeyMaterial(t *testing.T) {
	const value = "SUPERSECRETKEYMATERIAL"

	r := &secretResolver{external: resolverFunc(func(ctx context.Context, ref SecretRef) ([]byte, error) {
		return []byte(value), errors.New("store unavailable")
	})}

	got, err := r.Resolve(context.Background(), "vault:secret/gocloak")
	if err == nil {
		t.Fatal("a Resolver that returned an error resolved successfully")
	}
	if len(got.bytes()) != 0 {
		t.Fatal("a Resolver that returned an error still yielded key material")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error carries the resolved value: %v", err)
	}
}

// TestSecretResolverEmptyValueIsAnError covers a Resolver that reports
// success with nothing in it. An empty key is not a key, and accepting one
// would surface later as an unexplained handshake failure.
func TestSecretResolverEmptyValueIsAnError(t *testing.T) {
	r := &secretResolver{external: resolverFunc(func(ctx context.Context, ref SecretRef) ([]byte, error) {
		return nil, nil
	})}
	if _, err := r.Resolve(context.Background(), "vault:secret/gocloak"); err == nil {
		t.Fatal("a Resolver returning no value resolved successfully, want an error")
	}
}

// TestSecretDelegatedValueIsRedacted proves a value that came from outside
// this package is wrapped in secret on receipt, so it inherits the same
// redaction guarantee as one resolved here.
func TestSecretDelegatedValueIsRedacted(t *testing.T) {
	const value = "delegated-key-material"
	r := &secretResolver{external: resolverFunc(func(ctx context.Context, ref SecretRef) ([]byte, error) {
		return []byte(value), nil
	})}

	got, err := r.Resolve(context.Background(), "vault:secret/gocloak")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got.bytes()) != value {
		t.Fatalf("Resolve = %q, want %q", got.bytes(), value)
	}
	for _, repr := range []string{fmt.Sprintf("%v", got), fmt.Sprintf("%#v", got)} {
		if repr != "[REDACTED]" {
			t.Fatalf("delegated value renders as %q, want [REDACTED]", repr)
		}
	}
}

// resolverFunc adapts a function to SecretResolver.
type resolverFunc func(ctx context.Context, ref SecretRef) ([]byte, error)

func (f resolverFunc) ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error) {
	return f(ctx, ref)
}

// TestSecretRejectsLooseFilePermissions is the explicit 0644 rejection case
// the brief requires, isolated from the table above so it reads clearly on
// its own.
func TestSecretRejectsLooseFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	loose := filepath.Join(tmpDir, "loose")
	if err := os.WriteFile(loose, []byte("value"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &secretResolver{}
	_, err := r.Resolve(context.Background(), SecretRef("file:"+loose))
	if err == nil {
		t.Fatalf("Resolve of a 0644 file did not error")
	}
}

// TestSecretRejectsUnknownScheme is the explicit unknown-scheme rejection
// case the brief requires: an unrecognized scheme must error, never fall
// back to treating the reference as a literal value. It holds both with no
// Resolver and with one that does not recognize the scheme either.
func TestSecretRejectsUnknownScheme(t *testing.T) {
	refusing := &fakeResolver{}
	resolvers := map[string]*secretResolver{
		"no resolver":      {},
		"resolver refuses": {external: refusing},
	}
	for name, r := range resolvers {
		t.Run(name, func(t *testing.T) {
			got, err := r.Resolve(context.Background(), "http:not-a-real-scheme")
			if err == nil {
				t.Fatalf("Resolve of an unknown scheme did not error, got %v", got)
			}
			if string(got.bytes()) == "http:not-a-real-scheme" {
				t.Fatal("Resolve treated an unknown reference as a literal value")
			}
		})
	}
	// The Resolver, when there is one, is the thing that got to refuse:
	// an unknown scheme is delegated before it is rejected, so a caller
	// can add http: support without this package changing.
	if len(refusing.calls) != 1 || refusing.calls[0] != "http:not-a-real-scheme" {
		t.Fatalf("resolver calls = %v, want the unknown reference delegated once", refusing.calls)
	}
}

// TestSecretStringRedacted proves the returned type never renders the
// resolved value through %v, %s, or %#v, for both value and pointer
// receivers, so a future log line or debug struct dump cannot leak it.
//
// %#v bypasses String() and, without a GoString() method, would print the
// raw bytes as a []uint8 literal (e.g. []uint8{0x74, 0x6f, 0x70, ...}) which
// is a leak even though it does not contain the plaintext substring. So
// this asserts the exact redacted placeholder, not just the absence of the
// plaintext, to actually catch that case.
func TestSecretStringRedacted(t *testing.T) {
	const want = "[REDACTED]"
	s := secret{value: []byte("top-secret-value")}
	p := &s

	cases := []struct {
		name string
		repr string
	}{
		{"value %v", fmt.Sprintf("%v", s)},
		//lint:ignore S1025 deliberately exercising fmt's %s verb to confirm it
		// routes through secret's Stringer instead of calling String() directly
		{"value %s", fmt.Sprintf("%s", s)},
		{"value %#v", fmt.Sprintf("%#v", s)},
		{"pointer %v", fmt.Sprintf("%v", p)},
		//lint:ignore S1025 deliberately exercising fmt's %s verb to confirm it
		// routes through secret's Stringer instead of calling String() directly
		{"pointer %s", fmt.Sprintf("%s", p)},
		{"pointer %#v", fmt.Sprintf("%#v", p)},
	}
	for _, tc := range cases {
		if tc.repr != want {
			t.Fatalf("%s = %q, want %q (redacted)", tc.name, tc.repr, want)
		}
		if strings.Contains(tc.repr, "top-secret-value") {
			t.Fatalf("%s leaked the resolved value: %q", tc.name, tc.repr)
		}
	}
}

// TestSecretErrorsNeverEchoTheReference is the regression test for the leak
// that shipped in v0.1.0: parseSecretRef answered a reference with no scheme
// with `secret: reference %q has no scheme`, so a literal 32-byte key pasted
// where a SecretRef belongs came back, verbatim and in full, inside an error
// that a caller logs. The YAML path was already guarded by validSecretRef;
// the programmatic path, which is what a library consumer builds a
// ClientConfig on, was not.
//
// The rule the test pins: no error from parsing or resolving a reference may
// contain the text it was given. A reference with no scheme is precisely the
// case where that text is most likely to be a key.
//
// It checks every 10-character window of the input rather than the whole
// string, so a partial echo (a truncated key, a quoted prefix, a scheme that
// is really the head of a pasted secret) fails it too. Ten is the smallest
// window that still permits the one fragment an error here is allowed to
// carry, a scheme that has passed validSchemeName plus its colon: the
// longest this project defines, "aws:ssm:", is eight characters. Anything
// larger echoed from a reference fails the test.
func TestSecretErrorsNeverEchoTheReference(t *testing.T) {
	// Secret-shaped inputs: what an operator actually pastes when they get
	// this wrong. The first is the exact value that reproduced the v0.1.0
	// leak.
	inputs := []SecretRef{
		"jLTRL6w9l++zTSr+i3m6w61Eep/UvCa9cVtyxEKdIlg=",
		"8f40a1c7b25e93d06a4f18cc7b2e5d3491ab6720ff8c1d5e9a03b47c62d8e105",
		"AKIAIOSFODNN7EXAMPLE",
		"hunter2:correct-horse-battery-staple",
		"Aws:sm:gocloak/server/private",
		"3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
	}

	// Both resolvers, because delegation is a second path to an error: one
	// with no SecretResolver at all and one with a resolver that refuses
	// everything, the way a real store does for a reference it cannot find.
	bare := &secretResolver{}
	delegating := &secretResolver{external: &fakeResolver{err: errors.New("access denied")}}

	for _, ref := range inputs {
		t.Run(string(ref[:min(len(ref), 12)]), func(t *testing.T) {
			var errs []error

			if _, _, err := parseSecretRef(ref); err != nil {
				errs = append(errs, err)
			}
			if _, err := bare.Resolve(context.Background(), ref); err != nil {
				errs = append(errs, err)
			}
			if _, err := delegating.Resolve(context.Background(), ref); err != nil {
				errs = append(errs, err)
			}
			if err := validSecretRef(ref); err != nil {
				errs = append(errs, err)
			}
			// The live path a library consumer is on: a ClientConfig
			// built in Go with a literal key in a SecretRef field.
			if _, err := NewClient(ClientConfig{
				Endpoint:     "198.51.100.1:51820",
				ServerPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PrivateKey:   ref,
				PresharedKey: ref,
				TunnelIP:     netip.MustParseAddr("10.99.0.7"),
			}); err != nil {
				errs = append(errs, err)
			}

			if len(errs) == 0 {
				t.Fatalf("no error for %q, so this case proves nothing", string(ref))
			}
			for _, err := range errs {
				assertNoFragmentOf(t, err.Error(), string(ref))
			}
		})
	}
}

// assertNoFragmentOf fails the test if any 10-character window of the
// reference appears in msg.
func assertNoFragmentOf(t *testing.T, msg, secretText string) {
	t.Helper()
	const window = 10
	if strings.Contains(msg, secretText) {
		t.Fatalf("error echoes the whole reference:\n  error: %s\n  reference: %s", msg, secretText)
	}
	for i := 0; i+window <= len(secretText); i++ {
		if fragment := secretText[i : i+window]; strings.Contains(msg, fragment) {
			t.Fatalf("error echoes %q, a fragment of the reference:\n  error: %s", fragment, msg)
		}
	}
}
