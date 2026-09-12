package gocloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// SecretRef is a reference to key material, not the key material itself,
// e.g. "file:/etc/gocloak/server.key" or "env:GOCLOAK_PSK". Config types
// use SecretRef for secret-bearing fields so the compiler catches a config
// field accidentally populated with a literal secret value instead of a
// reference.
//
// This package resolves two schemes itself, file: and env:. Any other
// scheme, including the aws:sm: and aws:ssm: schemes that live in
// github.com/jbrahy/gocloak/awssecrets, is resolved by the SecretResolver
// the caller sets on ClientConfig.Resolver or ServerConfig.Resolver.
type SecretRef string

// SecretResolver resolves a scheme that the core library does not
// implement. Returning an error for an unrecognised scheme is correct.
//
// It exists so that a secret store's client library is a dependency of the
// programs that use that store, and of nothing else. Resolution used to
// switch on the scheme inside this package, which made every store's SDK
// reachable from any use of the package, so all of them linked: a program
// keeping its keys in a file: reference still paid for the AWS SDK in
// binary size, dependency count and supply-chain exposure.
//
// Three rules for an implementation:
//
//   - It is never asked to resolve file: or env:. Those are resolved here,
//     before a Resolver is consulted, so a Resolver cannot take them over.
//   - The returned slice is adopted as key material as it is. Do not retain
//     it, reuse it or mutate it after returning.
//   - Never put the resolved bytes in the returned error. The reference is
//     scrubbed out of an error before it reaches a log line; the value
//     behind it is never expected there in the first place.
type SecretResolver interface {
	ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error)
}

// secret holds resolved key material in memory. It is never written to disk.
// String and GoString return a redacted placeholder rather than the value,
// so a stray %v, %s, or %#v in a future log line cannot leak it.
type secret struct {
	value []byte
}

// bytes returns the resolved key material. It is deliberately unexported:
// it is the only accessor that hands raw key material to a caller, and
// nothing outside this package needs one. Keeping it in-package means the
// set of code that can hold a plaintext key is the set of code in this
// repository.
func (s secret) bytes() []byte {
	return s.value
}

// String implements fmt.Stringer with a redacted placeholder. It
// deliberately never returns the resolved value.
func (s secret) String() string {
	return "[REDACTED]"
}

// GoString implements fmt.GoStringer with the same redacted placeholder as
// String. Without this, %#v bypasses String and prints the raw bytes.
func (s secret) GoString() string {
	return "[REDACTED]"
}

// secretResolver resolves secret references to key material. It resolves
// file: and env: itself, with no dependency on anything outside the
// standard library, and delegates every other scheme to external, which is
// the caller's SecretResolver and is nil unless one was configured.
type secretResolver struct {
	external SecretResolver
}

// Resolve resolves a secret reference to its key material. file:<path> and
// env:<VAR> are resolved here. Any other scheme is delegated to the
// configured SecretResolver, and is an error when there is none. An
// unrecognized reference is always an error; it is never treated as a
// literal value.
func (r *secretResolver) Resolve(ctx context.Context, ref SecretRef) (secret, error) {
	scheme, payload, err := parseSecretRef(ref)
	if err != nil {
		return secret{}, err
	}
	switch scheme {
	case "file":
		return resolveFile(payload)
	case "env":
		return resolveEnv(payload)
	}

	if r.external == nil {
		return secret{}, fmt.Errorf("secret: scheme %q needs a Resolver: this package resolves file: and env: itself, and every other scheme comes from the SecretResolver set on ClientConfig.Resolver or ServerConfig.Resolver (aws:sm: and aws:ssm: live in github.com/jbrahy/gocloak/awssecrets)", scheme)
	}

	// The value is wrapped in a secret the moment it arrives, so the
	// redaction guarantees hold from here on. Nothing below formats it:
	// an error names the scheme and nothing else, because the bytes are
	// the one thing that must never reach a log line.
	value, rerr := r.external.ResolveSecret(ctx, ref)
	if rerr != nil {
		return secret{}, fmt.Errorf("secret: %s: resolver: %w", scheme, rerr)
	}
	if len(value) == 0 {
		return secret{}, fmt.Errorf("secret: %s: resolver returned no value", scheme)
	}
	return secret{value: value}, nil
}

// parseSecretRef splits a reference into its scheme and payload. It checks
// shape only: a scheme, a colon, and a non-empty payload. Which schemes
// resolve is Resolve's business, not this function's, because a caller can
// supply a SecretResolver for a scheme this package has never heard of, and
// a config file naming that scheme has to decode before that Resolver is
// anywhere in sight.
//
// Shape is still enough for the mistake SecretRef exists to catch. A
// literal key pasted where a reference belongs is base64 or hex, and
// neither alphabet contains a colon, so it has no scheme and is rejected
// here rather than being used as a key.
func parseSecretRef(ref SecretRef) (scheme, payload string, err error) {
	if ref == "" {
		return "", "", errors.New("secret: empty reference")
	}

	s := string(ref)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", fmt.Errorf("secret: reference %q has no scheme", s)
	}
	scheme, payload = s[:i], s[i+1:]

	if !validSchemeName(scheme) {
		return "", "", fmt.Errorf("secret: unknown scheme %q", scheme)
	}
	if payload == "" {
		return "", "", fmt.Errorf("secret: empty payload in reference %q", ref)
	}
	return scheme, payload, nil
}

// validSchemeName reports whether s has the shape of a scheme: a lowercase
// letter followed by lowercase letters, digits, '+', '-' or '.'. That is
// RFC 3986's scheme production without the uppercase half, which is
// deliberate: every scheme this project defines is lowercase, and keeping
// the set narrow is what stops a stray fragment of a pasted secret from
// passing for one.
func validSchemeName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// resolveFile resolves a file:<path> reference. It refuses to read a file
// whose permissions are looser than 0600. The permission check and the read
// are done against the same open file handle, so the file cannot be swapped
// out between the check and the read (TOCTOU).
func resolveFile(path string) (secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return secret{}, fmt.Errorf("secret: file:%s: permissions %#o are looser than 0600", path, info.Mode().Perm())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	return secret{value: data}, nil
}

// resolveEnv resolves an env:<VAR> reference.
func resolveEnv(name string) (secret, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return secret{}, fmt.Errorf("secret: env:%s: not set", name)
	}
	return secret{value: []byte(value)}, nil
}
