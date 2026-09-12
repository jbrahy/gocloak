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

	// The scheme is safe to name, and only the scheme: it has passed
	// validSchemeName, so it is lowercase and contains no colon, which no
	// fragment of a base64 or hex key can be. See parseSecretRef for why
	// nothing else about a reference reaches an error from this file.
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
//
// No error below quotes the reference. That rule is not a style choice: the
// input to this function is the one place in the package where a caller's
// mistake puts a literal secret in a string, and the two failures that
// mistake produces, no scheme and a malformed scheme, are exactly the two
// that would echo it. An error is logged; key material is not (spec section
// 8.2 and the fail-closed constraint on logging). Errors say what shape is
// wanted and name the schemes instead, which is what an operator needs and
// what an attacker reading a log does not get.
//
// The one fragment any error here may carry is a scheme that has already
// passed validSchemeName: lowercase, no colon, and by construction not a
// fragment of a base64 or hex key.
func parseSecretRef(ref SecretRef) (scheme, payload string, err error) {
	if ref == "" {
		return "", "", errors.New("secret: empty reference")
	}

	s := string(ref)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", errors.New(noSchemeMessage)
	}
	scheme, payload = s[:i], s[i+1:]

	if !validSchemeName(scheme) {
		return "", "", errors.New(badSchemeMessage)
	}
	if payload == "" {
		return "", "", fmt.Errorf("secret: scheme %s has an empty payload: want %s:<value>", scheme, scheme)
	}
	return scheme, payload, nil
}

// noSchemeMessage and badSchemeMessage are the two errors that a literal
// secret pasted into a SecretRef produces, so neither one may contain any
// part of what it was given. They are constants so the guarantee is visible
// in one place rather than spread across format strings.
const (
	noSchemeMessage = "secret: reference has no scheme: want <scheme>:<value>, for example " +
		"file:/etc/gocloak/server.key or env:GOCLOAK_PSK, or a scheme your SecretResolver " +
		"handles such as aws:sm:<secret-id>. The value given is not repeated here, because a " +
		"reference with no scheme is usually a literal key pasted where a reference belongs"

	badSchemeMessage = "secret: reference does not start with a usable scheme: a scheme is a " +
		"lowercase letter followed by lowercase letters, digits, '+', '-' or '.', as in file:, " +
		"env: or aws:sm:. The value given is not repeated here, because it may be a literal key " +
		"pasted where a reference belongs"
)

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
//
// The errors name the path and never the contents. A path reaches here only
// under an explicit file: scheme, so it is a path an operator wrote, not a
// key pasted where a reference belongs, and an operator debugging a startup
// failure needs to see which file was refused.
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
