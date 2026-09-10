package gocloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SecretRef is a reference to key material, not the key material itself,
// e.g. "aws:sm:gocloak/server/private" or "env:GOCLOAK_PSK". Config types
// use SecretRef for secret-bearing fields so the compiler catches a config
// field accidentally populated with a literal secret value instead of a
// reference.
type SecretRef string

// Secret holds resolved key material in memory. It is never written to disk.
// String and GoString return a redacted placeholder rather than the value,
// so a stray %v, %s, or %#v in a future log line cannot leak it.
type Secret struct {
	value []byte
}

// Bytes returns the resolved key material.
func (s Secret) Bytes() []byte {
	return s.value
}

// String implements fmt.Stringer with a redacted placeholder. It
// deliberately never returns the resolved value.
func (s Secret) String() string {
	return "[REDACTED]"
}

// GoString implements fmt.GoStringer with the same redacted placeholder as
// String. Without this, %#v bypasses String and prints the raw bytes.
func (s Secret) GoString() string {
	return "[REDACTED]"
}

// secretsManagerAPI is the subset of the Secrets Manager client used to
// resolve aws:sm references. A small interface here lets tests inject a
// fake, so resolution can be unit tested without network or AWS credentials.
type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// ssmAPI is the subset of the SSM client used to resolve aws:ssm references.
type ssmAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// SecretResolver resolves secret references to key material. Use
// NewSecretResolver to build one against real AWS clients; tests construct
// one directly with fake sm/ssm implementations.
type SecretResolver struct {
	sm  secretsManagerAPI
	ssm ssmAPI
}

// NewSecretResolver builds a SecretResolver backed by real AWS clients,
// using region and credentials from the ambient environment.
func NewSecretResolver(ctx context.Context) (*SecretResolver, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("secret: load AWS config: %w", err)
	}
	return &SecretResolver{
		sm:  secretsmanager.NewFromConfig(cfg),
		ssm: ssm.NewFromConfig(cfg),
	}, nil
}

// Resolve resolves a secret reference to its key material. Supported schemes
// are aws:sm:<secret-id>, aws:ssm:<parameter>, file:<path>, and env:<VAR>.
// An unrecognized scheme is always an error; it is never treated as a
// literal value.
func (r *SecretResolver) Resolve(ctx context.Context, ref SecretRef) (Secret, error) {
	scheme, payload, err := parseSecretRef(ref)
	if err != nil {
		return Secret{}, err
	}
	switch scheme {
	case "aws:sm":
		return r.resolveAWSSecretsManager(ctx, payload)
	case "aws:ssm":
		return r.resolveAWSSSM(ctx, payload)
	case "file":
		return resolveFile(payload)
	case "env":
		return resolveEnv(payload)
	default:
		// parseSecretRef only returns known schemes; unreachable.
		return Secret{}, fmt.Errorf("secret: unknown scheme %q", scheme)
	}
}

// parseSecretRef splits a reference into its scheme and payload, and
// rejects anything that is not one of the four known schemes. An unknown
// scheme is always an error, never a fallback to treating ref as a literal.
func parseSecretRef(ref SecretRef) (scheme, payload string, err error) {
	if ref == "" {
		return "", "", errors.New("secret: empty reference")
	}

	s := string(ref)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", fmt.Errorf("secret: reference %q has no scheme", s)
	}
	head, rest := s[:i], s[i+1:]

	switch head {
	case "aws":
		j := strings.IndexByte(rest, ':')
		if j < 0 {
			return "", "", fmt.Errorf("secret: reference %q has no scheme", ref)
		}
		scheme = "aws:" + rest[:j]
		payload = rest[j+1:]
	case "file", "env":
		scheme = head
		payload = rest
	default:
		return "", "", fmt.Errorf("secret: unknown scheme %q", head)
	}

	switch scheme {
	case "aws:sm", "aws:ssm", "file", "env":
		// known scheme, fall through to payload check
	default:
		return "", "", fmt.Errorf("secret: unknown scheme %q", scheme)
	}

	if payload == "" {
		return "", "", fmt.Errorf("secret: empty payload in reference %q", ref)
	}
	return scheme, payload, nil
}

// resolveAWSSecretsManager resolves an aws:sm:<secret-id> reference.
func (r *SecretResolver) resolveAWSSecretsManager(ctx context.Context, id string) (Secret, error) {
	out, err := r.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return Secret{}, fmt.Errorf("secret: aws:sm:%s: %w", id, err)
	}
	if out.SecretString != nil {
		return Secret{value: []byte(*out.SecretString)}, nil
	}
	if out.SecretBinary != nil {
		return Secret{value: out.SecretBinary}, nil
	}
	return Secret{}, fmt.Errorf("secret: aws:sm:%s: no secret value returned", id)
}

// resolveAWSSSM resolves an aws:ssm:<parameter> reference, always requesting
// decryption so SecureString parameters come back in plaintext.
func (r *SecretResolver) resolveAWSSSM(ctx context.Context, name string) (Secret, error) {
	out, err := r.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return Secret{}, fmt.Errorf("secret: aws:ssm:%s: %w", name, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return Secret{}, fmt.Errorf("secret: aws:ssm:%s: no parameter value returned", name)
	}
	return Secret{value: []byte(*out.Parameter.Value)}, nil
}

// resolveFile resolves a file:<path> reference. It refuses to read a file
// whose permissions are looser than 0600. The permission check and the read
// are done against the same open file handle, so the file cannot be swapped
// out between the check and the read (TOCTOU).
func resolveFile(path string) (Secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("secret: file:%s: permissions %#o are looser than 0600", path, info.Mode().Perm())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return Secret{}, fmt.Errorf("secret: file:%s: %w", path, err)
	}
	return Secret{value: data}, nil
}

// resolveEnv resolves an env:<VAR> reference.
func resolveEnv(name string) (Secret, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return Secret{}, fmt.Errorf("secret: env:%s: not set", name)
	}
	return Secret{value: []byte(value)}, nil
}
