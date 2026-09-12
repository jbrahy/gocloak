// Package awssecrets resolves gocloak secret references that live in AWS:
// aws:sm:<secret-id> in Secrets Manager and aws:ssm:<parameter> in SSM
// Parameter Store.
//
// It is a module of its own, not a package inside gocloak, and that is the
// whole point. A package here would still put aws-sdk-go-v2 in the core
// module's go.mod and go.sum, so every consumer would download it and every
// audit of the core module would have to cover it, whether or not any AWS
// scheme is ever used. A separate module means the SDK is a dependency of
// the programs that resolve AWS references and of nothing else.
//
// Wire it in explicitly:
//
//	resolver, err := awssecrets.New(ctx)
//	if err != nil {
//		return err
//	}
//	client, err := gocloak.NewClient(gocloak.ClientConfig{
//		PrivateKey:   "aws:sm:gocloak/app-01/private",
//		PresharedKey: "aws:sm:gocloak/app-01/psk",
//		Resolver:     resolver,
//		// ...
//	})
package awssecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/jbrahy/gocloak"
)

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

// Resolver resolves aws:sm: and aws:ssm: references. Use New to build one
// against real AWS clients; tests construct one directly with fakes.
//
// It satisfies gocloak.SecretResolver, so it is set on
// gocloak.ClientConfig.Resolver or gocloak.ServerConfig.Resolver and is
// consulted only for schemes gocloak does not resolve itself. file: and
// env: never reach it.
type Resolver struct {
	sm  secretsManagerAPI
	ssm ssmAPI
}

// Resolver must satisfy the interface it exists to implement. Checked here
// so a change to either side is a compile error rather than a surprise at
// the call site.
var _ gocloak.SecretResolver = (*Resolver)(nil)

// New builds a Resolver backed by real AWS clients, using region and
// credentials from the ambient environment.
func New(ctx context.Context) (*Resolver, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("awssecrets: load AWS config: %w", err)
	}
	return &Resolver{
		sm:  secretsmanager.NewFromConfig(cfg),
		ssm: ssm.NewFromConfig(cfg),
	}, nil
}

// ResolveSecret implements gocloak.SecretResolver. Supported schemes are
// aws:sm:<secret-id> and aws:ssm:<parameter>. Anything else is an error:
// this resolver speaks for AWS and nothing else, and gocloak treats an
// error here as a failure to resolve, never as a reason to improvise.
//
// The returned error names the reference it failed on, which is what an
// operator needs, and never the value behind it. gocloak scrubs the
// reference out before the error reaches a log line.
func (r *Resolver) ResolveSecret(ctx context.Context, ref gocloak.SecretRef) ([]byte, error) {
	scheme, payload, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "aws:sm":
		return r.secretsManager(ctx, payload)
	case "aws:ssm":
		return r.ssmParameter(ctx, payload)
	default:
		return nil, fmt.Errorf("awssecrets: unknown scheme %q, want aws:sm or aws:ssm", scheme)
	}
}

// parseRef splits an aws: reference into its two-part scheme and its
// payload. It rejects anything that is not aws:<sub>:<payload> with both
// parts present, so an empty secret id is refused here rather than being
// sent to AWS as a lookup for "".
func parseRef(ref gocloak.SecretRef) (scheme, payload string, err error) {
	s := string(ref)
	if s == "" {
		return "", "", errors.New("awssecrets: empty reference")
	}
	head, rest, ok := strings.Cut(s, ":")
	if !ok || head != "aws" {
		return "", "", fmt.Errorf("awssecrets: reference %q is not an aws: reference", s)
	}
	sub, payload, ok := strings.Cut(rest, ":")
	if !ok || sub == "" {
		return "", "", fmt.Errorf("awssecrets: reference %q has no aws sub-scheme, want aws:sm:<secret-id> or aws:ssm:<parameter>", s)
	}
	if payload == "" {
		return "", "", fmt.Errorf("awssecrets: empty payload in reference %q", s)
	}
	return "aws:" + sub, payload, nil
}

// secretsManager resolves an aws:sm:<secret-id> reference.
func (r *Resolver) secretsManager(ctx context.Context, id string) ([]byte, error) {
	if r.sm == nil {
		return nil, errors.New("awssecrets: no Secrets Manager client; build the Resolver with New")
	}
	out, err := r.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return nil, fmt.Errorf("awssecrets: aws:sm:%s: %w", id, err)
	}
	if out == nil {
		return nil, fmt.Errorf("awssecrets: aws:sm:%s: no secret value returned", id)
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	if out.SecretBinary != nil {
		return out.SecretBinary, nil
	}
	return nil, fmt.Errorf("awssecrets: aws:sm:%s: no secret value returned", id)
}

// ssmParameter resolves an aws:ssm:<parameter> reference, always requesting
// decryption so SecureString parameters come back in plaintext.
func (r *Resolver) ssmParameter(ctx context.Context, name string) ([]byte, error) {
	if r.ssm == nil {
		return nil, errors.New("awssecrets: no SSM client; build the Resolver with New")
	}
	out, err := r.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("awssecrets: aws:ssm:%s: %w", name, err)
	}
	if out == nil || out.Parameter == nil || out.Parameter.Value == nil {
		return nil, fmt.Errorf("awssecrets: aws:ssm:%s: no parameter value returned", name)
	}
	return []byte(*out.Parameter.Value), nil
}
