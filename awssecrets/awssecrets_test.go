package awssecrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/jbrahy/gocloak"
)

// fakeSMClient is a stand-in for the Secrets Manager client. Tests use it so
// resolution can be exercised without network or AWS credentials.
type fakeSMClient struct {
	out *secretsmanager.GetSecretValueOutput
	err error
	// in records the last input, so a test can assert what was asked for.
	in *secretsmanager.GetSecretValueInput
}

func (f *fakeSMClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.in = params
	return f.out, f.err
}

// fakeSSMClient is a stand-in for the SSM client, same purpose as fakeSMClient.
type fakeSSMClient struct {
	out *ssm.GetParameterOutput
	err error
	in  *ssm.GetParameterInput
}

func (f *fakeSSMClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.in = params
	return f.out, f.err
}

// newWorking returns a Resolver whose fakes answer successfully.
func newWorking() *Resolver {
	return &Resolver{
		sm: &fakeSMClient{
			out: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("sm-secret-value"),
			},
		},
		ssm: &fakeSSMClient{
			out: &ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{
					Value: aws.String("ssm-secret-value"),
				},
			},
		},
	}
}

func TestResolveSecret(t *testing.T) {
	working := newWorking()

	failing := &Resolver{
		sm:  &fakeSMClient{err: errors.New("access denied")},
		ssm: &fakeSSMClient{err: errors.New("access denied")},
	}

	binary := &Resolver{
		sm: &fakeSMClient{
			out: &secretsmanager.GetSecretValueOutput{
				SecretBinary: []byte("sm-binary-value"),
			},
		},
	}

	empty := &Resolver{
		sm:  &fakeSMClient{out: &secretsmanager.GetSecretValueOutput{}},
		ssm: &fakeSSMClient{out: &ssm.GetParameterOutput{}},
	}

	tests := []struct {
		name     string
		ref      gocloak.SecretRef
		resolver *Resolver
		want     string
		wantErr  bool
	}{
		{name: "aws sm success", ref: "aws:sm:gocloak/server/private", resolver: working, want: "sm-secret-value"},
		{name: "aws sm binary", ref: "aws:sm:gocloak/server/private", resolver: binary, want: "sm-binary-value"},
		{name: "aws sm backend error", ref: "aws:sm:gocloak/server/private", resolver: failing, wantErr: true},
		{name: "aws sm no value returned", ref: "aws:sm:gocloak/server/private", resolver: empty, wantErr: true},
		{name: "aws ssm success", ref: "aws:ssm:/gocloak/server/private", resolver: working, want: "ssm-secret-value"},
		{name: "aws ssm backend error", ref: "aws:ssm:/gocloak/server/private", resolver: failing, wantErr: true},
		{name: "aws ssm no parameter returned", ref: "aws:ssm:/gocloak/server/private", resolver: empty, wantErr: true},
		{name: "empty reference", ref: "", resolver: working, wantErr: true},
		{name: "missing colon", ref: "nocolonhere", resolver: working, wantErr: true},
		{name: "not an aws reference", ref: "file:/etc/gocloak/server.key", resolver: working, wantErr: true},
		{name: "no aws sub-scheme", ref: "aws:gocloak/server/private", resolver: working, wantErr: true},
		{name: "unknown aws sub-scheme", ref: "aws:kms:foo", resolver: working, wantErr: true},
		{name: "empty payload aws sm", ref: "aws:sm:", resolver: working, wantErr: true},
		{name: "empty payload aws ssm", ref: "aws:ssm:", resolver: working, wantErr: true},
		{name: "empty sub-scheme", ref: "aws::foo", resolver: working, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.resolver.ResolveSecret(context.Background(), tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveSecret(%q) = %q, want error", tt.ref, got)
				}
				if len(got) != 0 {
					t.Fatalf("ResolveSecret(%q) returned key material alongside an error", tt.ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSecret(%q) unexpected error: %v", tt.ref, err)
			}
			if string(got) != tt.want {
				t.Fatalf("ResolveSecret(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

// TestResolveSecretSendsTheIdentifierItWasGiven pins what actually reaches
// AWS: the payload after the sub-scheme, with nothing trimmed or prefixed.
func TestResolveSecretSendsTheIdentifierItWasGiven(t *testing.T) {
	r := newWorking()

	if _, err := r.ResolveSecret(context.Background(), "aws:sm:gocloak/server/private"); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	sm := r.sm.(*fakeSMClient)
	if sm.in == nil || sm.in.SecretId == nil || *sm.in.SecretId != "gocloak/server/private" {
		t.Fatalf("GetSecretValue SecretId = %v, want %q", sm.in.SecretId, "gocloak/server/private")
	}

	if _, err := r.ResolveSecret(context.Background(), "aws:ssm:/gocloak/server/private"); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	s := r.ssm.(*fakeSSMClient)
	if s.in == nil || s.in.Name == nil || *s.in.Name != "/gocloak/server/private" {
		t.Fatalf("GetParameter Name = %v, want %q", s.in.Name, "/gocloak/server/private")
	}
}

// TestResolveSecretSSMAlwaysDecrypts is the one behaviour of the aws:ssm
// scheme that is invisible in its result and fatal to get wrong: without
// WithDecryption a SecureString parameter comes back as ciphertext, which
// would be accepted as key material and fail later as an unexplained
// handshake failure.
func TestResolveSecretSSMAlwaysDecrypts(t *testing.T) {
	r := newWorking()
	if _, err := r.ResolveSecret(context.Background(), "aws:ssm:/gocloak/server/private"); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	in := r.ssm.(*fakeSSMClient).in
	if in == nil || in.WithDecryption == nil || !*in.WithDecryption {
		t.Fatalf("GetParameter WithDecryption = %v, want true", in.WithDecryption)
	}
}

// TestResolveSecretWithNoClientsFailsClosed covers a zero Resolver, which is
// what a caller gets by writing awssecrets.Resolver{} instead of calling
// New. It must say so rather than panic on a nil client.
func TestResolveSecretWithNoClientsFailsClosed(t *testing.T) {
	var r Resolver
	for _, ref := range []gocloak.SecretRef{"aws:sm:x", "aws:ssm:/x"} {
		if _, err := r.ResolveSecret(context.Background(), ref); err == nil {
			t.Fatalf("ResolveSecret(%q) on a zero Resolver succeeded", ref)
		}
	}
}

// TestResolveSecretErrorNamesTheReferenceNotTheValue checks the half of the
// redaction contract this module owns: an error may name what it was asked
// for, because an operator needs that, and must never carry the value.
func TestResolveSecretErrorNamesTheReferenceNotTheValue(t *testing.T) {
	const value = "SUPERSECRETKEYMATERIAL"
	r := &Resolver{
		sm: &fakeSMClient{
			out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(value)},
			err: errors.New("access denied"),
		},
	}
	_, err := r.ResolveSecret(context.Background(), "aws:sm:gocloak/server/private")
	if err == nil {
		t.Fatal("ResolveSecret succeeded, want the backend error")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error carries the secret value: %v", err)
	}
	if !strings.Contains(err.Error(), "gocloak/server/private") {
		t.Fatalf("error should name the reference it failed on, got: %v", err)
	}
}
