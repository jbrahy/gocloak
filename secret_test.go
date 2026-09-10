package gocloak

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeSMClient is a stand-in for the Secrets Manager client. Tests use it so
// resolution can be exercised without network or AWS credentials.
type fakeSMClient struct {
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (f fakeSMClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return f.out, f.err
}

// fakeSSMClient is a stand-in for the SSM client, same purpose as fakeSMClient.
type fakeSSMClient struct {
	out *ssm.GetParameterOutput
	err error
}

func (f fakeSSMClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	return f.out, f.err
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

	working := &SecretResolver{
		sm: fakeSMClient{
			out: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("sm-secret-value"),
			},
		},
		ssm: fakeSSMClient{
			out: &ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{
					Value: aws.String("ssm-secret-value"),
				},
			},
		},
	}

	failing := &SecretResolver{
		sm:  fakeSMClient{err: errors.New("access denied")},
		ssm: fakeSSMClient{err: errors.New("access denied")},
	}

	tests := []struct {
		name     string
		ref      string
		resolver *SecretResolver
		want     string
		wantErr  bool
	}{
		{name: "aws sm success", ref: "aws:sm:gocloak/server/private", resolver: working, want: "sm-secret-value"},
		{name: "aws sm backend error", ref: "aws:sm:gocloak/server/private", resolver: failing, wantErr: true},
		{name: "aws ssm success", ref: "aws:ssm:/gocloak/server/private", resolver: working, want: "ssm-secret-value"},
		{name: "aws ssm backend error", ref: "aws:ssm:/gocloak/server/private", resolver: failing, wantErr: true},
		{name: "file success", ref: "file:" + okFile, resolver: working, want: "file-secret-value"},
		{name: "file rejects 0644", ref: "file:" + looseFile, resolver: working, wantErr: true},
		{name: "file missing", ref: "file:" + missingFile, resolver: working, wantErr: true},
		{name: "env success", ref: "env:GOCLOAK_TEST_SECRET", resolver: working, want: "env-secret-value"},
		{name: "env unset", ref: "env:GOCLOAK_TEST_SECRET_UNSET", resolver: working, wantErr: true},
		{name: "unknown scheme", ref: "ftp:example.com/secret", resolver: working, wantErr: true},
		{name: "empty reference", ref: "", resolver: working, wantErr: true},
		{name: "missing colon", ref: "nocolonhere", resolver: working, wantErr: true},
		{name: "empty payload file", ref: "file:", resolver: working, wantErr: true},
		{name: "empty payload env", ref: "env:", resolver: working, wantErr: true},
		{name: "empty payload aws sm", ref: "aws:sm:", resolver: working, wantErr: true},
		{name: "unknown aws subscheme", ref: "aws:kms:foo", resolver: working, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.resolver.Resolve(context.Background(), tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Resolve(%q) = %v, want error", tt.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tt.ref, err)
			}
			if string(got.Bytes()) != tt.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tt.ref, got.Bytes(), tt.want)
			}
		})
	}
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

	r := &SecretResolver{}
	_, err := r.Resolve(context.Background(), "file:"+loose)
	if err == nil {
		t.Fatalf("Resolve of a 0644 file did not error")
	}
}

// TestSecretRejectsUnknownScheme is the explicit unknown-scheme rejection
// case the brief requires: an unrecognized scheme must error, never fall
// back to treating the reference as a literal value.
func TestSecretRejectsUnknownScheme(t *testing.T) {
	r := &SecretResolver{}
	got, err := r.Resolve(context.Background(), "http:not-a-real-scheme")
	if err == nil {
		t.Fatalf("Resolve of an unknown scheme did not error, got %v", got)
	}
}

// TestSecretStringRedacted proves the returned type never renders the
// resolved value through String/%v, so a future log line using %v cannot
// leak it.
func TestSecretStringRedacted(t *testing.T) {
	s := Secret{value: []byte("top-secret-value")}
	repr := fmt.Sprintf("%v", s)
	if strings.Contains(repr, "top-secret-value") {
		t.Fatalf("Secret.String() leaked the resolved value: %q", repr)
	}
}
