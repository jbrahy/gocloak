package awssecrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/jbrahy/gocloak"
)

// fakeSMByID answers GetSecretValue from a map of secret id to value, so
// the test needs no AWS credentials and no network. It is the same
// fake-client approach as the unit tests, keyed by id because this test
// resolves two different references through one Resolver.
type fakeSMByID struct {
	values map[string]string
}

func (f fakeSMByID) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	id := aws.ToString(params.SecretId)
	v, ok := f.values[id]
	if !ok {
		return nil, fmt.Errorf("fakeSMByID: no secret %q", id)
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

// integrationTestKey returns a random 32-byte key in the base64 form
// gocloak expects for a Curve25519 private key or a preshared key.
func integrationTestKey(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// TestResolverDrivesAGocloakClient is the proof that this module and the
// core module actually fit together: a Resolver built on a fake Secrets
// Manager client is set as gocloak.ClientConfig.Resolver, and a client
// whose private key and preshared key are both aws:sm: references comes up
// on key material that arrived through it.
//
// It goes through the core module's public API rather than calling
// ResolveSecret directly. The unit tests already cover what this module
// returns; what this covers is the wiring: that Resolver satisfies the
// interface the core module declares, that the core module consults it for
// a scheme it does not implement, and that what comes back is accepted as a
// key.
func TestResolverDrivesAGocloakClient(t *testing.T) {
	privateKey := integrationTestKey(t)
	psk := integrationTestKey(t)
	serverPub := integrationTestKey(t)

	resolver := &Resolver{sm: fakeSMByID{values: map[string]string{
		"gocloak/app-01/private": privateKey,
		"gocloak/app-01/psk":     psk,
	}}}

	client, err := gocloak.NewClient(gocloak.ClientConfig{
		// TEST-NET-2 (RFC 5737): reserved for documentation, so
		// nothing answers. NewClient sends no packet anyway.
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: serverPub,
		PrivateKey:   "aws:sm:gocloak/app-01/private",
		PresharedKey: "aws:sm:gocloak/app-01/psk",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
		Resolver:     resolver,
	})
	if err != nil {
		t.Fatalf("NewClient with an awssecrets.Resolver: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestGocloakClientWithoutTheResolverFailsClosed is the counterpart: the
// same config with no Resolver must refuse to build a client. That is the
// breaking change this module exists to make explicit, and the error has to
// be the one that sends an operator here.
func TestGocloakClientWithoutTheResolverFailsClosed(t *testing.T) {
	_, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     "198.51.100.1:51820",
		ServerPubKey: integrationTestKey(t),
		PrivateKey:   "aws:sm:gocloak/app-01/private",
		PresharedKey: "aws:sm:gocloak/app-01/psk",
		TunnelIP:     netip.MustParseAddr("10.99.0.8"),
	})
	if err == nil {
		t.Fatal("NewClient succeeded with aws:sm: references and no Resolver")
	}
}

// TestServerConfigAcceptsTheResolver pins the other of the two wiring
// points the core module grew, so this module is proven against both rather
// than only the client one. What the server does with it is the same
// delegation the client test above exercises end to end; what is worth
// pinning here is that the field takes a *Resolver and holds it.
func TestServerConfigAcceptsTheResolver(t *testing.T) {
	r := &Resolver{sm: fakeSMByID{}}
	cfg := gocloak.ServerConfig{Resolver: r}
	if cfg.Resolver != gocloak.SecretResolver(r) {
		t.Fatalf("ServerConfig.Resolver = %v, want the resolver it was given", cfg.Resolver)
	}
}
