package gocloak_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jbrahy/gocloak"
	"github.com/jbrahy/gocloak/internal/msg"
)

// TestExampleAppsEndToEnd stands up the gocloak-sink logic (internal/msg's
// Serve, on a loopback listener) behind a real gocloak.NewServer, then
// reaches it with a real gocloak.NewClient and internal/msg.Send: the same
// three pieces the README quickstart wires together as gocloak-sink,
// `gocloak serve` and gocloak-send. It reuses exampleStartServer and its
// helpers from example_test.go, the same way those functions stand in for
// `gocloak keygen`, server.yaml and peers.yaml.
//
// This is the test that fails if the README quickstart ever drifts from
// what the library and the example apps actually do: gocloak-sink and
// gocloak-send are thin wrappers around exactly the calls made here.
func TestExampleAppsEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), exampleBudget)
	defer cancel()

	// The sink: a plain TCP listener served by internal/msg, standing in
	// for `gocloak-sink --listen`. It is not a goCloak peer, exactly as
	// gocloak-sink's own doc comment says.
	sinkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sinkLn.Close()

	var mu sync.Mutex
	var gotAddr string
	var gotMessage string
	received := make(chan struct{}, 1)

	sinkDone := make(chan error, 1)
	go func() {
		sinkDone <- msg.Serve(ctx, sinkLn, func(addr string, message []byte) {
			mu.Lock()
			gotAddr = addr
			gotMessage = string(message)
			mu.Unlock()
			received <- struct{}{}
		}, slog.Default())
	}()

	// The operator's side: keys, peers.yaml (granting "primary-db" at the
	// sink's address), server.yaml, and a running server, exactly what
	// `gocloak keygen` and `gocloak serve --config server.yaml` produce.
	dep := exampleStartServer(ctx, sinkLn.Addr().String())
	defer dep.stop()

	// The application's side: what gocloak-send's --endpoint, --server-key,
	// --key, --psk and --tunnel-ip flags configure.
	client, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     dep.endpoint,
		ServerPubKey: dep.serverPubKey,
		PrivateKey:   dep.peerKeyRef,
		PresharedKey: dep.peerPSKRef,
		TunnelIP:     netip.MustParseAddr("10.99.0.7"),
		DialTimeout:  exampleBudget,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial(ctx, "primary-db")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(exampleBudget)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// gocloak-send's own work: write the message, read the ack.
	const wantMessage = "hello from the tunnel"
	ack, elapsed, err := msg.Send(conn, wantMessage)
	if err != nil {
		t.Fatalf("msg.Send: %v", err)
	}
	if ack != "ACK 21" {
		t.Fatalf("ack = %q, want %q", ack, "ACK 21")
	}
	if elapsed <= 0 {
		t.Fatalf("elapsed = %v, want > 0", elapsed)
	}

	select {
	case <-received:
	case <-ctx.Done():
		t.Fatalf("sink never received a message: %v", ctx.Err())
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMessage != wantMessage {
		t.Fatalf("sink received %q, want %q", gotMessage, wantMessage)
	}
	if gotAddr == "" {
		t.Fatalf("sink recorded an empty source address")
	}

	cancel()
	if err := <-sinkDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("sink Serve returned %v, want context.Canceled", err)
	}
}
