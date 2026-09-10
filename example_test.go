package gocloak_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/jbrahy/gocloak"
)

// exampleBudget bounds every step of the example. A WireGuard handshake is
// not instant, so Dial retries internally, but it always retries under a
// deadline: a broken tunnel must fail this example rather than hang it.
const exampleBudget = 60 * time.Second

// Example runs a complete goCloak deployment in one process: a backend
// service, a gocloak server that fronts it, and a client that reaches the
// backend by name over a real WireGuard tunnel on localhost UDP.
//
// The deployment half is what an operator writes in server.yaml and
// peers.yaml. The client half, from NewClient down, is what an application
// writes.
func Example() {
	ctx, cancel := context.WithTimeout(context.Background(), exampleBudget)
	defer cancel()

	// A backend service. In a real deployment this is a database, a cache
	// or an internal HTTP service inside the VPC, reachable from the
	// gocloak server and from nowhere else. Here it echoes one line.
	backend := exampleStartBackend()
	defer backend.Close()

	// The operator's side: keys, peers.yaml, server.yaml, and a running
	// server. See exampleStartServer below for the config files, which are
	// the ones in the README quickstart.
	dep := exampleStartServer(ctx, backend.Addr().String())
	defer dep.stop()

	// The application's side. A Client is one WireGuard device pinned to
	// one server public key. It holds no backend address: "primary-db"
	// resolves server-side, against the allow map for this peer.
	client, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     dep.endpoint,
		ServerPubKey: dep.serverPubKey,
		PrivateKey:   dep.peerKeyRef,
		PresharedKey: dep.peerPSKRef,
		TunnelIP:     netip.MustParseAddr("10.99.0.7"),
		DialTimeout:  exampleBudget,
	})
	if err != nil {
		fmt.Println("NewClient:", err)
		return
	}
	defer client.Close()

	// Dial blocks until the WireGuard handshake completes, so an
	// authentication failure surfaces here as ErrHandshakeTimeout rather
	// than as a connection that hangs later.
	conn, err := client.Dial(ctx, "primary-db")
	if err != nil {
		fmt.Println("Dial:", err)
		return
	}
	defer conn.Close()

	// From here it is an ordinary net.Conn.
	if err := conn.SetDeadline(time.Now().Add(exampleBudget)); err != nil {
		fmt.Println("SetDeadline:", err)
		return
	}
	if _, err := io.WriteString(conn, "hello from the tunnel\n"); err != nil {
		fmt.Println("write:", err)
		return
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Print(line)

	// Output:
	// hello from the tunnel
}

// ---------------------------------------------------------------------------
// deployment scaffolding
//
// Everything below stands in for work an operator does once, off the
// critical path of an application: `gocloak keygen`, two YAML files, and
// `gocloak serve --config server.yaml`. It panics on failure because a
// broken fixture is not a result this example should paper over.
// ---------------------------------------------------------------------------

// exampleStartBackend starts a one-line echo service on localhost, standing
// in for the real backend inside the VPC.
func exampleStartBackend() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				io.WriteString(c, line)
			}()
		}
	}()
	return ln
}

// exampleDeployment is a running gocloak server plus everything a client
// needs to reach it.
type exampleDeployment struct {
	endpoint     string
	serverPubKey string
	peerKeyRef   gocloak.SecretRef
	peerPSKRef   gocloak.SecretRef
	stop         func()
}

// exampleStartServer writes the server.yaml and peers.yaml from the README
// quickstart into a temporary directory, loads them through the same public
// entry points `gocloak serve` uses, and runs the server until ctx is done.
func exampleStartServer(ctx context.Context, backendAddr string) *exampleDeployment {
	dir, err := os.MkdirTemp("", "gocloak-example")
	if err != nil {
		panic(err)
	}

	// What `gocloak keygen --name server` and `gocloak keygen --name
	// app-01` mint on the command line. keygen writes the private key and
	// the PSK at 0600 and prints only the public key and the PSK.
	serverPriv, serverPub := exampleKeypair()
	peerPriv, peerPub := exampleKeypair()
	psk := exampleRandomKey()

	// gocloak never accepts a literal key, only a reference to one. In
	// production these are aws:sm: references; file: is the offline form
	// and refuses to read anything looser than 0600.
	serverKeyRef := exampleWriteSecret(filepath.Join(dir, "server.key"), serverPriv)
	peerKeyRef := exampleWriteSecret(filepath.Join(dir, "app-01.key"), peerPriv)
	pskRef := exampleWriteSecret(filepath.Join(dir, "app-01.psk"), psk)

	port := exampleFreeUDPPort()
	peersPath := filepath.Join(dir, "peers.yaml")
	serverPath := filepath.Join(dir, "server.yaml")

	// peers.yaml. Everything under allow is an explicit grant: there is no
	// wildcard, no CIDR and no port range, and absence is denial.
	exampleWriteFile(peersPath, fmt.Sprintf(`peers:
  - name: app-01
    public_key: %s
    psk: %s
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: %s
`, peerPub, pskRef, backendAddr))

	exampleWriteFile(serverPath, fmt.Sprintf(`listen_port: %d
private_key: %s
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: %s
log_format: json
`, port, serverKeyRef, peersPath))

	fc, err := gocloak.LoadServerConfig(serverPath)
	if err != nil {
		panic(err)
	}
	srv, err := gocloak.NewServer(gocloak.ServerConfigFrom(fc))
	if err != nil {
		panic(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Run(runCtx); err != nil {
			fmt.Println("Run:", err)
		}
	}()

	return &exampleDeployment{
		endpoint:     fmt.Sprintf("127.0.0.1:%d", port),
		serverPubKey: serverPub,
		peerKeyRef:   peerKeyRef,
		peerPSKRef:   pskRef,
		stop: func() {
			cancel()
			<-done
			os.RemoveAll(dir)
		},
	}
}

// exampleKeypair generates a clamped Curve25519 private key and its public
// key, both base64, which is the form keygen writes and peers.yaml carries.
func exampleKeypair() (privB64, pubB64 string) {
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		panic(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// exampleRandomKey generates a 32-byte pre-shared key, base64 encoded.
func exampleRandomKey() string {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(psk)
}

// exampleWriteSecret writes key material at 0600 and returns the file:
// reference that names it.
func exampleWriteSecret(path, value string) gocloak.SecretRef {
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		panic(err)
	}
	return gocloak.SecretRef("file:" + path)
}

func exampleWriteFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		panic(err)
	}
}

// exampleFreeUDPPort picks a UDP port that is free right now, so the example
// does not collide with anything else on the machine.
func exampleFreeUDPPort() int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
