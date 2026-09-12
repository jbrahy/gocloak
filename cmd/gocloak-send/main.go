// Command gocloak-send is a real goCloak client: it dials a named service
// through a tunnel and sends one message to whatever is listening on the
// other side, such as gocloak-sink.
//
// Every secret-shaped flag takes a SecretRef, never a literal value: --key
// and --psk name where the private key and preshared key live (for
// example file:./app-01.key), and this command never reads or prints
// their contents. There is deliberately no client.yaml; the flags below
// are the whole list of what a client must hold.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	gocloak "github.com/jbrahy/gocloak"
	"github.com/jbrahy/gocloak/internal/msg"
)

// Exit codes. 0 and the usage code 2 match cmd/gocloak's own convention.
// Everything from 10 up is a distinct network-visible failure class, so a
// script driving this command can tell them apart without parsing stderr.
const (
	exitOK                 = 0
	exitError              = 1
	exitUsage              = 2
	exitDenied             = 10
	exitBackendUnavailable = 11
	exitRateLimited        = 12
	exitHandshakeTimeout   = 13
	exitInvalidServiceName = 14
)

// wgKeyLen is the length in bytes of a Curve25519 key, matching the
// library's own check in config.go's validPublicKey.
const wgKeyLen = 32

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses and validates flags, then, only if that succeeds, dials and
// sends. It takes stdout and stderr explicitly so tests can capture output
// without touching the real process streams.
func run(args []string, stdout, stderr io.Writer) int {
	cfg, code := parseArgs(args, stderr)
	if cfg == nil {
		return code
	}
	return sendMessage(cfg, stdout, stderr)
}

// sendConfig is gocloak-send's validated configuration: everything flag
// parsing and pre-flight checks can establish without touching the
// network.
type sendConfig struct {
	endpoint  string
	serverKey string
	keyRef    gocloak.SecretRef
	pskRef    gocloak.SecretRef
	tunnelIP  netip.Addr
	service   string
	timeout   time.Duration
	message   string
}

func usage(fs *flag.FlagSet, stderr io.Writer) func() {
	return func() {
		fmt.Fprintln(stderr, "usage: gocloak-send [flags] <message>")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "exit codes:")
		fmt.Fprintln(stderr, "  0   sent, ack received")
		fmt.Fprintln(stderr, "  1   an error other than the ones below")
		fmt.Fprintln(stderr, "  2   usage error: a required flag is missing, empty, or malformed")
		fmt.Fprintln(stderr, "  10  denied: the service is not in this peer's allow map")
		fmt.Fprintln(stderr, "  11  backend unavailable: granted, but the server could not reach it")
		fmt.Fprintln(stderr, "  12  rate limited: this peer exceeded its configured dial limits")
		fmt.Fprintln(stderr, "  13  handshake timeout: see the printed message for what that can mean")
		fmt.Fprintln(stderr, "  14  invalid service name: rejected locally, no packet was sent")
	}
}

// parseArgs parses flags, checks that every required flag is present and
// non-empty, and validates --server-key's format, all before any network
// activity. It returns (nil, code) on any failure, where code is the
// process exit code to use; the caller must not proceed in that case.
func parseArgs(args []string, stderr io.Writer) (*sendConfig, int) {
	fs := flag.NewFlagSet("gocloak-send", flag.ContinueOnError)
	fs.SetOutput(stderr)

	endpoint := fs.String("endpoint", "", "host:port of the tunnel server, UDP")
	serverKey := fs.String("server-key", "", "base64 server public key, pinned")
	key := fs.String("key", "", "SecretRef for this peer's private key, for example file:./app-01.key")
	psk := fs.String("psk", "", "SecretRef for this peer's preshared key")
	tunnelIPFlag := fs.String("tunnel-ip", "", "this peer's address inside the tunnel, for example 10.99.0.7")
	service := fs.String("service", "", "the service name to dial")
	timeout := fs.Duration("timeout", gocloak.DefaultDialTimeout, "dial timeout")
	fs.Usage = usage(fs, stderr)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK
		}
		return nil, exitUsage
	}

	var missing []string
	if *endpoint == "" {
		missing = append(missing, "--endpoint")
	}
	if *serverKey == "" {
		missing = append(missing, "--server-key")
	}
	if *key == "" {
		missing = append(missing, "--key")
	}
	if *psk == "" {
		missing = append(missing, "--psk")
	}
	if *tunnelIPFlag == "" {
		missing = append(missing, "--tunnel-ip")
	}
	if *service == "" {
		missing = append(missing, "--service")
	}
	if fs.NArg() < 1 {
		missing = append(missing, "message (positional argument)")
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "gocloak-send: missing required: %s\n", strings.Join(missing, ", "))
		return nil, exitUsage
	}

	// --server-key is checked here, not left to NewClient, so a malformed
	// key is rejected in the same pre-flight pass as the missing-flag
	// checks above rather than surfacing however NewClient happens to
	// report it.
	keyBytes, err := base64.StdEncoding.DecodeString(*serverKey)
	if err != nil {
		fmt.Fprintln(stderr, "gocloak-send: --server-key is not valid base64")
		return nil, exitUsage
	}
	if len(keyBytes) != wgKeyLen {
		fmt.Fprintf(stderr, "gocloak-send: --server-key decodes to %d bytes, want %d\n", len(keyBytes), wgKeyLen)
		return nil, exitUsage
	}

	tunnelIP, err := netip.ParseAddr(*tunnelIPFlag)
	if err != nil {
		fmt.Fprintf(stderr, "gocloak-send: --tunnel-ip is not a valid address: %v\n", err)
		return nil, exitUsage
	}

	return &sendConfig{
		endpoint:  *endpoint,
		serverKey: *serverKey,
		keyRef:    gocloak.SecretRef(*key),
		pskRef:    gocloak.SecretRef(*psk),
		tunnelIP:  tunnelIP,
		service:   *service,
		timeout:   *timeout,
		message:   fs.Arg(0),
	}, exitOK
}

// sendMessage dials the tunnel, sends cfg.message to cfg.service, and
// prints the ack. This is the one function in this command that touches
// the network.
func sendMessage(cfg *sendConfig, stdout, stderr io.Writer) int {
	client, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     cfg.endpoint,
		ServerPubKey: cfg.serverKey,
		PrivateKey:   cfg.keyRef,
		PresharedKey: cfg.pskRef,
		TunnelIP:     cfg.tunnelIP,
		DialTimeout:  cfg.timeout,
	})
	if err != nil {
		return reportError(stderr, err)
	}
	defer client.Close()

	// The context budget is the dial timeout plus headroom for the
	// message round trip after the tunnel is up; DialTimeout is what
	// actually bounds the handshake, per spec section 5.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout+5*time.Second)
	defer cancel()

	conn, err := client.Dial(ctx, cfg.service)
	if err != nil {
		return reportError(stderr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(cfg.timeout)); err != nil {
		fmt.Fprintf(stderr, "gocloak-send: %v\n", err)
		return exitError
	}

	_, elapsed, err := msg.Send(conn, cfg.message)
	if err != nil {
		fmt.Fprintf(stderr, "gocloak-send: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, "sent %d bytes, ack in %dms\n", len(cfg.message), elapsed.Milliseconds())
	return exitOK
}

// reportError maps a Dial or NewClient error to its distinct sentinel, per
// spec section 8, printing a short explanation and returning that
// failure's exit code. It never has access to the private key or the PSK,
// so there is nothing here that could leak them regardless of what the
// underlying error wraps.
func reportError(stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, gocloak.ErrHandshakeTimeout):
		// Spec section 8.1 deliberately makes this case
		// indistinguishable from several others, and the library's
		// own message already names every possibility, so it is
		// printed in full rather than replaced with a shorter one.
		fmt.Fprintf(stderr, "gocloak-send: %v\n", err)
		return exitHandshakeTimeout
	case errors.Is(err, gocloak.ErrDenied):
		fmt.Fprintln(stderr, "gocloak-send: denied: this peer's allow map does not grant this service")
		return exitDenied
	case errors.Is(err, gocloak.ErrBackendUnavailable):
		fmt.Fprintln(stderr, "gocloak-send: backend unavailable: the service is granted, but the server could not reach it")
		return exitBackendUnavailable
	case errors.Is(err, gocloak.ErrRateLimited):
		fmt.Fprintln(stderr, "gocloak-send: rate limited: this peer exceeded its configured dial limits")
		return exitRateLimited
	case errors.Is(err, gocloak.ErrInvalidServiceName):
		fmt.Fprintf(stderr, "gocloak-send: invalid service name: %v\n", err)
		return exitInvalidServiceName
	default:
		fmt.Fprintf(stderr, "gocloak-send: %v\n", err)
		return exitError
	}
}
