// Command gocloak-sink is a plain TCP backend service for the goCloak
// example apps: it speaks no tunnel protocol and is NOT a goCloak peer. It
// is exactly the kind of ordinary service, like the database in the
// README's own examples, that a gocloak server proxies to over the tunnel.
//
// Point one of peers.yaml's `allow` entries at this process's --listen
// address, then reach it through the tunnel with gocloak-send and a
// service name; do not dial --listen directly from an application that is
// meant to demonstrate the tunnel.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jbrahy/gocloak/internal/msg"
)

// defaultListen is the sink's default bind address.
const defaultListen = "127.0.0.1:19000"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses flags, binds the listener, and serves until SIGINT or
// SIGTERM. It takes stdout and stderr explicitly so tests can capture
// output without touching the real process streams.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gocloak-sink", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", defaultListen, "address to listen on")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "gocloak-sink is a plain TCP backend service. It is NOT a goCloak")
		fmt.Fprintln(stderr, "peer and speaks no tunnel protocol: it is the kind of ordinary")
		fmt.Fprintln(stderr, "service, like the database in the README's own examples, that a")
		fmt.Fprintln(stderr, "gocloak server proxies to. Point a peers.yaml `allow` entry at its")
		fmt.Fprintln(stderr, "--listen address; do not dial --listen directly from gocloak-send.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "usage: gocloak-sink [--listen host:port]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "gocloak-sink: listen: %v\n", err)
		return 1
	}
	defer ln.Close()

	fmt.Fprintf(stdout, "gocloak-sink: listening on %s (plain TCP, not a goCloak peer)\n", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	handler := func(addr string, message []byte) {
		fmt.Fprintf(stdout, "%s %s: %s\n", time.Now().Format(time.RFC3339), addr, message)
	}

	if err := msg.Serve(ctx, ln, handler, logger); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "gocloak-sink: serve: %v\n", err)
		return 1
	}
	return 0
}
