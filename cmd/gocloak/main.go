// Command gocloak provides the keygen and serve subcommands for the
// goCloak tunnel: keygen mints a peer's Curve25519 keypair and a
// pre-shared key, serve runs the server described by a server.yaml.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	gocloak "github.com/jbrahy/gocloak"
	"golang.org/x/crypto/curve25519"
)

// pskLen is the length in bytes of a pre-shared key, per spec section 5's
// PresharedKey field and the 32-byte PSK the server resolves at startup.
const pskLen = 32

// keyLen is the length in bytes of a Curve25519 private or public key.
const keyLen = 32

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches to a subcommand and returns the process exit code. It
// takes stdout and stderr explicitly so tests can capture output without
// touching the real process streams.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stderr)
	case "-h", "-help", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gocloak: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: gocloak <command> [flags]")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  keygen --name <peer-name> [--dir <dir>]   mint a peer keypair and PSK")
	fmt.Fprintln(w, "  serve --config <path>                     run the server")
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

// runKeygen implements the keygen subcommand. It generates a Curve25519
// keypair and a 32-byte pre-shared key, writes the private key and the PSK
// to disk at 0600, refusing to overwrite an existing file, and prints only
// the public key and the PSK to stdout for the operator to paste into
// peers.yaml. The private key is never printed; only its file path is.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "peer name")
	dir := fs.String("dir", "", "directory to write key files (default: current directory)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *name == "" {
		fmt.Fprintln(stderr, "gocloak: keygen: --name is required")
		return 2
	}
	// The name becomes part of a file path below and, per spec section
	// 6, the peers.yaml entry the operator pastes it into. Restricting it
	// to the same charset config.go enforces for a peer name means a
	// generated key can never contain a path separator (no traversal out
	// of --dir) and never produces a name that peers.yaml would later
	// reject.
	if !gocloak.ValidServiceName(*name) {
		fmt.Fprintln(stderr, "gocloak: keygen: --name must match [a-z0-9][a-z0-9-]{0,62}")
		return 2
	}

	targetDir := *dir
	if targetDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gocloak: keygen: %v\n", err)
			return 1
		}
		targetDir = wd
	}

	priv, pub, err := generateKeypair()
	if err != nil {
		fmt.Fprintf(stderr, "gocloak: keygen: %v\n", err)
		return 1
	}
	psk, err := generatePSK()
	if err != nil {
		fmt.Fprintf(stderr, "gocloak: keygen: %v\n", err)
		return 1
	}

	keyPath := filepath.Join(targetDir, *name+".key")
	pskPath := filepath.Join(targetDir, *name+".psk")

	if err := writeSecretFile(keyPath, base64.StdEncoding.EncodeToString(priv)); err != nil {
		fmt.Fprintf(stderr, "gocloak: keygen: %v\n", err)
		return 1
	}
	if err := writeSecretFile(pskPath, base64.StdEncoding.EncodeToString(psk)); err != nil {
		// The private key file was already written successfully. Leaving
		// it behind here would orphan a key with no matching PSK on disk
		// and would also mean a retry of this exact command fails on the
		// O_EXCL guard instead of succeeding, so it is removed on this
		// path. Best effort: if the removal itself fails, the write
		// error below is still reported and is what matters to the
		// operator.
		_ = os.Remove(keyPath)
		fmt.Fprintf(stderr, "gocloak: keygen: %v\n", err)
		return 1
	}

	// This is the one deliberate exception to "never print secret
	// material": the operator must paste the PSK into a secret store, and
	// it goes to stdout only, never to a log. The private key is never
	// printed anywhere; only the path it was written to is.
	fmt.Fprintf(stdout, "peer: %s\n", *name)
	fmt.Fprintf(stdout, "public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintf(stdout, "psk: %s\n", base64.StdEncoding.EncodeToString(psk))
	fmt.Fprintf(stdout, "private key written to: %s\n", keyPath)
	fmt.Fprintf(stdout, "psk written to: %s\n", pskPath)
	return 0
}

// generateKeypair generates a Curve25519 private key with crypto/rand,
// clamps it per the X25519 contract, and derives the matching public key.
func generateKeypair() (priv, pub []byte, err error) {
	priv = make([]byte, keyLen)
	// io.ReadFull, not rand.Read: a short read here would silently
	// produce a low-entropy key, the worst possible failure of this
	// command, so the byte count is checked explicitly.
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}
	clampPrivateKey(priv)

	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive public key: %w", err)
	}
	return priv, pub, nil
}

// clampPrivateKey applies the X25519 clamping contract in place: clear the
// low 3 bits of byte 0, clear the high bit of byte 31, set the
// second-highest bit of byte 31.
func clampPrivateKey(priv []byte) {
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
}

// generatePSK generates a 32-byte pre-shared key with crypto/rand, checking
// the byte count read for the same reason generateKeypair does.
func generatePSK() ([]byte, error) {
	psk := make([]byte, pskLen)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return nil, fmt.Errorf("generate psk: %w", err)
	}
	return psk, nil
}

// writeSecretFile writes content to path at mode 0600, refusing to
// overwrite an existing file. Clobbering a peer's existing private key or
// PSK would be a self-inflicted outage, so O_EXCL makes that impossible
// rather than merely unlikely.
//
// The write is synced and Close's error is checked explicitly, and on any
// write, sync, or close failure the partial file is removed before
// returning. Without that, a failed close could leave a zero-length file
// on disk that the O_EXCL guard above would then permanently refuse to
// regenerate: this is the one file whose loss has no recovery path short
// of an operator manually deleting it, so a retry must be able to succeed.
func writeSecretFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, refusing to overwrite", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}

	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

// runServe implements the serve subcommand. It loads server.yaml, builds
// the daemon's own logger from log_format, constructs the server, and runs
// it until SIGINT or SIGTERM. Per spec section 8.2 the server must fail
// closed: any startup error is logged and the process exits non-zero,
// never starting degraded and never retrying into a started state.
func runServe(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to server.yaml")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "gocloak: serve: --config is required")
		return 2
	}

	// Before the config is loaded, log_format is not yet known, so a
	// load failure is reported through a default JSON logger, matching
	// the format the library itself defaults to when no daemon has set
	// one.
	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	fc, err := gocloak.LoadServerConfig(*configPath)
	if err != nil {
		logger.Error("gocloak: serve: could not load config", "error", err.Error())
		return 1
	}

	// Carried requirement from the task 7 review: ServerConfigFrom drops
	// log_format because spec section 5's ServerConfig has no such field.
	// log_format is not inert, though: it configures the handler used for
	// the whole process's output, so the key still does something rather
	// than being silently ignored, per spec section 6's "fail loudly,
	// never silently ignore".
	//
	// slog.SetDefault makes this the process-wide default handler, which
	// NewServer picks up below via slog.Default() (see server.go). That
	// is what makes log_format govern the whole process rather than just
	// this command's own lines: the daemon's own output and the
	// library's connection logs then share one handler writing to one
	// stream, instead of two differently-formatted writers interleaved on
	// the same file descriptor.
	handler, err := newLogHandler(fc.LogFormat, stderr)
	if err != nil {
		logger.Error("gocloak: serve: could not build log handler", "error", err.Error())
		return 1
	}
	logger = slog.New(handler)
	slog.SetDefault(logger)

	cfg := gocloak.ServerConfigFrom(fc)
	srv, err := gocloak.NewServer(cfg)
	if err != nil {
		logger.Error("gocloak: serve: could not construct server", "error", err.Error())
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("gocloak: starting", "config", *configPath)
	if err := srv.Run(ctx); err != nil {
		logger.Error("gocloak: serve: server run failed", "error", err.Error())
		return 1
	}
	logger.Info("gocloak: stopped")
	return 0
}

// newLogHandler builds the slog.Handler for the daemon's own output from
// log_format. LoadServerConfig already restricts log_format to "json" or
// "text" and defaults an empty value to "json", so the default case below
// is unreachable in practice; it still fails closed rather than silently
// picking a handler for a value nothing upstream validated.
func newLogHandler(format string, w io.Writer) (slog.Handler, error) {
	switch format {
	case "json":
		return slog.NewJSONHandler(w, nil), nil
	case "text":
		return slog.NewTextHandler(w, nil), nil
	default:
		return nil, fmt.Errorf("log_format %q must be json or text", format)
	}
}
