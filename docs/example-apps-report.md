# Example apps: gocloak-sink and gocloak-send

Status: complete. Branch `feat/example-apps`, one commit (see repository log
for the SHA; this doc is part of that same commit).

## What was built

### Piece 1: `internal/msg`

Shared, unit-testable message logic used by both binaries, so neither has to
be spawned as a process to test it.

- `MaxMessageLen = 64 * 1024`: named bound on a single message, excluding
  the trailing newline.
- `ErrMessageTooLarge`: returned when a message crosses that bound before a
  newline appears.
- `Handler`: `func(addr string, message []byte)`, invoked once per message.
- `Serve(ctx, ln, handler, logger) error`: accepts connections on a
  `net.Listener` until `ctx` is done, handling each concurrently.
- `ServeConn(conn, handler, logger)`: the per-connection loop `Serve` runs
  in its own goroutine; exported so tests can drive it directly over
  `net.Pipe` without a listener.
- `Send(conn, message) (ack string, elapsed time.Duration, err error)`:
  writes `message + "\n"`, reads back the ack line.

`readMessage` (unexported) reads byte by byte off a `bufio.Reader`, capping
the accumulated buffer at `MaxMessageLen`, so a peer that streams an
unterminated message cannot make it allocate without bound. It distinguishes
a clean close between messages (`io.EOF`), a close or read error mid-message
(`errIncompleteMessage`, logged at Info and not surfaced as a crash), and an
oversized message (`ErrMessageTooLarge`, logged at Warn). Message content is
handed to `handler` exactly once and never also logged, so the sink's print
is the only place it appears.

### Piece 2: `cmd/gocloak-sink`

A plain TCP service. Its package doc comment and `--help` both state
explicitly that it is **not** a goCloak peer and speaks no tunnel protocol,
which is the one thing this example is built to teach. Flag: `--listen`
(default `127.0.0.1:19000`). Prints each message with an RFC3339 timestamp
and the source address, then acks via `internal/msg`. Exits 1 on a bind
failure, 0 on a clean shutdown (SIGINT/SIGTERM).

### Piece 3: `cmd/gocloak-send`

A real goCloak client. Flags: `--endpoint`, `--server-key`, `--key`, `--psk`,
`--tunnel-ip`, `--service`, `--timeout` (default
`gocloak.DefaultDialTimeout`), plus a positional message argument.

- `parseArgs` validates every required flag is present and non-empty, and
  validates `--server-key`'s base64 encoding and 32-byte length, entirely
  before any network call. It is a pure function of `(args, stderr)` that
  returns `(*sendConfig, exitCode)`, which is what makes it testable without
  a server.
- `sendMessage` is the only function that touches the network: it builds a
  `gocloak.Client`, calls `Dial`, then `msg.Send`.
- `reportError` maps `errors.Is` against `ErrDenied`, `ErrBackendUnavailable`,
  `ErrRateLimited`, `ErrHandshakeTimeout`, `ErrInvalidServiceName` to a short
  explanation and a distinct exit code (10-14 respectively); anything else
  is exit 1. `ErrHandshakeTimeout`'s full library message is printed
  verbatim, per spec 8.1.
- The private key and PSK are never read into this process; only their
  `SecretRef` strings are held, and those are never printed, including on
  every error path (checked by hand and by
  `TestHelpNeverPrintsKeyOrPSKFlagValues`).

## Tests (all real, all fail on a real break)

- `internal/msg/msg_test.go`: round trip over `net.Pipe`, concurrent senders
  to one `Serve`d listener, a sender that disconnects mid-message, a message
  with no trailing newline, a message at exactly `MaxMessageLen` accepted, a
  message over the limit rejected, an unbounded-input reader proving
  `readMessage` stops growing at the limit, and `Send` rejecting an
  oversized message before writing.
- `cmd/gocloak-send/main_test.go`: each of the six required flags missing
  (in turn) exits 2 and names that flag; the positional message missing
  does the same; `--server-key` malformed (bad base64, and valid base64
  that is not 32 bytes) both exit 2 before any network activity; an invalid
  `--tunnel-ip` exits 2.
- `examples_test.go` (`TestExampleAppsEndToEnd`, package `gocloak_test`):
  reuses `example_test.go`'s own `exampleStartServer` harness, pointed at an
  `internal/msg`-served loopback listener instead of a bare echo backend,
  with a real `gocloak.NewClient` and `msg.Send` completing the round trip.
  Bounded by `exampleBudget` (60s). This is the test that fails if
  `gocloak-sink`/`gocloak-send` ever drift from the README quickstart.

## README

Added step 6, "Try it with the example apps," between the existing "Run the
server" and the hand-written Go snippet (renumbered to step 7, "Dial from
your own application"). Kept the Go snippet: it is the one place the README
shows the public API used directly, which the two binaries do not replace.
Updated `peers.yaml`'s `primary-db` grant from the illustrative
`192.0.2.10:3306` to `127.0.0.1:19000` (`gocloak-sink`'s default), with a
note that a real deployment would point it at the actual database, so the
quickstart is literally runnable end to end. Every flag and YAML key shown
was checked against `--help` output and the source, not written from
memory. Added `make build` to the Development section's target list.

## Verification, real output

```
$ go build ./...
(no output)

$ go vet ./...
(no output)

$ staticcheck ./...
(no output)

$ gofmt -l .
(no output, i.e. empty)

$ go test -count=1 -race ./...
ok  	github.com/jbrahy/gocloak	205.481s
ok  	github.com/jbrahy/gocloak/cmd/gocloak	1.845s
ok  	github.com/jbrahy/gocloak/cmd/gocloak-send	2.014s
?   	github.com/jbrahy/gocloak/cmd/gocloak-sink	[no test files]
ok  	github.com/jbrahy/gocloak/internal/msg	2.263s
```

## Real demo transcript

Run end to end exactly as the README's own step 6 instructions say, keys
minted into a scratch temp directory and deleted afterward.

```
$ gocloak keygen --name server --dir "$DEMO"
peer: server
public_key: E8vwqazY4tBKwTCemvAXSNPYiemQev7HD9Ahyt+/s30=
psk: BvXzePo+44BhjID+V5+J1iNSlbjFKD/+nkXvE/vyVsw=
private key written to: .../server.key
psk written to: .../server.psk

$ gocloak keygen --name app-01 --dir "$DEMO"
peer: app-01
public_key: 5U6ZwApOsTecvJ3FR+HGJiF34gZSxUC1fPRlDTDH7mo=
psk: 4AlZRzP0dPDXCKP6+tFFQ1ZY9nbsc3ZWLll7860hc5A=
private key written to: .../app-01.key
psk written to: .../app-01.psk

# server.yaml: listen_port 58120 (picked free for this run; README uses
# 51820), private_key file:.../server.key, tunnel_ip 10.99.0.1, mtu 1280,
# peers_file .../peers.yaml, log_format text
# peers.yaml: app-01, public_key above, psk file:.../app-01.psk,
# tunnel_ip 10.99.0.7, allow primary-db -> 127.0.0.1:19000

$ gocloak-sink --listen 127.0.0.1:19000
gocloak-sink: listening on 127.0.0.1:19000 (plain TCP, not a goCloak peer)

$ gocloak serve --config "$DEMO/server.yaml"
level=INFO msg="gocloak: starting" config=.../server.yaml
level=ERROR msg="gocloak: wireguard" message="peer(5U6Z...H7mo) - Failed to send handshake initiation: no known endpoint for peer"
level=INFO msg="gocloak: server listening" listen_port=58120 tunnel_ip=10.99.0.1 mtu=1280 peers_file=.../peers.yaml peers=1

$ gocloak-send --endpoint 127.0.0.1:58120 --server-key E8vwqazY4tBKwTCemvAXSNPYiemQev7HD9Ahyt+/s30= \
    --key file:.../app-01.key --psk file:.../app-01.psk --tunnel-ip 10.99.0.7 \
    --service primary-db "hello from the tunnel"
sent 21 bytes, ack in 0ms
exit=0

# gocloak-sink's terminal:
2026-09-11T23:02:52-07:00 127.0.0.1:51700: hello from the tunnel

$ gocloak-send --endpoint 127.0.0.1:58120 --server-key E8vwqazY4tBKwTCemvAXSNPYiemQev7HD9Ahyt+/s30= \
    --key file:.../app-01.key --psk file:.../app-01.psk --tunnel-ip 10.99.0.7 \
    --service not-granted "this should be denied"
gocloak-send: denied: this peer's allow map does not grant this service
exit=10

# stopped the server and sink, then:
$ rm -rf "$DEMO"
```

The `Failed to send handshake initiation: no known endpoint for peer` line
is the pre-existing, separately tracked idle-peer logging defect named in
the task brief. It was left alone, not worked around.

## What could not be done / notes

- Nothing in the requested scope was skipped. `package gocloak` was not
  touched; no new identifier was exported from it; no dependency was added
  (`go.mod`/`go.sum` diff is empty); no existing test was weakened, skipped,
  or deleted; no `client.yaml` was added.
- `cmd/gocloak-sink` has no dedicated test file: its logic is entirely
  `internal/msg`, which is unit-tested, and the task's test list did not
  call for sink-specific tests beyond that.
