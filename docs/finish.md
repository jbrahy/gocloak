# Goal: Build goCloak to completion, maximum security, no review gates

## Objective

Implement the library specified in
`docs/superpowers/specs/2026-09-09-gocloak-design.md` to a finished,
tested, committed state. Read that spec first. It is the contract. This
document is how to execute it, not what to build.

Done means: every task below is complete, every verification command passes with
the output shown, and each task is committed.

## Execution rules

1. **Do not stop for review.** No approval gates, no "does this look right",
   no progress check-ins between tasks. Execute the task list in order to the
   end. Report once at the end.
2. **Use subagent-driven development** (`superpowers:subagent-driven-development`).
   Fresh subagent per task, review gate handled between subagents, not by the
   human.
3. **TDD, always** (`superpowers:test-driven-development`). Write the failing
   test, watch it fail, make it pass. This matters more than usual here: the
   security tests in task 10 are the only proof the threat model is real.
4. **Commit after each task** with a descriptive message. Never batch two tasks
   into one commit.
5. **Verify before claiming.** Run the verification command, read its output,
   and only then mark a task done. A task is not done because the code looks
   right.

## The tie-breaker for every ambiguous decision

**Choose the option that fails closed.** When the spec does not settle a
question and two implementations are defensible, pick the one where a bug,
a typo, or a partial failure results in denied access rather than granted
access, and in a crash rather than a silent degradation.

Concretely, in descending priority:

1. Deny by default. An unlisted peer, an unlisted service, an unparsed config,
   a resolver that returned nothing: all deny.
2. Never add a network-facing surface that the spec did not ask for. No health
   endpoint on the public interface, no debug listener, no pprof, no metrics
   port that answers unauthenticated requests.
3. Never widen an error message that an unauthenticated party can observe. The
   endpoint's silence to strangers is a designed property, not an oversight.
4. Never log secret material. Private keys, PSKs, and payload bytes never reach
   a log line at any level, including debug. Log peer name, service name,
   status, and byte counts.
5. Prefer deleting code over adding a flag. Every configuration knob is a way
   to be deployed insecurely.
6. Do not add a dependency that is not in the spec's pinned table. If one seems
   necessary, write the 30 lines instead.

## Task list

Each task lists its verification. Run it, read it, then commit.

### 1. Bootstrap

`go mod init github.com/jbrahy/gocloak`. Pin the dependency versions from the
spec's table. Add `.gitignore` covering `credentials.md`, `*.key`, `*.cnf`.
Add a `Makefile` with `test`, `lint`, `fuzz`, `vuln` targets.

Verify: `go build ./... && go vet ./...` exits 0.

### 2. `secret.go`

`SecretRef` parsing and resolution for `aws:sm`, `aws:ssm`, `file`, `env`.
Resolved values live in memory only. `file:` refuses a target with permissions
looser than 0600.

Verify: `go test -run TestSecret ./...` passes, including a case that rejects an
unknown scheme and a case that rejects a 0644 file.

### 3. `wire.go`

The hello frame codec exactly as specified in spec section 4. Version byte,
length byte, name charset `^[a-z0-9][a-z0-9-]{0,62}$`, the status codes, and the
5 second read deadline.

Verify: `go test -run TestWire ./...` passes, then
`go test -fuzz=FuzzHelloFrame -fuzztime=60s ./...` finds no crash.

### 4. `policy.go`

The policy engine. `(peerTunnelIP, serviceName) -> backendAddr`. Default deny.
No wildcards, no CIDR, no port ranges.

Verify: `go test -run TestPolicy ./...` passes, with table cases for unknown
peer, unknown service, cross-peer access, and an empty allow map.

### 5. `config.go`

YAML types for `server.yaml` and `peers.yaml`, decoded with
`KnownFields(true)`. Full validation, then atomic swap. Hot reload via fsnotify.
A malformed file leaves the previous config in force and logs loudly.

Verify: `go test -run TestConfig ./...` passes, including a test that writes a
malformed peers file during a reload and asserts the old policy still resolves.

### 6. `device.go`

wireguard-go plus netstack bring-up shared by client and server. Build the
`IpcSet` string. Default MTU 1280. `persistent_keepalive_interval=25`.
Import `golang.zx2c4.com/wireguard/tun/netstack` from inside the main
`golang.zx2c4.com/wireguard` module, not the stale standalone one.

Verify: `go test -run TestDevice ./...` brings a client and server device up on
localhost UDP and passes bytes both ways.

### 7. `server.go`

Accept loop on the netstack listener at `10.99.0.1:443`. Peer identity from
`conn.RemoteAddr()`. Read the hello frame, resolve policy, dial the backend,
pipe. Per-peer concurrency and rate limits. Structured JSON logging. Live peer
add and remove through `IpcSet` with `update_only` and `remove`.

Verify: `go test -run TestServer -race ./...` passes.

### 8. `client.go`

`NewClient`, `Dial`, `DialContext`, `Close`. `Dial` blocks until the handshake
completes and returns `ErrHandshakeTimeout` with the full message from spec
section 8.1 on timeout. No transparent per-connection reconnect.

Verify: `go test -run TestClient -race ./...` passes, including a test asserting
the exact `ErrHandshakeTimeout` text.

### 9. `cmd/gocloak`

`keygen` mints a Curve25519 keypair and a 32-byte PSK, writing the private key
at 0600 and printing the public key and PSK to stdout. `serve` runs the server
from a config path.

Verify: `go run ./cmd/gocloak keygen --name test` produces a keypair that the
integration test in task 10 accepts.

### 10. Security test suite

The tests that prove the threat model. Each is a real test in
`security_test.go`.

1. Wrong client key: the handshake never completes, and a capture on the
   server's UDP socket shows zero bytes sent back.
2. Correct key, wrong PSK: same, zero bytes back.
3. Revoke a connected peer via hot reload, then assert the next `Dial` fails.
4. Peer A dialing peer B's service is denied with status `0x01`.
5. A captured handshake initiation, replayed, is rejected.

Verify: `go test -run TestSecurity -race -v ./...` passes with all five named
in the output.

### 11. Hardening pass

Verify, all four clean:

```
go vet ./...
staticcheck ./...
govulncheck ./...
go test -race ./...
```

Fix anything they find. If `govulncheck` reports a vulnerability in a pinned
dependency, upgrade it and rerun the full suite.

### 12. README and example

`README.md` with the architecture diagram, a five minute quickstart, the
security properties table from spec section 7.1, and the "does not hold" list
from 7.2 stated just as plainly. An `example_test.go` that runs a real loopback
tunnel.

Verify: `go test -run Example ./...` passes.

## Definition of done

```
go build ./...                                  exit 0
go vet ./...                                    exit 0
staticcheck ./...                               exit 0
govulncheck ./...                               no findings
go test -race ./...                             all pass
go test -fuzz=FuzzHelloFrame -fuzztime=60s ./... no crash
git log --oneline                               one commit per task, 12 total
```

Report at the end with that block filled in with real output. Do not report
completion on any line you did not actually run.

## Stop only for these

Everything else is yours to decide with the fail-closed rule. Stop and ask only
if:

1. Completing a task would require weakening a property in spec section 7.1.
2. `govulncheck` reports an unpatched vulnerability in wireguard-go or gVisor
   with no fixed version available.
3. The pinned wireguard-go version turns out not to support live peer removal
   or `preshared_key`, contradicting the spec's verified claim.

None of these are expected.
