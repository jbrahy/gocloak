# goCloak implementation guide

This is the contributor's map of the codebase: what each layer is for, what
each file owns, how one connection actually travels from a UDP packet to
backend bytes, and which invariants must not be broken.

If you want to use goCloak rather than change it, read
[integration-guide.md](integration-guide.md). The binding design document is
the [design spec](superpowers/specs/2026-09-09-gocloak-design.md); where this
guide and the spec disagree, the spec wins and this guide is wrong.

For how to build, test and submit a change, see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Contents

1. [The layers, and why each one exists](#1-the-layers-and-why-each-one-exists)
2. [File by file](#2-file-by-file)
3. [The path of one connection](#3-the-path-of-one-connection)
4. [Peer identity: the invariant everything rests on](#4-peer-identity-the-invariant-everything-rests-on)
5. [Hot reload and revocation](#5-hot-reload-and-revocation)
6. [Shutdown ordering](#6-shutdown-ordering)
7. [Testing strategy](#7-testing-strategy)
8. [Invariants: the checklist](#8-invariants-the-checklist)

## 1. The layers, and why each one exists

```
  application code
        |  net.Conn
  +-----------------------------+
  |  gocloak                    |   policy, hello frame, config, secrets
  +-----------------------------+
  |  gVisor netstack            |   userspace TCP/IP
  +-----------------------------+
  |  wireguard-go               |   Noise_IKpsk2, encryption, cryptokey routing
  +-----------------------------+
        |  UDP datagrams
   the host's real network
```

**wireguard-go provides Noise.** goCloak writes no cryptography. The handshake,
the ratchet, replay windows, cookies under load and cryptokey routing are all
wireguard-go's, unmodified. This is the single most important structural
decision in the project: the security-critical code goCloak actually owns is
the policy engine and the hello frame parser, both small enough to read in one
sitting, and everything else is a well-reviewed implementation of a
well-reviewed protocol.

**gVisor netstack provides TCP.** wireguard-go moves IP packets; it does not
speak TCP. Netstack is a userspace TCP/IP stack that takes those packets and
gives back something with `Dial` and `Listen`. It arrives transitively with
wireguard-go, which matters: the standalone `golang.zx2c4.com/wireguard/tun/netstack`
module is stale (last published 2022, drags in a 2021 gVisor). The current
package lives inside `golang.zx2c4.com/wireguard`. Import that one.

**Why userspace, rather than a TUN device.** A TUN device needs root or
`CAP_NET_ADMIN`, and it puts the tunnel in the host's routing table where every
other process on the box can use it. Userspace means no privileges, no
kernel-visible interface, no routing table entry, and a tunnel that exists only
inside the process that opened it. The cost is real: the whole TCP stack runs in
Go, so throughput is lower than a kernel WireGuard interface. For the workload
this is built for, a small fixed set of backend services, that is the right
trade.

**Why netstack does not forward.** The netstack instance holds exactly one
address and never calls `SetForwarding`, `SetSpoofing` or
`SetPromiscuousMode`, so a packet one peer addresses to another peer's tunnel
address is dropped rather than routed. There is no peer-to-peer path inside the
tunnel, by construction rather than by policy.

## 2. File by file

Every non-test file in `package gocloak`, what it owns, and what it must not
know about.

### `device.go`

Owns bringing up one userspace WireGuard device with netstack on top, and
translating goCloak's idea of a peer into wireguard-go's UAPI text. Shared by
the client and the server: `newTunnelDevice`, `AddPeer`, `UpdatePeer`,
`RemovePeer`, `Close`.

`keyToHex` is the chokepoint for every key that reaches the UAPI. It base64
decodes, requires exactly 32 bytes and hex encodes, and its errors never echo
the key. That matters because wireguard-go's own `IpcSetOperation` logs errors
that quote the offending value, which for a key line would be key bytes. That
path is closed here, not there.

Must not know: what a service is, what a policy is, what YAML looks like. It
takes addresses and keys and gives back a device.

### `wire.go`

Owns the hello frame: `writeHelloRequest`, `readHelloRequest`,
`writeHelloResponse`, `readHelloResponse`, the `status` codes, and
`ValidServiceName`, which is the single source of truth for the service name
charset `^[a-z0-9][a-z0-9-]{0,62}$`.

Every byte here arrives from an authenticated but possibly compromised peer, so
the parser validates the version and the declared length **before** it sizes any
allocation from them, treats a short read as an error rather than a partial
success, and never echoes attacker-supplied name bytes back into an error.

Must not know: anything about peers, policy, connections or deadlines. It takes
an `io.Reader` and an `io.Writer`. The caller owns deadlines; this file never
touches them.

### `policy.go`

Owns authorization, and nothing else. `newPolicy` builds an immutable
`policy` from a slice of `peerPolicy`; `Resolve(peerTunnelIP, serviceName)`
answers with a backend address and a bool.

A `policy` is immutable once built: no exported mutator, no exported map, and
no method that hands out a reference to an internal map a caller could write
through. That is what makes it safe to share across goroutines while the hot
reload swaps a new one in atomically.

Must not know: YAML, config files, the server, `net.Conn`. It is deliberately
independent of `config.go` so the security-critical unit is testable from a Go
literal with no fixture file.

### `config.go`

Owns YAML decoding, validation, the peer diff and the file watcher.
`LoadServerConfig`, `LoadPeersConfig`, `peerWatcher` and its `Run` loop.

Decoding is strict: `KnownFields(true)`, one document only, unknown key is a
hard error. Validation is total: a `PeersConfig` that exists has passed every
check, so there is never a half-built value in circulation. YAML error messages
are sanitized (`sanitizeYAMLMessage`) because yaml.v3 quotes document keys back
at you, and a document key under `allow:` or `psk:` can be attacker-shaped or
secret-shaped text.

Must not know: the WireGuard device, netstack, or how a connection is served.
It produces validated data and a diff; applying them is the server's job.

### `secret.go`

Owns `SecretRef` parsing and resolution to an in-memory `secret`. Two schemes
natively, `file:` and `env:`, neither needing a dependency outside the standard
library. Every other scheme is delegated to the caller's `SecretResolver`
(`ClientConfig.Resolver`, `ServerConfig.Resolver`), and is an error when there
is none; `aws:sm:` and `aws:ssm:` are that resolver, in the nested
`awssecrets` module. `file:` and `env:` are resolved before a `Resolver` is
consulted, so a `Resolver` can add schemes and can never take those two over. A
value that arrives from a `Resolver` is wrapped in `secret` on receipt, so it
inherits the same redaction guarantee as one resolved here. There is no
fallback to treating an unparsed string as a literal key. `secret.String`
and `secret.GoString` both return `[REDACTED]`, so a stray `%v`, `%s` or `%#v`
in a future log line cannot leak key material, and `secret.bytes()` is
deliberately unexported so the set of code that can hold a plaintext key is the
set of code in this repository.

Must not know: what the key is for.

### `server.go`

Owns everything server-side: `NewServer`, `Run`, the accept loop, `handleConn`,
the per-peer limiters, the reload application path and the shutdown drain.

This is the largest file and the one where ordering matters most. Sections 3, 5
and 6 below are all about this file.

Must not know: how to parse YAML (that is `config.go`) or how to frame a hello
(that is `wire.go`).

### `client.go`

Owns `NewClient`, `Dial`, `DialContext`, `Close`, and the seven `Err*`
sentinels. Also owns the one message the project is most careful about:
`handshakeTimeoutError`, which must be byte for byte identical whatever the
cause was.

Must not know: anything about backends. The client cannot express an address
and must never gain the ability to.

### `cmd/gocloak`

The operator CLI. `keygen` mints a Curve25519 keypair and a PSK, writes both at
0600 with `O_EXCL`, and prints the public key and the PSK. `serve` loads
`server.yaml`, builds the process-wide slog handler from `log_format`, and runs
the server until SIGINT or SIGTERM.

### `cmd/gocloak-sink`, `cmd/gocloak-send`, `internal/msg`

The example apps. `gocloak-sink` is a plain TCP service and deliberately not a
goCloak peer. `gocloak-send` is a real client that maps each `Err*` sentinel to
a distinct exit code. `internal/msg` is the newline-delimited message protocol
they share, which has nothing to do with the goCloak wire protocol and must not
be confused with it.

## 3. The path of one connection

Server side, from a UDP packet on the public interface to bytes reaching the
backend. Function names are given so you can follow along in the source.

1. **A UDP datagram arrives** on `listen_port`. wireguard-go's bind reads it.
   If it fails MAC1, which is keyed on the server's public key, it is dropped
   with no response and no log line. If it is a handshake initiation from a
   static key the server has never seen, the peer lookup fails and, again,
   nothing is sent back. This is the endpoint invisibility property, and none
   of it is goCloak's code.

2. **The session comes up.** wireguard-go decrypts transport packets and hands
   the inner IP packets to the netstack TUN created in `newTunnelDevice`
   (`device.go`). Cryptokey routing has already checked that the packet's
   source address is inside the `allowed_ip` configured for that peer's key,
   which is always a `/32`.

3. **Netstack terminates TCP.** The listener was opened in `Server.Run` with
   `dev.Net().ListenTCPAddrPort(10.99.0.1:443)`. `Accept` returns a `net.Conn`
   whose `RemoteAddr` is the peer's tunnel address. `Run` spins
   `go s.handleConn(runCtx, conn)` after `s.wg.Add(1)`.

4. **`handleConn` derives the peer identity** via `remoteTunnelIP(conn)`, which
   reads `conn.RemoteAddr()` and normalizes it with `Unmap()`. Nothing the peer
   sends contributes to this value. See section 4.

5. **Limits are applied**, before the hello frame is read.
   `s.limiterFor(peerIP)` returns the peer's `*peerLimiter` and whether that
   peer is in the list currently in force. No entry means the connection is
   closed in silence, with nothing written back. Then `limiter.acquire(now)`
   checks `max_concurrent` and the `dials_per_second` bucket; a refusal answers
   `statusRateLimited` and returns.

   The ordering is deliberate: the connection already costs a goroutine, a
   netstack connection and a file descriptor by the time it is accepted, and
   the hello read can sit on its deadline for five seconds. Checking after the
   read would let a peer that connects and says nothing hold unbounded
   connections in flight.

6. **The hello frame is read** under a 5 second deadline:
   `readHelloRequest(conn)` (`wire.go`). A malformed frame answers
   `statusMalformed`; an I/O error or a silent peer gets nothing back, because
   there is nothing to answer.

7. **Authorization.** `s.watcher.policy().Resolve(peerIP, service)`
   (`policy.go`). Not granted means `statusDenied`, a `service denied` warning
   carrying the peer and the requested name, and close. Note what the service
   name can and cannot do: it selects a key **within** that peer's own allow
   map, and can never reach another peer's map.

8. **The backend dial.** `(&net.Dialer{}).DialContext(dialCtx, "tcp",
   backend.String())` under a 10 second timeout. A failure answers
   `statusBackendUnavailable`. This is an ordinary TCP connection; the backend
   knows nothing about goCloak.

9. **Registration and the re-check.** The pair is wrapped in a `liveConn` and
   registered with `limiter.track(live)`. Then, and only then, `handleConn`
   re-reads `s.limiterFor(peerIP)` and compares pointers with the limiter it
   was admitted under. A mismatch means the peer was revoked or replaced during
   setup, and the connection is closed in silence rather than becoming a proxy.
   Everything between step 5 and here is a window of up to about 15 seconds,
   and this check is what closes it. The ordering (`track`, then check, then
   `defer untrack`) is load bearing in both directions.

10. **The response and the pipe.** `s.respond(conn, statusOK)` writes the two
    byte frame, `conn.SetDeadline(time.Time{})` clears deadlines because from
    here a long idle session is legitimate, and `pipeConns(ctx, conn,
    backendConn)` copies in both directions until either side ends. It returns
    byte counts for the log line.

11. **Close.** `pipeConns` closes both sides when the first copy finishes, and
    its watchdog goroutine closes both if the context is cancelled. The defers
    in `handleConn` then run: `untrack`, `backendConn.Close`,
    `limiter.release`, `conn.Close`, `s.wg.Done`. One `connection closed` log
    line carries peer, service, status, byte counts and duration. Never
    payload.

Client side, for the same connection:

`Dial` validates the name with `ValidServiceName` (a bad name never reaches
the network), builds one budget with `context.WithTimeout` for the whole call,
and calls `dialControl`, which retries an in-tunnel TCP dial to `10.99.0.1:443`
every 250ms until the WireGuard handshake completes. That retry loop is what
makes `Dial` block on the handshake. On expiry it returns
`handshakeTimeoutError(handshakeBound(budget, start))`. On success `hello`
writes the request, reads the status, maps it through `statusError`, and
`finishHello` clears the deadlines. `finishHello` checks the result of the
watchdog's `stop()`: false means `conn.Close` is already running in another
goroutine, so the connection must not be returned.

## 4. Peer identity: the invariant everything rests on

**The peer's identity is its tunnel IP, and nothing the client sends may
influence it.** If you break one thing in this codebase, break something else.

Why the tunnel IP is trustworthy: every peer is configured with
`allowed_ip=<addr>/32` (`devicePeer.ipcConfig` in `device.go`). WireGuard
cryptokey routing drops any inner packet whose source address is not inside
that peer's allowed IPs, and that check happens after decryption, which means
after the packet has been proven to come from the holder of that keypair.
So a packet sourced from `10.99.0.7` provably came from the keypair bound to
`10.99.0.7`. `conn.RemoteAddr()` on the server is therefore a
cryptographically enforced fact, not a claim.

Three details that keep it that way:

- **The `/32` is not negotiable.** `ipcConfig` writes `allowed_ip=%s/32` with a
  single `netip.Addr`, never a prefix, and `devicePeer.AllowedIP` is an `Addr`
  rather than a `Prefix` so a wider grant cannot be expressed. A peer that owned
  a range could source packets from another peer's address and be authorized as
  that peer.
- **`replace_allowed_ips=true`, never an append.** When a peer keeps its key and
  moves to a new tunnel address, the old address must stop being accepted from
  that key. Appending would leave the old identity live forever.
- **One spelling.** Netstack hands back IPv4-in-IPv6 addresses in some paths, so
  `remoteTunnelIP` (`server.go`), `newPolicy` and `policy.Resolve` (`policy.go`)
  all `Unmap()`. If those two files ever disagree about normalization,
  `10.99.0.7` and `::ffff:10.99.0.7` become two identities and the policy lookup
  can miss.

What the client's own bytes are allowed to do: exactly one thing. The service
name from the hello frame selects a key inside the map already chosen by the
peer's address. It cannot select the map. Any change that lets a client-supplied
value reach the authorization key, directly or as a lookup into a wider table,
breaks the entire design, and no amount of validation on that value makes it
acceptable.

## 5. Hot reload and revocation

`peerWatcher.Run` (`config.go`) services fsnotify events with a 50ms debounce,
plus a 30 second re-arm ticker that re-adds the directory watch and reloads if
the file's size or mtime changed without an event arriving. A watch that dies
silently means revocation has stopped working, which is the worst failure this
project has, so the event stream is deliberately not the only path to a reload.

`reloadLocked` parses, validates, builds the new policy, computes the diff
against the config it is about to replace, and then publishes it with one
atomic `w.cur.Store(cfg)`. A reader either sees the whole previous config or
the whole new one. On any error nothing is published: the previous good config
stays in force and the result carries the error.

`report` then hands the result to the callback, which for a running server is
`Server.handleReload` (`server.go`). That runs in the watcher's own goroutine,
which `Run` waits for before closing the device, so a reload can never apply a
peer to a closed device.

**The ordering inside `handleReload` fails closed in both directions:**

```
policy swap (already done, inside the watcher)
   -> refreshPeers      rebuild names and limiters, reap departed peers' connections
   -> applyDiff         removals first, then adds, then changes, against the device
   -> pruneSecretCache  drop key material for references no longer in use
```

- **Adding a peer**: the policy has already swapped, so if `applyDiff` ran
  first, a brand new peer could complete a handshake, be granted its service by
  the new policy, and then be refused for having no limiter entry yet.
  Building the limiter set first closes that window.
- **Removing a peer**: every step of the window denies. The policy swap already
  dropped the peer's grants. `refreshPeers` then drops its limiter (so any new
  connection hits the no-entry path and is closed in silence) and closes its
  in-flight connections. Only then does `applyDiff` destroy the keypair.
- **Inside `applyDiff`, removals always go first.** Revocation must take effect
  at the earliest possible instant, and a failure later in the diff must not
  have delayed it. Every error is collected with `errors.Join` and returned,
  never swallowed: a removal failure logs `PEER REVOCATION FAILED` and
  `handleReload` logs "reloaded but NOT fully applied" rather than success.

**A limiter's identity is the peer, not the address.** `refreshPeers` keeps an
existing limiter only when `l.publicKey == p.PublicKey`. A reload that removes
peer A at `10.99.0.7` and adds peer B at the same address builds a fresh
limiter for B, which leaves A's limiter out of the kept set, into the `gone`
set, and its connections are reaped like any other departure. Keying by address
alone would let the departed peer's proxied connections and their backend file
descriptors outlive the revocation.

Two locking details worth knowing before you edit this: `gone` limiters are
collected under `s.mu` and closed **after** it is released, because closing a
connection wakes the handler that owns it and that handler takes locks on its
way out. And `report` is called outside `w.mu` for the same class of reason.

## 6. Shutdown ordering

`Server.Run` registers its defers so shutdown runs in exactly this order:

```
cancel runCtx
  -> wait for the watcher goroutine
  -> ln.Close()                 stop accepting
  -> close every tracked live connection
  -> s.wg.Wait(), bounded at 30s
  -> dev.Close()
  -> watcher.Close()
```

The three middle steps are `s.drainConnections(ln)`, deferred **after** the
device's `Close` so that it runs **before** it.

**Why this order, and what the previous one did.** Shutdown used to close the
device before waiting for the connection handlers. While a handler was still
unwinding, gVisor's TCP stack was still emitting packets for the connections
that handler was closing, resets among them, and
`netstack.(*netTun).Close()` drains the channel that `WriteNotify()` sends on.
The two race. It was observed under `-race` as a genuine data race, at roughly
one occurrence in four full suite runs, surfacing in
`TestServerMaxConcurrentIsEnforced`.

**Why closing the live connections is not optional.** Moving the wait ahead of
`dev.Close` without it would turn a rare race into a reliable deadlock: a
handler parked in `io.Copy` on a tunnel connection that never errors on its own
would hold shutdown forever. So `drainConnections` closes both sides of every
connection tracked by every limiter in force. Between that, `refreshPeers`
reaping departed peers, and `handleConn`'s own re-check closing connections
admitted under a limiter no longer in force, every tracked connection is
covered.

**Why the wait is bounded anyway.** No accounting can prove the set of tracked
connections is the set of places a handler can be parked: the window between
`Accept` and `limiter.track` is in no live set. Every step in that window is
separately bounded (5s hello read, 10s backend dial, 5s response write) and
`runCtx` is already cancelled, so the worst case is about 20 seconds and in
practice immediate. `shutdownDrainTimeout` is 30s. If it fires, shutdown logs
an error and closes the device with a straggler still running, which is exactly
what this code did on every shutdown before the fix. It is expected to be dead
code.

**Why `watcher.Close()` is last.** It is registered first. A handler unwinding
during the drain still reads the policy through `s.watcher`, and `Close` only
releases the filesystem watch, so closing it earlier would gain nothing and
could take a live reader's config out from under it. The watcher's *goroutine*
is a different thing and is waited for before any of this.

Two log lines mark the boundary and their order is load bearing:
`gocloak: shutdown: every connection handler has returned` must precede
`gocloak: shutdown: closing the tunnel device`. That order is what the
end-to-end test asserts on, because it is the only place the ordering is
visible from outside the package.

## 7. Testing strategy

`go test -race ./...` takes about 200 seconds. Budget for it; it is not hung.
Most of that is real WireGuard handshakes and real netstack TCP in-process.

### Unit tests

Table-driven, one `_test.go` per source file. 159 test functions across the
tree at the time of writing. The ones to read first when you change something:

- `policy_test.go`: unknown peer, unknown service, cross-peer access, empty
  allow map, duplicate tunnel IP, the `Unmap` equivalence.
- `wire_test.go`: zero length, length exceeding the buffer, truncated,
  oversized, invalid charset, unknown status byte, and a byte-at-a-time slow
  loris against the read deadline.
- `config_test.go`: unknown keys rejected, a malformed hot reload leaving the
  previous config in force, the debounce, rename replacement, and the YAML
  error sanitization that keeps a document key out of a message.
- `secret_test.go`: unknown scheme rejected, `file:` with permissions looser
  than 0600 rejected, an `aws:` reference with no `Resolver` rejected with an
  error that names what to import, a supplied `Resolver` delegated to, and
  `file:`/`env:` never reaching a `Resolver`.
- `awssecrets/` (nested module, run its tests from that directory):
  `aws:sm:` and `aws:ssm:` against fake AWS clients, `WithDecryption` asserted,
  and an end-to-end test that wires the resolver into a `gocloak.ClientConfig`.

### Fuzz

`FuzzHelloFrame` (`wire_fuzz_test.go`) fuzzes both frame parsers. The
properties asserted are that neither ever panics, that `readHelloRequest` never
returns a name failing its own charset check, and that `readHelloResponse`
never accepts an unknown status byte. Run it with `make fuzz`, which is
`go test -fuzz=FuzzHelloFrame -fuzztime=60s .`

The parser is the boundary that receives input from an authenticated but
possibly compromised peer, which is why it is the one thing here that gets
fuzzed.

### The five threat-model tests

`security_test.go`. Every top-level name contains `TestSecurity` because the
verification command is `go test -run TestSecurity`, which matches by
substring: a test named otherwise is silently skipped rather than failed.

| Test | What it proves |
|---|---|
| `TestSecurityWrongClientKeyGetsZeroBytesBack` | The endpoint answers an unknown key with exactly zero bytes, measured on a byte-counting UDP relay. It measures two distinct silences, an initiation from an unknown static key and a packet failing MAC1, and carries a positive control through the same relay so the zero is not vacuous |
| `TestSecurityWrongPSKNeverCompletesAHandshake` | A correct static key with the wrong PSK establishes no session. Note what it does **not** claim: IKpsk2 mixes the PSK into message 2, so such a party does draw a response. The README says so |
| `TestSecurityRevokedPeerCanNoLongerConnect` | Revoking a connected peer by hot reload makes the next dial fail |
| `TestSecurityPeerCannotReachAnotherPeersService` | Peer A dialing peer B's service is denied |
| `TestSecurityReplayedHandshakeInitiationIsRejected` | A captured initiation, replayed, is rejected. Each captured initiation is its own positive control, and the high-water-mark case (replaying an older initiation after a newer one was accepted) is covered explicitly |

These are not smoke tests. They are the evidence for spec section 7.1, and a
change that makes one of them pass vacuously is worse than a change that makes
it fail. If you touch a security test, prove it still fails when the property
is broken, and say in the PR how you proved it.

### Integration

`example_test.go` runs a real tunnel in one process: real wireguard-go client
and server over localhost UDP, real netstack, real backend, bytes end to end.
It lives in `package gocloak_test` and touches the library only through the
public API, so it is also the proof that the exported surface is sufficient to
build, configure, run and use a tunnel.

`examples_test.go` runs the same shape with `internal/msg`'s sink in place of
the backend. It is the in-process version of the README quickstart and fails if
the example apps ever drift from what the quickstart shows.

### What is not tested here

wireguard-go's cookie mechanism under load. Testing someone else's cookie
implementation is out of scope; goCloak's contribution to anti-DoS is using the
library correctly, not reimplementing it.

## 8. Invariants: the checklist

Run down this list before you open a pull request. Each one has an incident or
a design decision behind it.

- [ ] **Never log secret material, at any level.** Not truncated, not prefixed,
      not "just to debug this once". `secret` redacts in `String` and
      `GoString`; `secret.bytes()` stays unexported; `scrubRef` removes a
      secret reference and its payload before an error can reach a log line and
      deliberately over-redacts. A key or a PSK reaching a log line is a
      critical bug, not a style issue.
- [ ] **Authorization is default deny, with no wildcards.** No wildcard, no
      CIDR, no port range, no "all services for trusted peers". Absence is
      denial. A peer with no `allow` map reaches nothing.
- [ ] **Nothing the client sends may influence the authorization key.** The
      peer identity comes from `conn.RemoteAddr()` and cryptokey routing, full
      stop. See section 4.
- [ ] **`allowed_ip` is always a `/32`, and always with
      `replace_allowed_ips=true`.**
- [ ] **The public API does not grow.** The exported surface is exactly:
      `NewClient`, `NewServer`, `LoadServerConfig`, `LoadPeersConfig`,
      `ServerConfigFrom`, `ValidServiceName`; types `Client`, `ClientConfig`,
      `Server`, `ServerConfig`, `ServerFileConfig`, `PeersConfig`, `SecretRef`;
      the `Default*` constants; and the seven `Err*` sentinels. A new exported
      identifier needs an argument, not just a use.
- [ ] **The endpoint never answers unauthenticated traffic.** No enrollment
      endpoint, no health endpoint, no second listener, no error reply that a
      stranger can draw. If a change makes the process answer anything an
      unauthenticated party sent, it is wrong regardless of how convenient it is.
- [ ] **Names are never resolved.** No DNS anywhere: not in the tunnel, not for
      a backend address, not for a peer. `validatePeer` rejects a hostname at
      load time. This is what removes DNS rebinding from the design.
- [ ] **No X.509, no TLS, no certificate parsing** anywhere in the process.
- [ ] **Fail closed on every partial failure.** An unreachable secret store, a
      malformed config, a peer that will not apply: exit non-zero rather than
      start degraded. Never cache secrets to disk. Never start on a stale peer
      list.
- [ ] **A failed reload keeps the previous good config in force**, and says so
      loudly. A typo must neither revoke everyone nor widen access.
- [ ] **Revocation removes the peer from the live device** and reaps its
      in-flight connections. Removals go first in every ordering.
- [ ] **YAML decoding stays strict.** `KnownFields(true)`, one document, unknown
      key is a hard error.
- [ ] **The hello parser validates before it allocates**, and never echoes
      attacker-supplied bytes into an error or a log line.
- [ ] **`ErrHandshakeTimeout`'s message stays byte for byte identical across
      causes.** Including the duration, which is the bound rounded to 100ms,
      not the elapsed time. A message that varies with the failure is the
      beginning of the distinguishing signal spec 8.1 exists to deny.
- [ ] **No new dependencies** without a strong argument. The dependency list is
      part of the attack surface.
- [ ] **No test weakened, skipped or deleted** to make a change pass.
