# goCloak: the three parked residuals, closed

Date: 2026-09-10
Branch: `harden/close-residuals`, off `main`.

This closes the three items left open in `docs/build-decisions.md` under "Open
items, all owner calls", and triaged in `docs/final-review.md` section 6. The
owner asked for the most secure resolution of each, so in every case the
option chosen is the one that fails closed, per `docs/finish.md`.

## Residual 1: the `limiterFor` to `track` window

### What was wrong

`handleConn` captured the peer's limiter before the hello read and registered
the connection against it after the backend dial. The gap spans the hello read
deadline (5s) plus the backend dial timeout (10s). A reload landing anywhere
in that window drains a live set the connection has not joined yet, and the
handler then registers against a limiter that is no longer in force. That
connection is never reaped: it holds its backend file descriptor and a
concurrency slot on a garbage limiter until the peer or the backend closes it.

### What changed

`server.go`, `handleConn`. After `track`, the handler re-reads
`limiterFor(peerIP)` and compares pointers with the limiter it was admitted
under. On a mismatch, or if the address has no entry at all, the connection is
closed and the handler returns without answering.

```go
limiter.track(live)
if current, ok := s.limiterFor(peerIP); !ok || current != limiter {
	limiter.untrack(live)
	s.logger.Warn("gocloak: peer was revoked or replaced while the connection was being set up, closed without a reply", ...)
	return
}
defer limiter.untrack(live)
```

Three things about the shape, all load bearing:

1. `track` comes first. Reversing it reopens the same orphan for a reload that
   lands between the check and the registration.
2. `untrack` is explicit on the refusal path and the `defer` is registered
   only after the check passes, so the registration is removed exactly once on
   either path.
3. The peer connection, the backend connection and the concurrency slot are
   released by the `defer`s already above this point (`defer conn.Close()`,
   `defer limiter.release()`, `defer backendConn.Close()`), so the refusal path
   leaks nothing. Nothing is written back, matching the existing no-entry path:
   a status frame is a metered reply, and the meter is exactly what is no
   longer in force.

There is no window left. If the map swap happens before the re-check reads it,
the re-check sees the mismatch and closes. If it happens after, the reload's
own `closeLive` finds this connection in the live set, because `track` already
ran, and closes it. Those two cases are exhaustive.

### Fail-closed reasoning

A connection whose authorization may have been revoked mid setup must not
become a live proxy. The cost of being wrong in this direction is that a
connection which the operator did not actually intend to revoke is dropped and
the application redials. The cost in the other direction is a proxy running
for an identity the operator has removed.

## Residual 2: a recycled tunnel IP inherited the limiter

### What was wrong

`refreshPeers` looked limiters up by tunnel address. A reload that removed
peer A at `10.99.0.7` and added peer B at `10.99.0.7` found the existing
limiter, kept it, and therefore never put it in the `gone` set. A's in-flight
proxied connections were not reaped. A's keypair is destroyed by `applyDiff`,
so A could neither send nor receive, but A's backend connections and file
descriptors stayed open until the backend closed them.

### What changed

`server.go`. A `peerLimiter` now carries the `publicKey` of the peer it
belongs to, set once at construction and never written again, so it is read
without the lock. `refreshPeers` keeps an existing limiter only when the
public key at that address is unchanged:

```go
if l, ok := s.limiters[ip]; ok && l.publicKey == p.PublicKey {
	l.setLimits(p.Limits)
	limiters[ip] = l
	continue
}
limiters[ip] = newPeerLimiter(p.PublicKey, p.Limits)
```

A replacement therefore gets a fresh limiter, the old object falls out of the
`kept` set, lands in `gone`, and its live connections are reaped exactly like
any other departure. The public key is the right identity because the reload
diff is already keyed by public key, and a key change is what actually swaps
one party for another behind an unchanged `10.99.0.N`.

The comment in `refreshPeers` that described the old inheritance behavior, and
which `docs/final-review.md` promoted to finding I4 as parked residual 3, is
replaced by one describing the new behavior. That closes residual 3 as well:
there is no longer an undocumented exception to the reap, because there is no
longer an exception.

### Which direction fails closed

The reaping direction. Getting it wrong the way it was leaves live proxied
connections, and their backend descriptors, running for an identity the
operator has just removed, which is precisely the outcome the reap exists to
prevent. Getting it wrong the new way at worst hands the arriving peer a zero
concurrency count instead of an inherited one.

That is worth stating plainly, because the original ruling called the
inherited count "the fail-closed direction" and that reading does not survive
the change. It was fail-closed only as an accounting matter: a stricter
starting count. But the connections that count was counting are now closed by
the reap, so inheriting it would charge the arriving peer for connections that
no longer exist, and the budget it is denied is the one its own config grants
it. Resource accounting is the lesser concern; a revoked peer's proxy still
running is the greater one. The new behavior is stricter on the axis that
matters and looser only on an axis that is now merely inaccurate.

## Residual 3: the exported surface

### What changed

Everything not reachable from outside `package gocloak` is now unexported.
This is a visibility change only: no function, type, field, constant or
behavior was deleted, and every identifier still exists under a lowercase
name.

Unexported, by file:

- `wire.go`: `Status` and its five constants (`StatusOK`, `StatusDenied`,
  `StatusBackendUnavailable`, `StatusRateLimited`, `StatusMalformed`),
  `ReadHelloRequest`, `ReadHelloResponse`, `WriteHelloRequest`,
  `WriteHelloResponse`, `HelloReadDeadline`, `ErrMalformedFrame`.
  `ValidServiceName` stays exported: `cmd/gocloak` calls it.
- `policy.go`: `NewPolicy`, `Policy`, `PeerPolicy`.
- `config.go`: `NewPeerWatcher`, `PeerWatcher` and its methods, `PeerConfig`,
  `PeerDiff`, `PeerLimits`, `ReloadResult`, and the two fields of
  `PeersConfig`.
- `secret.go`: `Secret`, `SecretResolver`, `NewSecretResolver`. `SecretRef`
  stays exported: spec section 5 declares it.
- `server.go`: `MinMTU`, `MaxMTU`.

### Before and after

| | Exported identifiers |
|---|---|
| before | 102 |
| after | 47 |

Counted over the non-test files of `package gocloak` with a `go/ast` pass:
exported top-level funcs, types, consts and vars, plus exported methods on
exported types and exported fields of exported structs. The same pass
including `_test.go` files gives 221 before and 168 after, and the test files
were not part of this change.

Neither number is the owner's measured 251, and I could not reproduce that
figure under any counting rule I tried, so the table above states its own
method rather than claiming to continue the owner's. The 8 identifiers the
owner measured as externally referenced are confirmed exactly: a scan of
`cmd/gocloak` and `example_test.go` finds `ClientConfig`, `LoadPeersConfig`,
`LoadServerConfig`, `NewClient`, `NewServer`, `SecretRef`, `ServerConfigFrom`
and `ValidServiceName`, and nothing else.

### What is still exported, and why

The 47 are exactly spec section 5's declared API plus the types those
signatures name, the error sentinels a caller compares against, and the
`Default*` constants:

- Spec section 5 verbatim: `ClientConfig` and its 7 fields, `NewClient`,
  `Client` with `Dial`, `DialContext` and `Close`, `ServerConfig` and its 5
  fields, `NewServer`, `Server` with `Run`, and `SecretRef`.
- Called from `cmd/gocloak`: `LoadServerConfig`, `LoadPeersConfig`,
  `ServerConfigFrom`, `ValidServiceName`.
- Named by those signatures: `ServerFileConfig` and its 6 fields
  (`cmd/gocloak` reads `LogFormat`), and `PeersConfig`.
- Sentinels a caller compares with `errors.Is`: `ErrHandshakeTimeout`,
  `ErrDenied`, `ErrBackendUnavailable`, `ErrRateLimited`,
  `ErrMalformedRequest`, `ErrClientClosed`, `ErrInvalidServiceName`. All seven
  are documented in the README as the errors `Dial` returns.
- `DefaultMTU`, `DefaultDialTimeout`, `DefaultLogFormat`, `DefaultMaxConcurrent`,
  `DefaultDialsPerSecond`.

Nothing was kept exported against the owner's list. Two notes on items the
list did not settle:

1. `PeersConfig` is kept exported because `LoadPeersConfig` returns it and a
   caller has to be able to name that type, which is the owner's stated reason
   for keeping it. Its two fields are unexported, because they are a peer list
   carrying public keys and secret references and no external consumer has a
   reason to read them. That leaves `PeersConfig` exported with no exported
   members, which is the shape `docs/final-review.md` finding M2 criticised for
   `Secret`. It is not the same situation: `Secret` had no exported constructor
   at all, whereas `PeersConfig` is produced by an exported function and is
   nameable for exactly that reason. Flagging it anyway, since it is the one
   judgment call in this part.
2. `MinMTU` and `MaxMTU` are unexported. They are not in spec section 5, not in
   the owner's list, and not referenced anywhere outside the package. A caller
   that sets an out of range MTU is told the bounds by the error message from
   `NewClient` or `NewServer`.

### README

No change was needed. The README references only `ClientConfig`, `SecretRef`,
`NewClient`, `Dial`, `Close`, `DialTimeout`, `MTU`, `ServerPubKey` and the
seven `Err*` sentinels, all of which are still exported. `Peers` appears once
at line 281 as English prose about enrolling peers, not as an identifier.

## Tests added

Both are in `server_test.go` and both contain `TestServer`, so the
`go test -run TestServer` verification matches them.

### `TestServerReplacingAPeerAtTheSameTunnelIPReapsTheDepartedPeer`

Residual 2, over the full real path: a real WireGuard pair on localhost UDP,
real netstack TCP, real backends on the host network, and a real peers.yaml
hot reload.

Peer `app-doomed` at `10.99.0.7` and peer `app-survivor` at `10.99.0.8` each
open a proxied connection and exchange bytes with their backend, so the
"before" state is a working proxy rather than merely an accepted connection.
One reload then replaces `app-doomed` with `app-replacement`, a different
keypair and a different PSK, at the same `10.99.0.7`, with an identical allow
map so that nothing but the identity changes. The test asserts:

- the diff removed exactly `app-doomed` and added exactly `app-replacement`;
- the limiter now at `10.99.0.7` is a different object carrying the
  replacement's public key;
- the departed peer's backend connection was released, proving the file
  descriptor was freed rather than left until the backend closed it;
- the departed peer's handler unwound, which happens only after both sides of
  the proxy are closed, so the peer-side connection is closed and the
  concurrency slot is back;
- the untouched peer at `10.99.0.8` still exchanges bytes, so the reap is
  targeted rather than a device-wide close.

Proved non-vacuous twice. With the identity check reverted to the old
address-keyed lookup, the test fails on the limiter-identity assertion; with
that assertion also removed, it fails on the backend-release assertion with
"replacing a peer at the same tunnel ip let its in-flight connection escape the
reap". The reap assertion, not just the bookkeeping assertion, catches the bug.

### `TestServerRevocationDuringConnectionSetupIsNotProxied`

Residual 1. This one is deterministic by injection, and this is the honest
account of what that means.

The peer side of the connection is a `net.Pipe` with a fake remote address of
`10.99.0.7`, handed to the real `handleConn` on a real running server. The
server, the peers.yaml hot reload, the watcher, the policy, the limiters and
the backend dial are all real. Only the peer transport is faked.

It is faked because a tunnelled version cannot be made deterministic. The
window opens when the handler captures the limiter and closes when it
registers the connection, and the only two points where a test can hold the
handler inside it are the hello read and the backend dial. Neither is
reachable through a real tunnel once the peer is revoked: revocation destroys
the peer's keypair, so the client cannot put another byte on the wire, and the
backend dial's timing is not controllable from a test without a synthetic
backend that can delay a TCP handshake. A `net.Pipe` makes the hello read a
hard synchronisation point: the handler blocks there until the test writes, so
the reload lands inside the window on every run rather than in a race the test
would have to lose in order to fail.

The sequence is: start the handler, wait until the limiter's concurrency count
reaches 1 (which happens immediately after `limiterFor`, so the pointer is
captured and the handler is now blocked on the hello read), rewrite peers.yaml
replacing the peer at the same address with an identical allow map, wait for
the reload to be applied, confirm the limiter at that address changed, and only
then write the hello frame. The policy still grants `db` to `10.99.0.7` at that
point, so the re-check is the only thing between this connection and a live
proxy. The test asserts:

- `ReadHelloResponse` on the peer side returns an error, so no status frame was
  sent and the connection was closed in silence;
- the handler returned rather than proxying;
- the backend connection it had already dialed was closed;
- the limiter the connection was admitted under is back to zero active and zero
  live, so the slot and the registration were both given back, exactly once;
- the arriving peer's limiter never saw the connection at all;
- the refusal was logged.

What it proves: the re-check branch closes the connection, releases the
backend, returns the concurrency slot and removes the registration exactly
once, and answers nothing. What it does not prove: that a real tunnelled
connection can be caught mid dial, or anything about netstack TCP behavior on
this path. It also exercises residual 2's keying, since a pointer mismatch at
an unchanged address is what residual 2's fix produces; the two fixes are
tested together here by construction.

Proved non-vacuous: with the re-check condition forced to false, the test fails
with "the server answered ok: a connection whose peer was revoked mid setup
became a proxy".

### Tests changed

One call site, `TestServerLimiterAccounting`, now passes a public key to
`newPeerLimiter`. One local variable named `status` in
`TestServerLogsNeverContainKeyMaterial` was renamed to `granted`, because it
shadowed the newly unexported `status` type in the same function. One
`http.StatusOK` in `client_test.go` was restored after the rename pass
lowercased it. No test was weakened, skipped or deleted.

## Verification

All run in the foreground on this branch, after every change above.

```
go build ./...                        exit 0
go vet ./...                          exit 0
staticcheck ./...                     exit 0
gofmt -l .                            empty
go test -count=1 -race ./...          ok github.com/jbrahy/gocloak 195.042s
                                      ok github.com/jbrahy/gocloak/cmd/gocloak 2.463s
go test -run '^Example$' -v .         --- PASS: Example (5.33s)
govulncheck ./...                     0 vulnerabilities
```

The `Example` run is the one that matters for residual 3: `example_test.go` is
in `package gocloak_test` and touches the library only through the public API,
so a passing `Example` is the proof that the surviving 47 identifiers are still
enough to build, configure, run and use a tunnel. It needed no edit at all,
which is the other half of that proof.

# Follow-up: the shutdown ordering data race

Date: 2026-09-11
Branch: `harden/close-residuals`, same branch as the work above.

## What was wrong

`Run` registered its defers so that shutdown ran in this order:

```
cancel -> watcher goroutine wait -> ln.Close -> dev.Close -> s.wg.Wait -> watcher.Close
```

The device was closed before the connection handlers were waited for. While a
handler was still unwinding, gVisor's TCP stack was still emitting packets for
the connections that handler was closing, resets among them.
`netstack.(*netTun).Close()` drains the channel `netstack.(*netTun).WriteNotify()`
sends on, so the two race. Observed once under `-race` on this branch, in
`TestServerMaxConcurrentIsEnforced`:

```
WARNING: DATA RACE
Write at ... by goroutine 4760:
  netstack.(*netTun).Close()   tun.go:180
  device.(*Device).Close()     device.go:381
  gocloak.(*tunnelDevice).Close.1()   device.go:280
Previous read at ... by goroutine 4821:
  netstack.(*netTun).WriteNotify()   tun.go:166
  ... gvisor tcp.replyWithReset ...
```

Frequency on this branch before the fix: 1 race in 4 full `-race` suite runs.
On `main`, before the residual hardening: 0 in 4. The hardening did not create
the ordering bug. It made it reachable more often, because reaping a revoked
peer's connections produces more resets near shutdown.

## The new order

```
cancel -> watcher goroutine wait -> ln.Close -> close every tracked live
connection -> s.wg.Wait (bounded) -> dev.Close -> watcher.Close
```

`server.go`, `Run`. The three middle steps are one new deferred call,
`s.drainConnections(ln)`, registered after the device's `Close` so it runs
before it. `defer s.wg.Wait()` is gone from the top of `Run`; the wait now
lives inside the drain, where it is correctly ordered against both the close
of the live connections and the close of the device.

`watcher.Close()` stays last, registered first. A handler unwinding during the
drain still reads the policy through `s.watcher`, and `Close` only releases the
filesystem watch, so closing it earlier would gain nothing and could take a
live reader's config out from under it. The watcher's own goroutine is a
separate thing and is still waited for before any of this, which is what keeps
a reload from ever applying a peer to a closed device.

## Why this cannot hang

Closing the live connections is the step that makes the earlier wait safe.
Moving `wg.Wait` ahead of `dev.Close` without it would turn a rare race into a
reliable deadlock: a handler parked in `io.Copy` on a tunnel connection that
never errors on its own would hold shutdown forever. So `drainConnections`
closes both sides of every connection tracked by every peer limiter in force,
using the per-peer live sets the residual work added. A peer that has left the
list has already been reaped by `refreshPeers`, and a handler that registered
against a limiter no longer in force closes its own connection on the re-check
in `handleConn`, so between the three of them every tracked connection is
covered.

The gap that accounting cannot close is the window between `Accept` and
`limiter.track`. A connection in that window is in no live set, so closing the
live sets does not touch it. Every step in that window is separately bounded:
the hello read deadline is 5s, the backend dial timeout is 10s, the response
write deadline is 5s, and `runCtx` is already cancelled by the time the drain
runs, which collapses the dial to nothing. Worst case is therefore about 20s
and in practice immediate.

Rather than trust that argument, the wait is bounded anyway.
`shutdownDrainTimeout` is 30s, comfortably above the 20s worst case. If it
fires, shutdown logs an error naming the timeout and proceeds to close the
device with a straggler still running, which is exactly what this code did on
every single shutdown before this change. That fallback is strictly better
than today's behaviour and strictly better than a shutdown that can block
forever. It is expected to be dead code.

Two log lines were added, both at the shutdown boundary:
`gocloak: shutdown: every connection handler has returned` and
`gocloak: shutdown: closing the tunnel device`. The order is load bearing and
the log is the only place it is visible from outside the package, which is
what the end-to-end test asserts on.

## Tests

`TestServerShutdownWithLiveConnectionsClosesTheDeviceLast` brings up two peers,
opens a real proxied connection for each through a real WireGuard pair, proves
each one carries bytes, then parks both with no traffic and no deadlines, which
is where a handler spends a long session. It cancels the server and asserts
that `Run` returns nil within 30s, that both handlers logged their closing line
before the device close line, and that the bounded wait never fired.

What it proves: shutdown with live connections in flight returns promptly and
without error, every handler had returned before the device was closed, and
the explicit close is what freed them rather than the timeout. Reverting the
ordering so the device closes first fails it deterministically, verified by
doing exactly that: 3 runs, 3 failures, on the assertion that the device was
closed before the handler wait finished.

What it does not prove: that the data race is gone. The race is intermittent
and a passing `-race` run is weak evidence for its absence. The test asserts
the ordering invariant that makes the race impossible, which is the stronger
thing available here, but it cannot observe the race itself.

`TestServerDrainClosesLiveConnectionsBeforeWaiting` is the deterministic half.
The end-to-end test cannot fail reliably if the explicit close is dropped,
because `pipeConns` has its own context watchdog that frees a parked copy when
`runCtx` is cancelled. So this one parks a stand-in handler on a tracked
connection with no watchdog at all: the only thing that can free it is
`drainConnections` closing that connection. Verified by deleting the
`closeLiveConns` call, which makes the test run to its bound and fail.

No test was weakened, skipped or deleted. No dependency was added. None of the
residual hardening was reverted; this fix is built on the per-peer live sets it
introduced.

## Verification

All run in the foreground on this branch, after every change above.

```
go build ./...                        exit 0
go vet ./...                          exit 0
staticcheck ./...                     exit 0
gofmt -l .                            empty
go test -count=1 -race ./... run 1    0 races, ok 186.132s / ok 1.780s
go test -count=1 -race ./... run 2    0 races, ok 201.508s / ok 1.999s
go test -count=1 -race ./... run 3    0 races, ok 192.821s / ok 2.574s
go test -run '^Example$' -v .         --- PASS: Example (5.15s)
```

Three full `-race` suite runs, zero races in each. Against a pre-fix frequency
of 1 in 4 runs, three clean runs is consistent with the fix and is not proof of
it: the expected number of races in three runs was under one to begin with.
The ordering assertion in the tests, not the race count, is the durable part.
