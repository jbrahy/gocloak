# goCloak integration guide

This is the practical guide: how to install goCloak, mint keys, configure a
server, dial a service from Go code, and work out what has gone wrong when a
tunnel does not come up. It assumes a competent Go developer who has never
seen this project.

If you want to know how the internals work, read
[implementation.md](implementation.md) instead. If you want the design
rationale and the threat model, read the
[design spec](superpowers/specs/2026-09-09-gocloak-design.md).

Before you put this anywhere important, read the maturity warning in the
[README](../README.md). goCloak has never been externally audited.

## Contents

1. [The mental model](#1-the-mental-model)
2. [Install](#2-install)
3. [Keys and what each artifact is for](#3-keys-and-what-each-artifact-is-for)
4. [A complete worked example](#4-a-complete-worked-example)
5. [Using the connection](#5-using-the-connection)
6. [The error model](#6-the-error-model)
7. [Operations](#7-operations)
8. [Troubleshooting a handshake that never completes](#8-troubleshooting-a-handshake-that-never-completes)

## 1. The mental model

Four sentences, and everything else in this guide follows from them.

The client dials a **name**, never an address: `client.Dial(ctx, "primary-db")`
returns an ordinary `net.Conn`. The server holds a per-peer map from names to
real backend addresses, so `primary-db` means one thing for one peer and
possibly nothing at all for another. The client never learns a backend address
and cannot express one, which is why a stolen client key cannot be used to scan
or pivot. The backend is an ordinary TCP service that knows nothing about
goCloak: the server dials it with a plain `net.Dial`, so the backend sees a
normal TCP connection from the goCloak host.

Authorization is default deny. A service name that is not in that peer's
`allow` map is refused; there is no wildcard, no CIDR and no port range.

## 2. Install

As a library:

```
go get github.com/jbrahy/gocloak
```

The module requires Go 1.26.6 or newer. That floor is deliberate: it makes a
build against a known-vulnerable standard library a hard failure rather than a
silent one.

There are three binaries in this repository.

| Binary | What it is |
|---|---|
| `cmd/gocloak` | the operator CLI: `keygen` mints keys, `serve` runs the server |
| `cmd/gocloak-sink` | a plain TCP backend for testing. Not a goCloak peer, speaks no tunnel protocol |
| `cmd/gocloak-send` | a real goCloak client that sends one message through the tunnel |

Build all three into `bin/`:

```
make build
```

which runs exactly:

```
go build -o bin/gocloak ./cmd/gocloak
go build -o bin/gocloak-sink ./cmd/gocloak-sink
go build -o bin/gocloak-send ./cmd/gocloak-send
```

Or install just the operator CLI:

```
go install github.com/jbrahy/gocloak/cmd/gocloak@latest
```

## 3. Keys and what each artifact is for

Run `gocloak keygen` once for the server and once for every peer:

```
gocloak keygen --name server --dir /etc/gocloak
gocloak keygen --name app-01 --dir /etc/gocloak
```

`--name` is required and must match `[a-z0-9][a-z0-9-]{0,62}`, the same charset
a peer name and a service name use. That is not cosmetic: the name becomes part
of a file path, so the charset is what makes a path separator impossible.
`--dir` is optional and defaults to the current directory.

Each run prints:

```
peer: app-01
public_key: dT8xTJL1IthNgUwCuqLxblFAdmsHkI6WKh9+Gvwa4Qg=
psk: PHFcwgmV3FfO7YeCTtiDIVwvKm4qLOVu34hVBv/qcPk=
private key written to: /etc/gocloak/app-01.key
psk written to: /etc/gocloak/app-01.psk
```

and writes two files at mode 0600, refusing to overwrite an existing file.

| Artifact | Who holds it | What it is for |
|---|---|---|
| `<name>.key` | the peer it belongs to, or the server for its own | the Curve25519 private key. Load it into a secret store and delete the file |
| `<name>.psk` | the server, via `peers.yaml` | the peer's 32 byte preshared key, mixed into the handshake |
| printed `public_key` | the server, in `peers.yaml` | the peer's identity. Paste it verbatim |
| printed `psk` | your secret store | the same PSK as the file, printed so you can paste it into a secret store |

Three things to know.

**The `psk:` line is the one place this tool ever prints a live secret.** It
lands in scrollback, in CI logs and in session recordings. Move it into your
secret store and clear the scrollback.

**`keygen --name server` produces a `server.psk` that nothing consumes.** A PSK
belongs to a peer relationship, and the server takes each peer's PSK from that
peer's `psk:` reference in `peers.yaml`. The server's own `.psk` file is a
by-product of keygen being one code path for every name. Delete it.

**The private key is never printed**, only the path it was written to. Once the
key and the PSK are in your secret store, delete both files. They are the only
key material goCloak puts at rest, and the README's "no key material at rest"
property holds only once they are gone.

## 4. A complete worked example

This section is the quickstart with more explanation. Every flag and YAML key
below was checked against the source, and the whole sequence was run.

### 4.1 `server.yaml`

```yaml
listen_port: 51820
private_key: file:/etc/gocloak/server.key
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: /etc/gocloak/peers.yaml
log_format: text
```

| Key | Required | Meaning |
|---|---|---|
| `listen_port` | yes | the UDP port WireGuard binds. The only port this process opens to the internet. 1 to 65535 |
| `private_key` | yes | a secret reference to the server's private key, never a literal key |
| `tunnel_ip` | yes | must be exactly `10.99.0.1`. The server's address inside the tunnel |
| `mtu` | no | defaults to 1280. Accepted range is 1280 to 1500 |
| `peers_file` | yes | path to `peers.yaml`. Watched and hot reloaded |
| `log_format` | no | `json` (default) or `text`. Governs the whole process's logging |

An unrecognized key is a hard error. A typo in a security-relevant key has to
fail loudly rather than quietly granting or revoking access.

For production use `private_key: aws:sm:gocloak/server/private` instead of a
`file:` reference. That scheme lives in the separate
`github.com/jbrahy/gocloak/awssecrets` module and needs wiring in; see
[7.2](#72-secret-references) for every scheme and for the wiring.

### 4.2 `peers.yaml`

```yaml
peers:
  - name: app-01
    public_key: dT8xTJL1IthNgUwCuqLxblFAdmsHkI6WKh9+Gvwa4Qg=
    psk: file:/etc/gocloak/app-01.psk
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: 127.0.0.1:19000
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | the peer's name in log lines. Same charset as a service name |
| `public_key` | yes | base64 Curve25519, must decode to 32 bytes. Paste what keygen printed |
| `psk` | yes | a secret reference to this peer's PSK. Required, never optional |
| `tunnel_ip` | yes | this peer's address in `10.99.0.0/24`. Not `10.99.0.1`, not the network or broadcast address |
| `limits.max_concurrent` | no | defaults to 32 |
| `limits.dials_per_second` | no | defaults to 10 |
| `allow` | no | service name to literal `ip:port`. Omitting it means this peer can reach nothing |

Every backend must be a literal `ip:port`. A hostname is rejected at load time,
because nothing in this project resolves names, which is what removes DNS
rebinding from the design entirely. Peer names, public keys and tunnel
addresses must each be unique across the file.

An empty peer list (`peers: []`) is valid and means nobody may connect. A
zero-byte file is rejected: that is far more likely a truncated write than a
deliberate revocation of everyone.

### 4.3 Start a backend and the server

`gocloak-sink` is a plain TCP service, useful as a stand-in backend. It is not
a goCloak peer and speaks no tunnel protocol:

```
bin/gocloak-sink --listen 127.0.0.1:19000
```

```
gocloak-sink: listening on 127.0.0.1:19000 (plain TCP, not a goCloak peer)
```

`--listen` is the only flag and defaults to `127.0.0.1:19000`, which is the
address `peers.yaml` above grants to `primary-db`.

Then the server. `--config` is the only flag and is required:

```
bin/gocloak serve --config /etc/gocloak/server.yaml
```

```
level=INFO msg="gocloak: starting" config=/etc/gocloak/server.yaml
level=INFO msg="gocloak: server listening" listen_port=51820 tunnel_ip=10.99.0.1 mtu=1280 peers_file=/etc/gocloak/peers.yaml peers=1
```

The server fails closed. An unreachable secret store, a malformed config, an
unreadable key or a peer whose PSK will not resolve all exit non-zero rather
than starting degraded, so a supervisor backs off and retries instead of
running a half-configured tunnel.

You will also see this line, at ERROR level, roughly every six seconds for
every peer that has not yet spoken:

```
level=ERROR msg="gocloak: wireguard" message="peer(dT8x...a4Qg) - Failed to send handshake initiation: no known endpoint for peer"
```

That is a known, tracked defect in idle-peer logging, not a sign anything is
broken. See the "good first contributions" list in
[CONTRIBUTING.md](../CONTRIBUTING.md).

### 4.4 Send something through the tunnel

`gocloak-send` is a real client. Every flag except `--timeout` is required:

```
bin/gocloak-send \
  --endpoint 127.0.0.1:51820 \
  --server-key lv7sINDEP2auW5+l46h3aWpttdKaUQSDLudoIoTp6xg= \
  --key file:/etc/gocloak/app-01.key \
  --psk file:/etc/gocloak/app-01.psk \
  --tunnel-ip 10.99.0.7 \
  --service primary-db \
  "hello from the tunnel"
```

```
sent 21 bytes, ack in 1ms
```

and the sink's terminal shows the message arriving, with the source address
inside the tunnel:

```
2026-09-12T07:17:16-07:00 127.0.0.1:62278: hello from the tunnel
```

| Flag | Meaning |
|---|---|
| `--endpoint` | the server's `host:port`, UDP. Matches `listen_port` in `server.yaml` |
| `--server-key` | the `public_key` that `gocloak keygen --name server` printed. Pinned |
| `--key` | a secret reference to this peer's private key |
| `--psk` | a secret reference to this peer's PSK |
| `--tunnel-ip` | this peer's `tunnel_ip` from `peers.yaml` |
| `--service` | the service name to dial |
| `--timeout` | optional, defaults to `gocloak.DefaultDialTimeout` (10s) |

The positional argument is the message. `--key` and `--psk` take references,
never values, and `gocloak-send` never prints either one on any path,
including every error path.

Asking for a service this peer was not granted fails with exit code 10:

```
gocloak-send: denied: this peer's allow map does not grant this service
```

`gocloak-send --help` lists every exit code: 0 sent, 1 other error, 2 usage,
10 denied, 11 backend unavailable, 12 rate limited, 13 handshake timeout,
14 invalid service name.

### 4.5 Dial from your own program

```go
package main

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/jbrahy/gocloak"
	"github.com/jbrahy/gocloak/awssecrets"
)

func main() {
	// Only needed because one of the references below is aws:sm:. A
	// config that is all file: and env: needs no Resolver and no
	// awssecrets import, and links no AWS SDK.
	resolver, err := awssecrets.New(context.Background())
	if err != nil {
		panic(err)
	}

	client, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     "tunnel.example.com:51820",
		ServerPubKey: "lv7sINDEP2auW5+l46h3aWpttdKaUQSDLudoIoTp6xg=",
		PrivateKey:   gocloak.SecretRef("file:/etc/gocloak/app-01.key"),
		PresharedKey: gocloak.SecretRef("aws:sm:gocloak/peers/app-01"),
		TunnelIP:     netip.MustParseAddr("10.99.0.7"),
		MTU:          1280,
		DialTimeout:  10 * time.Second,
		Resolver:     resolver,
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	conn, err := client.Dial(context.Background(), "primary-db")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "hello from the tunnel\n"); err != nil {
		panic(err)
	}
}
```

`MTU` and `DialTimeout` may be omitted and default to 1280 and 10 seconds.
`ServerPubKey` is pinned: it is the only key this client will complete a
handshake with, and there is no certificate authority and nothing to
negotiate. `Endpoint` is resolved once, at construction.

`NewClient` contacts the secret store, so it can fail. It fails rather than
returning a half-usable client: there is no path where a client exists with
unresolved key material.

`Dial` blocks until the WireGuard handshake completes, so an authentication
failure surfaces on the first call rather than as a connection that hangs
later.

Build and run that program against the server from 4.3 and it behaves exactly
like `gocloak-send`.

## 5. Using the connection

`Dial` returns an ordinary `net.Conn`. Anything that takes one works.

### 5.1 With `http.Transport`

`(*Client).DialContext(ctx, network, addr)` has the standard dialer signature,
so it drops straight in. It ignores `network` and treats `addr` as the service
name with any `:port` suffix stripped, because the tunnel carries exactly one
transport and the port in a URL describes a backend the client never learns:

```go
httpClient := &http.Client{
	Transport: &http.Transport{
		DialContext: client.DialContext,
	},
	Timeout: 30 * time.Second,
}

// The host in the URL is the service name, not a hostname.
resp, err := httpClient.Get("http://internal-api/health")
```

The URL's host must therefore match the service name charset,
`^[a-z0-9][a-z0-9-]{0,62}$`. A port in the URL is stripped and ignored.

### 5.2 With `database/sql`

Any driver that accepts a dialer works. With
`github.com/go-sql-driver/mysql`, register a named network whose dialer is the
tunnel, then put the service name where the address goes in the DSN:

```go
mysql.RegisterDialContext("gocloak", func(ctx context.Context, addr string) (net.Conn, error) {
	// addr is the DSN's address field, which here is the service name.
	return client.Dial(ctx, addr)
})

db, err := sql.Open("mysql", "app:"+password+"@gocloak(primary-db)/orders?parseTime=true")
```

`gocloak(primary-db)` is the driver's `protocol(address)` syntax: `gocloak` is
the network registered above, and `primary-db` is handed to the dialer as
`addr`, which is exactly the service name. The database's real address never
appears in the DSN, and the application cannot express one.

`database/sql` opens connections lazily and reconnects on its own, so every new
pooled connection is a fresh `Dial` through the same tunnel. Set
`db.SetConnMaxLifetime` to something shorter than you would on a LAN and keep
the pool size at or below the peer's `max_concurrent`, or the pool will cause
its own `ErrRateLimited`.

### 5.3 What the connection is and is not

It is a raw byte pipe with no framing and no deadlines once `Dial` returns. A
long idle session is legitimate.

It is never re-established underneath you. If the tunnel drops mid-session, the
connections that were on it error out and the application calls `Dial` again.
That is deliberate: transparently reconnecting one would silently reorder or
duplicate application bytes. The WireGuard device itself may re-handshake at
any time, which does not affect a connection already handed out.

A `*Client` is safe for concurrent use.

## 6. The error model

Every error below is a sentinel, testable with `errors.Is`.

| Error | Cause | What an operator should do |
|---|---|---|
| `ErrInvalidServiceName` | the name does not match `^[a-z0-9][a-z0-9-]{0,62}$` | fix the caller. Rejected client-side, no packet was sent |
| `ErrClientClosed` | `Dial` was called after `Close` | fix the caller's lifecycle |
| `ErrHandshakeTimeout` | the endpoint never answered within `DialTimeout` | see section 8. The server log is the only place the answer exists |
| `ErrDenied` | the service is not in this peer's `allow` map | add the grant to `peers.yaml`, or fix the name the application asked for. The server logs this as a security event with the peer and the requested name |
| `ErrBackendUnavailable` | the service is granted but the server could not reach the backend | the grant is fine; the backend is down or the address in `peers.yaml` is wrong. Check the server log, which carries the backend address and the dial error |
| `ErrRateLimited` | the dial exceeded this peer's `limits` | raise `max_concurrent` or `dials_per_second` in `peers.yaml`, or fix the client that is dialing in a loop. Applies before the service name is even read |
| `ErrMalformedRequest` | the server could not parse the hello frame | against a server running this library, a version mismatch. Not a caller mistake |

The four that come back from the server (`ErrDenied`,
`ErrBackendUnavailable`, `ErrRateLimited`, `ErrMalformedRequest`) are safe to
be specific about, because by then the peer is authenticated and the detail
leaks nothing to a stranger. That is the whole reason the wire protocol carries
a status byte.

### `ErrHandshakeTimeout` is deliberately ambiguous

This is the one error the library will not narrow, and it matters enough to
say twice. Per spec section 8.1, WireGuard gives no negative feedback by
design: a wrong server public key, a wrong client key, a revoked peer, a wrong
PSK, UDP blocked on the path, and a server that is simply down all present
identically as silence. Any signal that told them apart is exactly what a
scanner is looking for, so the library does not produce one.

What you actually get is one error naming every possibility:

```
gocloak: handshake timeout: no response from 127.0.0.1:51820 after 10s. The
endpoint does not answer unauthenticated traffic, so this means one of: wrong
server public key, wrong client key, revoked peer, wrong PSK, UDP blocked on
this network, or the endpoint is down. The server cannot tell you which. Check
the server log for a peer entry
```

(One line in reality, wrapped here.) The duration in that message is the bound
the client applied, rounded to 100ms, not the elapsed time, precisely so the
message is byte for byte identical whatever the cause was.

**The server log is where the answer lives.** Section 8 is how to read it.

## 7. Operations

### 7.1 Revocation is an edit, not a restart

`peers.yaml` is watched. Delete the peer, save, and the peer is removed from
the live WireGuard device: the next packet from that key is dropped, and any
connection it still had proxying is closed. There is no restart and no window
in which a revoked key still works. Adding a peer and changing an `allow` map
work the same way.

Verified live, with the server left running throughout:

```
level=INFO msg="gocloak: connection closed" peer=app-01 service=primary-db status=ok bytes_sent=7 bytes_received=22 duration_ms=8802
level=WARN msg="gocloak: peer revoked" peer=app-01
level=INFO msg="gocloak: peers file reloaded" path=/etc/gocloak/peers.yaml peers=0 added=[] removed=[app-01] changed=[]
```

and the next dial from that peer times out as `ErrHandshakeTimeout`, exit code
13 from `gocloak-send`, because a revoked peer is indistinguishable from a dead
endpoint by design.

A reload that fails to parse or validate keeps the previous good config in
force and logs loudly, so a typo neither revokes everyone nor widens access.
Look for `peers file reload FAILED, the previous peer list is still in force`.

The watcher debounces for 50ms, so one editor save is one reload, and it
re-arms its filesystem watch every 30 seconds in case an event was missed. A
watch that dies for good is fatal: the server stops rather than serve a peer
list that can no longer change.

### 7.2 Secret references

Every secret-bearing field takes a reference, never a value. References are
resolved at startup into memory and never written to disk.

The library itself resolves two schemes, with no dependency outside the
standard library:

| Reference | Source |
|---|---|
| `file:<path>` | file contents. Refused if the mode is looser than 0600 |
| `env:<VAR>` | environment variable |

Every other scheme comes from a `SecretResolver` you supply:

```go
type SecretResolver interface {
	ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error)
}
```

Set it on `ClientConfig.Resolver` or `ServerConfig.Resolver`. It is optional:
nil means `file:` and `env:` only. `file:` and `env:` are resolved before a
`Resolver` is consulted, so a `Resolver` can add schemes but can never take
those two over.

The AWS schemes are such a resolver, shipped as a separate module:

| Reference | Source |
|---|---|
| `aws:sm:<secret-id>` | AWS Secrets Manager. The production form |
| `aws:ssm:<parameter>` | AWS SSM Parameter Store, read `WithDecryption` |

```
go get github.com/jbrahy/gocloak/awssecrets
```

```go
import (
	"github.com/jbrahy/gocloak"
	"github.com/jbrahy/gocloak/awssecrets"
)

resolver, err := awssecrets.New(ctx)
if err != nil {
	return err
}

srv, err := gocloak.NewServer(gocloak.ServerConfig{
	// ... listen_port, private_key, tunnel_ip, peers_file as usual
	Resolver: resolver,
})
```

`awssecrets.New` builds its clients from the ambient AWS region and
credentials. Because it is a separate module, a deployment whose references
are all `file:` or `env:` never imports it, never downloads the AWS SDK, and
never needs an AWS configuration to start. That is the change from v0.1.0: the
`aws:` schemes used to be built in, and an `aws:` reference with no `Resolver`
is now a startup error naming the module to import.

An unknown scheme is always an error, never a fallback to treating the string
as a literal key. If the secret store is unreachable at startup the server
exits non-zero rather than starting on a stale peer list, which would keep
revoked peers alive.

### 7.3 Rotation needs a restart, revocation does not

The server resolves each reference once and caches the value for the process
lifetime. Changing a secret **in place** under the same reference is therefore
never picked up by a reload. Rotate by writing the new value under a **new**
reference and pointing `peers.yaml` at that, which reloads like any other edit.
Otherwise, restart.

Revocation is unaffected either way: it removes the peer from the live device
rather than depending on the value behind a reference. Cached material for a
reference that has left the peer list is dropped on the next reload.

### 7.4 MTU defaults to 1280 on purpose

1280 is the IPv6 minimum, which is the largest value guaranteed to cross any
path, not the 1420 a LAN WireGuard setup usually takes. An MTU too large for
the path blackholes TCP silently, and that is the most common reason a
userspace WireGuard setup appears hung rather than broken. Accepted values are
1280 to 1500. Raise it only if you control the whole path and have measured it,
and set the same value on both ends.

### 7.5 Per-peer limits

`max_concurrent` (default 32) bounds connections in flight for that peer, and
it is applied the moment a connection is accepted, before the hello frame is
even read. That ordering is why a peer that connects and then says nothing
cannot starve everyone else. `dials_per_second` (default 10) is a token bucket
on the dial rate. Exceeding either returns `ErrRateLimited`.

A peer whose client exits without closing cleanly can leave its server-side
connection open until it is reaped by a reload or the backend closes it, so
size `max_concurrent` with some headroom above the pool size you actually
expect.

### 7.6 Deployment shape

The process opens exactly one port to the internet: the UDP `listen_port`.
Nothing answers an unauthenticated packet, so the port looks filtered to a
scanner. Run it under a supervisor that restarts it, because every startup
failure is deliberately fatal.

The tunnel subnet is fixed at `10.99.0.0/24`, the server holds `10.99.0.1`, and
that caps a deployment at 253 peers.

## 8. Troubleshooting a handshake that never completes

This is the failure you will actually hit, and the client is not allowed to
tell you which of the six causes it was. Here is how to work through them.

Start on the server, not the client. **Every one of these is visible in the
server log or the server's config; none of them is visible from the client.**

### Cause 1: wrong server public key

The client pins `ServerPubKey` and will complete a handshake with nothing else.

Check: run `gocloak keygen --name server` output against what the client has.
If you no longer have it, the server's public key is not recoverable from the
running process; derive it from the private key in your secret store, or mint a
new server keypair and update every client.

Tell: the server log shows nothing at all for this peer. A packet that fails
MAC1, which is keyed on the server public key, is dropped with zero response
and zero logging.

### Cause 2: wrong client key

Check: `public_key` in `peers.yaml` must be exactly what
`gocloak keygen --name <peer>` printed for the key the client is actually
loading. Watch for a client pointed at the wrong `.key` file, which is easy
when one host runs two peers.

Tell: also silence. A handshake initiation from a static key the server has
never seen gets exactly zero bytes back, because the peer lookup fails before
any response is generated.

### Cause 3: revoked peer

Check: is the peer still in `peers.yaml`? Search the server log for
`peer revoked` and for `peers file reloaded`, whose `removed=[...]` field names
every peer that left.

Tell: the reload lines above are definitive, and they are the reason to read
the server log first rather than guessing.

### Cause 4: wrong PSK

Check: the `psk:` reference in `peers.yaml` must resolve to the same 32 bytes
the client's `PresharedKey` resolves to. This is the one that survives a key
rotation done halfway: the keypair was updated, the PSK was not.

Tell: this one is different from causes 1 and 2, and the difference is worth
knowing. IKpsk2 mixes the PSK into message 2, not message 1, so a party holding
a valid client key but the wrong PSK **does** draw a Noise response back. The
handshake then fails and no session is established. So if you can see a reply
packet on the wire, the client key is right and the PSK is wrong.

Check for a startup failure too: if the PSK reference will not resolve at all,
the server exits non-zero at startup rather than running without it. Look at
the very first lines of the log.

### Cause 5: UDP blocked on this network

goCloak is UDP only. There is deliberately no TCP fallback, so on a network
that blocks UDP it does not work at all.

Check: from the client host, confirm the path carries UDP to that port. Corporate
networks, some cloud egress rules and a surprising number of hotel networks
block outbound UDP to non-standard ports.

Tell: the server log shows nothing, because nothing arrived.

### Cause 6: the endpoint is down, or you are talking to the wrong one

Check: is the process running, and is it bound where you think? The
`gocloak: server listening` line names `listen_port`, `tunnel_ip`, `mtu`,
`peers_file` and the peer count. If that line is absent, the server never
finished starting and the error above it says why.

Check the endpoint the client resolved. When `Endpoint` is a name, the error
message includes what it resolved to: `no response from tunnel.example.com:51820
(resolved to 203.0.113.10:51820)`. A stale DNS record sends a perfectly good
client to a perfectly silent address.

### A seventh thing that is not on the client's list

If the handshake completes but the connection then fails or hangs, suspect
**MTU**. Both ends must agree, and a value too large for the path blackholes
TCP silently rather than erroring. Set both to 1280 and see whether the problem
goes away. See 7.4.

### The fast triage order

1. Read the server log from its first line. A server that failed to start says
   so there, and that accounts for causes 3, 4 and 6 immediately.
2. Look for `peers file reloaded` with a `removed=[...]` naming your peer.
   That is cause 3.
3. Look for any line at all mentioning your peer. If the server has seen
   nothing from this client, you are in causes 1, 2 or 5, and no amount of
   client-side debugging will separate them.
4. Confirm the three values that have to match exactly: the server public key
   the client pins, the client public key in `peers.yaml`, and the peer's
   `tunnel_ip` on both sides.
5. Only then suspect the network.
