# goCloak

goCloak is a Go library that gives a local application an encrypted, mutually
authenticated byte stream to a named backend service that is reachable only
from a remote endpoint. `client.Dial(ctx, "primary-db")` returns an ordinary
`net.Conn`. The endpoint sits on the public internet and is assumed to be under
constant hostile attention, so it answers nothing it cannot authenticate: to
anyone without the server public key it is indistinguishable from a filtered
port. It is for operators who need an application outside a VPC to reach a
small, fixed set of services inside one, without a bastion host, without a TUN
device, without root, and without a certificate authority.

Before you deploy it, read
[What goCloak does not protect against](#what-gocloak-does-not-protect-against).
That section is short, and it is the part that decides whether this tool fits
your threat model.

## Architecture

```
LOCAL APP                          HOSTILE INTERNET              PRIVATE VPC

 client.Dial(ctx, "primary-db")
        |
        v
 +- gocloak client -----------+
 |  gVisor netstack           |
 |    (userspace TCP)         |
 |  wireguard-go device       |
 +-----------+----------------+
             |  Noise_IKpsk2 / UDP
             +--------------------->  +- gocloak server (EC2) ---------+
                                      |  wireguard-go  UDP :51820      |
                                      |  netstack listener 10.99.0.1   |
                                      |  policy: (peer, name) -> addr  |
                                      +----------+---------------------+
                                                 | plain net.Dial
                                                 v
                                         192.0.2.10:3306
```

Everything is userspace. WireGuard
(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) is provided by wireguard-go and TCP
by gVisor netstack, both inside the process. There is no TUN device, no root,
and no `CAP_NET_ADMIN`. goCloak itself writes no cryptography and no transport:
the security-critical code in this repository is the policy engine and the
hello frame parser, and both are small enough to read in one sitting.

Each peer owns one address in `10.99.0.0/24`, pinned by WireGuard cryptokey
routing to its keypair. The server holds `10.99.0.1`, which caps a deployment
at 253 peers. Because a packet sourced from `10.99.0.7` provably came from the
keypair bound to that address, `RemoteAddr()` on the server is a
cryptographically enforced peer identity rather than a claim, and the policy
lookup keys off it.

The client never learns a backend address. It sends a service name over the
tunnel, the server resolves that name against this peer's allow map, and the
connection becomes a raw byte pipe. Backends move without touching any client.

## Five minute quickstart

### 1. Build the CLI

```
go install github.com/jbrahy/gocloak/cmd/gocloak@latest
```

Or from a checkout:

```
go build -o gocloak ./cmd/gocloak
```

### 2. Mint keys

Run keygen once for the server and once for each peer. `--name` must match
`[a-z0-9][a-z0-9-]{0,62}`, the same charset a peer name and a service name use.

```
gocloak keygen --name server --dir /etc/gocloak
gocloak keygen --name app-01 --dir /etc/gocloak
```

Each run writes `<name>.key` and `<name>.psk` at mode 0600, refuses to
overwrite an existing file, and prints:

```
peer: app-01
public_key: 7T4dP1sVQ0zK8mJ9c3rW5hLxB2nY6uA0eF+iG4kS1oM=
psk: hN2q8XvR6cD1yP4mZ0tK7aW3sU9bE5jL8gO+fH2iC6Y=
private key written to: /etc/gocloak/app-01.key
psk written to: /etc/gocloak/app-01.psk
```

`--dir` is optional and defaults to the current directory. The private key is
never printed, only the path it was written to.

The `psk:` line is the one place this tool ever emits a live secret, so treat
that terminal as sensitive: the value lands in scrollback, in any session
recording or CI job log, and in shell history if you pipe or re-echo it. Move
it into your secret store and clear the scrollback rather than leaving it
sitting in a window.

The peer's `public_key` goes into `peers.yaml` verbatim. The peer's PSK goes
into your secret store, and `peers.yaml` carries a reference to it, not the
value. The peer's own `.key` and `.psk` files go to the peer host. The server's
own `.psk` file is not used at all: a PSK belongs to a peer relationship, and
the server takes each peer's PSK from `peers.yaml`.

### 3. Write `server.yaml`

```yaml
listen_port: 51820
private_key: aws:sm:gocloak/server/private
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: /etc/gocloak/peers.yaml
log_format: json
```

Every key is required except `mtu` (default 1280) and `log_format` (default
`json`, the alternative is `text`). `tunnel_ip` must be `10.99.0.1`. An
unrecognized key is a hard error, never a silent ignore: a typo in a
security-relevant key must fail loudly rather than quietly granting or revoking
access.

`aws:sm:` is the production form for `private_key`. To get a first deployment
running without AWS, point it at the file keygen just wrote:
`private_key: file:/etc/gocloak/server.key`. See
[Operational essentials](#operational-essentials) for every reference scheme.

### 4. Write `peers.yaml`

```yaml
peers:
  - name: app-01
    public_key: 7T4dP1sVQ0zK8mJ9c3rW5hLxB2nY6uA0eF+iG4kS1oM=
    psk: aws:sm:gocloak/peers/app-01
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: 192.0.2.10:3306
      cache: 192.0.2.11:6379
```

`name`, `public_key`, `psk` and `tunnel_ip` are required per peer. `limits` is
optional and defaults to `max_concurrent: 32` and `dials_per_second: 10`.

Everything under `allow` is an explicit grant of one service name to one
literal `ip:port`. A hostname is rejected at load time, because nothing in this
project resolves names. There is no wildcard, no CIDR and no port range.
Absence is denial, and a peer with no `allow` map can reach nothing.

### 5. Run the server

```
gocloak serve --config /etc/gocloak/server.yaml
```

`--config` is the only flag, and it is required. The process opens exactly one
port to the internet, the UDP `listen_port`. It fails closed: an unreachable
secret store, a malformed config or an unreadable key at startup exits non-zero
rather than starting degraded, so systemd backs off and retries.

### 6. Dial from an application

```go
package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/jbrahy/gocloak"
)

func main() {
	client, err := gocloak.NewClient(gocloak.ClientConfig{
		Endpoint:     "tunnel.example.com:51820",
		ServerPubKey: "mF3kQ8vT2xN7pY0aR5cJ1wL6dH9sB4eU+gI2oZ8yK0M=",
		PrivateKey:   gocloak.SecretRef("file:/etc/gocloak/app-01.key"),
		PresharedKey: gocloak.SecretRef("aws:sm:gocloak/peers/app-01"),
		TunnelIP:     netip.MustParseAddr("10.99.0.7"),
		MTU:          1280,
		DialTimeout:  10 * time.Second,
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

	io.WriteString(conn, "hello from the tunnel\n")
	fmt.Println("connected")
}
```

`ServerPubKey` is the `public_key` that `gocloak keygen --name server` printed,
and it is pinned: it is the only key this client will complete a handshake
with. `MTU` and `DialTimeout` may be omitted and default to 1280 and 10
seconds. `Dial` blocks until the WireGuard handshake completes, so an
authentication failure surfaces on the first call rather than as a connection
that hangs later.

`(*Client).DialContext(ctx, network, addr)` has the standard dialer signature,
so a `*Client` drops straight into `http.Transport.DialContext` or any database
driver that accepts a dialer. It ignores `network` and treats `addr` as the
service name with any `:port` suffix stripped.

`example_test.go` in this repository runs the whole of the above end to end,
server and client and backend, in one process.

## Security properties that hold

| Property | Mechanism |
|---|---|
| Endpoint invisibility | Packets failing MAC1, keyed on the server public key, are dropped with zero response. No ICMP, no reset, no timing tell. Indistinguishable from a filtered port. |
| Mutual auth and confidentiality | Noise IKpsk2. The client's identity is encrypted inside the first message, so a passive observer cannot tell which peer connected. |
| Forward secrecy | Ephemeral keys per session, rekey every 2 minutes or 2^60 messages. A stolen static key does not decrypt recorded traffic. |
| Replay resistance | 64-bit nonce with a sliding receive window, plus TAI64N handshake timestamps rejecting replayed initiations. |
| Post-quantum hedge | The PSK is mixed into the chaining key. Breaking Curve25519, including harvest-now-decrypt-later, still leaves a 32-byte symmetric secret. |
| Anti-DoS | Under load the server returns a cookie MAC'd to the source address instead of performing Curve25519. Address validation precedes expensive work. |
| Blast radius | A stolen client key reaches only that peer's named services. It cannot express an unapproved address, so it cannot scan or pivot. |
| No key material at rest | Secrets Manager to memory. Nothing in EBS snapshots. CloudTrail records every read. |
| Instant revocation | A peers file change removes the peer from the live device. The next packet from that key is dropped. No restart, no window. |

## What goCloak does not protect against

These are not gaps waiting to be fixed. They are the boundaries of what the
design can do, and they are stated here as plainly as the table above.

**1. Traffic analysis is not defeated.** Packet sizes and timing are visible on
the wire. An observer sees that two addresses exchange WireGuard-shaped UDP, and
can measure how much and when. goCloak encrypts what you send, not the fact
that you sent it.

**2. Silent to strangers, not steganographic.** Anyone who already holds the
server public key can confirm the endpoint exists. Invisibility here means the
endpoint does not answer unauthenticated traffic, not that a determined party
who has the key cannot tell it is there. Nor is the silence keyed on the PSK: a
party holding a valid client key but the wrong PSK still draws a Noise message
2 back, because IKpsk2 mixes the PSK into message 2 rather than message 1. The
handshake then fails and no session is established, but the response itself
confirms the endpoint.

**3. Client host compromise is peer compromise.** No secret survives root on the
client. An attacker with that access has the peer's key and PSK and can reach
everything in that peer's allow map. This is why blast radius is the real
control: keep each peer's `allow` map as small as the application actually
needs.

**4. Server compromise is total for its allowed services.** The server holds
every peer's grants and terminates every tunnel. An attacker who owns the
server process reaches every backend any peer is allowed to reach.

**5. Bandwidth flooding is a network-layer problem, not a cryptographic one.**
The cookie mechanism keeps a flood from burning CPU on Curve25519, but nothing
in this library stops a large enough flood from saturating the link. That is a
job for the network in front of the endpoint.

## Deliberate omissions, and what they buy

- **No X.509 and no TLS anywhere.** Zero certificate parsing in the process, so
  no certificate chain bugs, no expiry outages, no CA to trust or rotate.
- **No enrollment endpoint.** Nothing in the process answers an unauthenticated
  request, which is what makes the endpoint invisibility above achievable at
  all. Peers are enrolled by editing `peers.yaml`.
- **No DNS inside the tunnel.** Names resolve server-side against a static map,
  which removes DNS rebinding entirely and means the client can never be
  steered at an address the operator did not write down.
- **No TCP fallback.** The tunnel is UDP only, so there is no visible port for
  a scanner to find and no second code path to audit. The cost is real: on a
  network that blocks UDP, goCloak does not work.
- **Logs carry peer name, service name, status and byte counts.** Never key
  material, never payload, at any level including debug.

## Authentication failure is indistinguishable from a dead endpoint

This is by design and it is worth knowing before you debug your first
deployment. WireGuard gives no negative feedback. A wrong server public key, a
wrong client key, a revoked peer, a wrong PSK, UDP blocked on the path, and a
server that is simply down all present identically as silence. The library does
not try to tell them apart, because any signal that distinguishes them is
exactly what a scanner is looking for.

`Dial` bounds the wait at `DialTimeout` and returns one error, wrapping
`ErrHandshakeTimeout`, that names every possibility:

```
gocloak: handshake timeout: no response from tunnel.example.com:51820
  (resolved to 203.0.113.10:51820) after 10s. The endpoint does not answer
  unauthenticated traffic, so this means one of: wrong server public key,
  wrong client key, revoked peer, wrong PSK, UDP blocked on this network,
  or the endpoint is down. The server cannot tell you which. Check the
  server log for a peer entry
```

(The message is one line; it is wrapped here to fit.)

When you hit this, go read the server log. That is the only place the answer
exists. The client cannot narrow it down and will not pretend to.

Once the tunnel is up, the server does answer with detail, because the peer is
by then authenticated and the detail leaks nothing to a stranger. Each of these
is a distinct sentinel, testable with `errors.Is`:

| Error | Meaning |
|---|---|
| `ErrDenied` | The service is not in this peer's `allow` map. |
| `ErrBackendUnavailable` | The service is granted, but the server could not reach the backend. |
| `ErrRateLimited` | The dial exceeded this peer's `limits`. |
| `ErrMalformedRequest` | The server could not parse the hello frame, which means a version mismatch. |
| `ErrInvalidServiceName` | The name does not match `^[a-z0-9][a-z0-9-]{0,62}$`. Rejected client-side, no packet sent. |
| `ErrClientClosed` | `Dial` was called after `Close`. |

## Operational essentials

**Revocation is an edit, not a restart.** `peers.yaml` is watched. Delete a
peer, save, and the peer is removed from the live WireGuard device; the next
packet from that key is dropped. There is no restart and no window in which a
revoked key still works. Adding a peer and changing an `allow` map work the same
way. A reload that fails to parse or validate keeps the previous good config in
force and logs loudly, so a typo neither revokes everyone nor widens access.

**MTU defaults to 1280, not the usual 1420, and that is deliberate.** 1280 is
the IPv6 minimum, which is the largest value guaranteed to cross any path. An
MTU that is too large for the path blackholes TCP silently, and that is the most
common reason a userspace WireGuard setup appears hung rather than broken.
Accepted values are 1280 to 1500. Raise it only if you control the whole path
and have measured it.

**Secrets are references, never literals.** Both `ClientConfig` and the YAML
take a `SecretRef`, resolved at startup into memory and never written to disk:

| Reference | Source |
|---|---|
| `aws:sm:<secret-id>` | AWS Secrets Manager. This is the production form. |
| `aws:ssm:<parameter>` | AWS SSM Parameter Store, read `WithDecryption`. |
| `file:<path>` | File contents. Refused if the mode is looser than 0600. |
| `env:<VAR>` | Environment variable. |

An unknown scheme is an error, never a fallback to treating the string as a
literal key. If the secret store is unreachable at startup the server exits
non-zero rather than starting on a stale peer list, which would keep revoked
peers alive.

**Rotation is not revocation, and rotation does need a restart.** The server
resolves each reference once and caches the value for the process lifetime, so
changing a PSK in place under the same reference is never picked up by a
reload. Rotate by writing the new value under a new reference and pointing
`peers.yaml` at that, or restart the server. Revocation is unaffected: it
removes the peer from the live device rather than depending on the value behind
a reference.

**A dropped tunnel errors the connections that were on it.** There is no
transparent per-connection reconnect, because silently re-establishing a
connection underneath an application reorders or duplicates its bytes. Call
`Dial` again. `persistent_keepalive_interval` is 25 seconds, which keeps NAT
bindings alive and detects a dead path quickly. A client that changes network is
handled by WireGuard roaming: the server relearns the peer's endpoint from its
first valid authenticated packet.

## Development

```
make test    # go test -race ./...
make lint    # go vet and staticcheck
make fuzz    # fuzz the hello frame parser
make vuln    # govulncheck
```

`go test -run Example ./...` runs a real tunnel, a real server and a real
backend in one process, end to end.
