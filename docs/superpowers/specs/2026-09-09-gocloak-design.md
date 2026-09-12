# goCloak Design Spec

Date: 2026-09-09
Status: Approved (architecture, API, threat model, failure handling, testing)

## 1. Purpose

A Go library that gives a local application an encrypted, mutually authenticated
byte stream to a named backend service reachable only from a remote endpoint.
The endpoint sits on the public internet and is assumed to be under constant
hostile attention. Security outranks features, performance, and convenience at
every decision point.

## 2. Scope

In scope:

- A client library. `Dial(ctx, "service-name")` returns a `net.Conn`.
- A server library and daemon that terminates tunnels and proxies to backends.
- A CLI for key generation and running the server.

Out of scope, deliberately:

- Traffic obfuscation or censorship circumvention.
- A TCP fallback for networks that block UDP.
- Multi-hop or relaying between peers.
- A peer enrollment protocol.
- Any DNS resolution inside the tunnel.
- Any X.509 or TLS code path.

## 3. Architecture

```
LOCAL APP                          HOSTILE INTERNET              PRIVATE VPC

 tun.Dial(ctx, "primary-db")
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

### 3.1 Cryptographic core

`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, provided by wireguard-go in userspace.
No TUN device, no root, no CAP_NET_ADMIN. TCP is provided by gVisor netstack,
also in userspace.

We write no cryptography and no transport. The security-critical code we do
write is the policy engine and the hello frame parser, and both are small
enough to read in one sitting.

### 3.2 Peer identity

Each peer is assigned a unique tunnel address via `allowed_ip=10.99.0.N/32`.
WireGuard cryptokey routing guarantees that a packet sourced from `10.99.0.7`
came from the keypair bound to that address. Therefore
`conn.RemoteAddr()` on the server is a cryptographically enforced peer
identity, not a claim. Policy lookup keys off it.

Tunnel subnet is `10.99.0.0/24`. The server holds `10.99.0.1`. This caps the
deployment at 253 peers, which is documented and accepted.

### 3.3 Service name transport

netstack carries IP packets, so a service name needs a carrier. The client
opens one netstack TCP connection to `10.99.0.1:443` and writes a single hello
frame. The server resolves it and the connection becomes a raw byte pipe.

The client never learns a real backend address. Backends move without touching
any client.

## 4. Wire protocol (inside the tunnel)

This protocol runs only inside an authenticated, encrypted WireGuard session
with an already-verified peer. It is intentionally minimal.

Request, written by the client immediately on connect:

```
byte 0        version, must be 0x01
byte 1        name length N, 1..255
bytes 2..N+1  service name
```

Service names are validated against `^[a-z0-9][a-z0-9-]{0,62}$`. The charset is
restricted so a name can never inject control characters into a log line.

Response, written by the server:

```
byte 0   version, 0x01
byte 1   status
           0x00 ok
           0x01 denied (unknown service for this peer)
           0x02 backend unavailable
           0x03 rate limited
           0x04 malformed request
```

After `0x00` the connection is a raw bidirectional pipe with no further
framing. Any other status is followed immediately by close.

The server sets a 5 second read deadline for the request and clears deadlines
after the response. A peer that sends the frame one byte at a time is cut off
by the deadline.

Giving a specific status here is safe and deliberate: the peer is already
authenticated, so the detail leaks nothing to an unauthenticated attacker, and
it lets the application distinguish "denied" from "the database is down."

## 5. Public API

```go
package gocloak

// ---- client ----

type ClientConfig struct {
    Endpoint     string     // "tunnel.example.com:51820", UDP
    ServerPubKey string     // base64 Curve25519, pinned
    PrivateKey   SecretRef
    PresharedKey SecretRef
    TunnelIP     netip.Addr // this peer's 10.99.0.N
    MTU          int        // default 1280
    DialTimeout  time.Duration // default 10s
}

func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) Dial(ctx context.Context, service string) (net.Conn, error)
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
func (c *Client) Close() error

// ---- server ----

type ServerConfig struct {
    ListenPort int
    PrivateKey SecretRef
    TunnelIP   netip.Addr // 10.99.0.1
    MTU        int        // default 1280
    PeersFile  string     // watched, hot-reloaded
}

func NewServer(cfg ServerConfig) (*Server, error)
func (s *Server) Run(ctx context.Context) error
```

`DialContext` exists so a `*Client` drops into `http.Transport.DialContext` and
any driver that accepts a dialer. It ignores `network` and treats `addr` as the
service name with any `:port` suffix stripped.

`Dial` blocks until the tunnel handshake completes, so the first call surfaces
an authentication failure rather than hanging on a half-open connection.

**Amended in v0.2.0.** `Endpoint` was resolved exactly once, at construction,
which meant an endpoint whose address changed could only be recovered from by
destroying the `Client` and building another. That is expensive for every
integrator to get right, because a `Client` is documented as safe for
concurrent use and would have to be swapped out from underneath its own
concurrent users. A `Dial` that cannot bring the tunnel up now re-resolves the
name once and, if it yields a different address, moves the device peer onto it
before the remaining attempts. A dial that succeeds does no lookup, an IP
literal is never looked up, and a re-resolution that fails or returns nothing
fails the dial rather than falling back to an address that cannot be
confirmed. The public API is unchanged.

## 6. Configuration

YAML is decoded with `KnownFields(true)`. An unrecognized key is a hard error,
never a silent ignore. A typo in a security-relevant key must fail loudly
rather than quietly granting or revoking access.

`server.yaml`:

```yaml
listen_port: 51820
private_key: aws:sm:gocloak/server/private
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: /etc/gocloak/peers.yaml
log_format: json
```

`peers.yaml`, watched and hot-reloaded:

```yaml
peers:
  - name: app-01
    public_key: mF3k...=
    psk: aws:sm:gocloak/peers/app-01
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: 192.0.2.10:3306
      cache: 192.0.2.11:6379
```

Everything under `allow` is an explicit grant. There is no wildcard, no CIDR,
and no port range. Absence is denial.

### 6.1 Secret references

The core module resolves exactly two schemes, and needs nothing outside the
standard library to do it:

```
file:<path>            file contents, must be mode 0600 or stricter
env:<VAR>              environment variable
```

Every other scheme comes from a `SecretResolver` the program supplies, set on
`ClientConfig.Resolver` or `ServerConfig.Resolver`. The AWS schemes are one
such resolver, in a nested module of their own:

```
aws:sm:<secret-id>     AWS Secrets Manager                 github.com/jbrahy/gocloak/awssecrets
aws:ssm:<parameter>    AWS SSM Parameter Store, WithDecryption
```

`aws:sm` is still the production form for an AWS deployment. Resolved values
live in memory only and are never written to disk. `file:` refuses to read a
file with permissions looser than 0600. An unknown scheme is always an error;
it is never a fallback to treating the reference as a literal key, and a
`Resolver` is never consulted for `file:` or `env:`, so one cannot take those
two over.

Why the split, since it is a breaking change. Resolution used to switch on the
scheme at runtime inside this package, which made every scheme's
implementation reachable from any use of the package, so all of them linked. A
program whose entire body was `gocloak.ValidServiceName("x")` pulled 89 AWS
packages into its build and produced a 4.9 MB stripped binary. Someone keeping
key material in a `file:` or `env:` reference paid for Secrets Manager and SSM
in binary size, dependency count and supply-chain exposure, and never learned
why. For a library whose reason to exist is a small auditable attack surface,
that is worse as a supply-chain problem than as a size problem.

A subpackage would not have fixed it: `go.mod` and `go.sum` would still carry
`aws-sdk-go-v2`, `go mod download` would still fetch it, and an audit of this
module would still have to cover it. A nested module with its own `go.mod`
takes AWS out of the core dependency graph entirely. The same program now
links 0 AWS packages, 205 packages in total rather than 358, and is 3.4 MB
stripped.

Wiring is explicit rather than a `database/sql`-style global `Register`. Global
mutable state in a security library means any imported package can silently
install a secret resolver; whoever builds the config should be the one who
decides where key material comes from.

## 7. Threat model

Assumed attacker: full control of the network path (read, modify, drop, replay,
inject), unlimited scanning and probing of the public endpoint, unlimited
handshake attempts, and a copy of this source.

### 7.1 Properties that hold

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
| Instant revocation | A peers file change triggers IpcSet with `remove=true`. The next packet from that key is dropped. No restart, no window. |

### 7.2 Properties that do not hold

1. Traffic analysis is not defeated. Packet sizes and timing are visible. An
   observer sees that two addresses exchange WireGuard-shaped UDP.
2. Silent to strangers, not steganographic. Anyone already holding the server
   public key can confirm the endpoint exists.
3. Client host compromise is peer compromise. No secret survives root on the
   client, which is why blast radius is the real control.
4. Server compromise is total for its allowed services.
5. Bandwidth flooding is a network-layer problem, not a cryptographic one.

### 7.3 Omissions that shrink the attack surface

- No X.509 and no TLS anywhere. Zero certificate parsing in the process.
- No enrollment endpoint. Nothing answers an unauthenticated request.
- No DNS inside the tunnel. Names resolve server-side against a static map,
  which removes DNS rebinding entirely.
- No TCP fallback, so no visible port.
- Logs carry peer name, service name, status and byte counts. Never key
  material, never payload.

## 8. Failure handling

### 8.1 Authentication failure is indistinguishable from a dead endpoint

WireGuard gives no negative feedback by design. Wrong key, revoked peer, wrong
PSK, and an offline server all present identically as silence. The library must
not attempt to distinguish them, because any distinguishing signal is what a
scanner is looking for.

The client bounds the wait at `DialTimeout` and returns a single error naming
every possibility:

```
ErrHandshakeTimeout: no response from <endpoint> after <d>.
  The endpoint does not answer unauthenticated traffic, so this means one of:
  wrong server public key, wrong client key, revoked peer, wrong PSK,
  UDP blocked on this network, or the endpoint is down.
  The server cannot tell you which. Check the server log for a peer entry.
```

### 8.2 Other modes

| Failure | Behavior |
|---|---|
| Secret store unavailable at startup | Fail closed. Exit non-zero and let systemd back off. Never cache secrets to disk. Never start on a stale peer list, which would keep revoked peers alive. |
| `peers.yaml` malformed on reload | Parse and validate fully, then swap atomically. On any error keep the previous good config in memory and log loudly. A typo must neither revoke everyone nor widen access. |
| Service not in the peer's allowlist | Status `0x01`, connection closed, logged server-side as a security event with peer and requested name. |
| Backend unreachable | Status `0x02`, so the application distinguishes denial from an unhealthy backend. |
| Tunnel drops mid-session | Existing conns error out. No transparent per-connection reconnect, which would silently reorder or duplicate application bytes. The application retries via `Dial`. `persistent_keepalive_interval=25` keeps NAT bindings alive and detects death quickly. Amended in v0.2.0: it is applied only to a peer that has an endpoint, which is the client's peer, never the server's. A peer with no endpoint has nowhere to send a keepalive, so the timer only produces an ERROR line every few seconds; and the binding to keep open belongs to the side behind the NAT, which is the side that knows its peer's address. |
| Client changes network | Handled by WireGuard. The server updates the peer endpoint on the first valid authenticated packet from the new address. |
| Endpoint's address changes (v0.2.0) | Followed by the client, but only once something is already wrong. A `Dial` that cannot bring the tunnel up re-resolves a name endpoint once and moves the peer if the address changed. No lookup on a dial that succeeds, none ever for an IP literal, and a failed re-resolution fails the dial. See section 5. |
| Path MTU too small | Default MTU is 1280, the IPv6 minimum, not the usual 1420. A too-large MTU blackholes TCP silently and is the most common reason a userspace WireGuard setup appears hung. |
| Abusive authenticated peer | Per-peer caps on concurrent streams and dials per second, default deny beyond the cap, status `0x03`. |

## 9. Testing

1. Unit, table-driven: policy resolution `(peer, name) -> addr`. Cases must
   include unknown peer, unknown service, cross-peer access, and empty allow
   map.
2. Unit and fuzz: hello frame codec. Zero length, length exceeding the buffer,
   truncated, oversized, invalid charset, and a byte-at-a-time slow loris
   against the deadline. `go test -fuzz` on the parser.
3. Unit: secret reference parsing, including rejection of an unknown scheme and
   of a `file:` target with permissions looser than 0600.
4. Unit: config decode rejects unknown keys, and a malformed hot reload leaves
   the previous config in force.
5. Integration: a real tunnel in one process. Real wireguard-go client and
   server over localhost UDP, real netstack, real backend behind `httptest`.
   Bytes end to end.
6. Security tests that assert silence. These prove the threat model, so they
   are real tests:
   - Wrong client key: the handshake never completes and the server socket
     sends zero bytes back, verified by capturing on the UDP socket.
   - Correct key, wrong PSK: same, zero bytes.
   - Revoke a peer via hot reload while connected, then assert the next dial
     fails.
   - Peer A dialing peer B's service is denied.
   - A captured handshake initiation, replayed, is rejected.
7. CI: race detector on integration tests, plus `go vet`, `staticcheck`, and
   `govulncheck`.

## 10. Repository layout

```
gocloak/
  go.mod
  README.md
  client.go        Client, Dial, DialContext
  server.go        Server, accept loop, proxy
  device.go        wireguard-go and netstack bring-up, shared
  config.go        YAML types, validation, atomic hot reload
  policy.go        the policy engine
  wire.go          hello frame codec
  secret.go        SecretRef resolution, file: and env:, SecretResolver
  awssecrets/      nested module: aws:sm and aws:ssm, its own go.mod
  cmd/gocloak/     keygen, serve
  docs/
```

Every `.go` file above has a matching `_test.go`.

## 11. Dependencies, pinned

| Module | Version | Why |
|---|---|---|
| `golang.zx2c4.com/wireguard` | `v0.0.0-20260522210424-ecfc5a8d5446` | Noise IKpsk2 and the netstack TUN. Verified to accept `preshared_key`, to ship `cookie.go`, and to support `update_only` and `remove` for live revocation. |
| `gvisor.dev/gvisor` | `v0.0.0-20250503011706-39ed1f5ac29c` | Userspace TCP, pulled transitively by the above. |
| `github.com/aws/aws-sdk-go-v2` | latest at implementation | Secrets Manager and SSM. **Not a dependency of this module.** It lives in the nested `awssecrets` module and is pulled in only by programs that resolve `aws:` references. See 6.1. |
| `gopkg.in/yaml.v3` | latest at implementation | Config, used with `KnownFields(true)`. |
| `github.com/fsnotify/fsnotify` | latest at implementation | Peers file watching. |

Known trap: the standalone module `golang.zx2c4.com/wireguard/tun/netstack` is
stale, last published in 2022, and drags in a 2021 gVisor. The current package
lives inside `golang.zx2c4.com/wireguard`. Import that one.
