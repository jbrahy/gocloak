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

Everything runs in userspace: WireGuard
(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) via wireguard-go, and TCP via gVisor
netstack, both inside the process.

## Maturity: read this before you evaluate goCloak for real use

**This code has never been externally audited.** No security review by anyone
outside the project, no penetration test, no formal verification of any part of
it.

**It has no production deployment.** Nobody is running this in anger. There is
no operational track record, no uptime history, and no incident experience to
learn from.

**It has been exercised only on loopback and in one live local run.** The test
suite brings up real WireGuard tunnels and real netstack TCP, and it is
thorough, but every one of those runs is a single machine talking to itself.
goCloak has not been run across a real network, at scale, under load, behind a
real NAT, or against a real database.

What that does and does not mean. The cryptography is wireguard-go's,
unmodified, and that is a well-reviewed implementation of a well-reviewed
protocol. The code goCloak actually owns is the policy engine, the hello frame
parser, the config loader and the proxy, and those are the parts that carry the
risk of an unaudited project. Read them: they are deliberately small.

If you need a hardened, audited, battle-tested tunnel today, use one that is.
If you are evaluating goCloak, evaluate it as what it is: a carefully built,
carefully documented, entirely unproven piece of software.

## Documentation

| Document | What it is for |
|---|---|
| [docs/integration-guide.md](docs/integration-guide.md) | Using goCloak: install, keys, config, `database/sql` and `http.Transport`, the error model, operations, troubleshooting a handshake that never completes |
| [docs/implementation.md](docs/implementation.md) | Contributing to goCloak: the layers, a file by file tour, the path of one connection, the invariants |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to build, test, lint, and what the bar for a change is. Also how to report a vulnerability |
| [docs/superpowers/specs/2026-09-09-gocloak-design.md](docs/superpowers/specs/2026-09-09-gocloak-design.md) | The binding design spec: architecture, wire protocol, public API, threat model, failure handling |

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

There is no TUN device, no root, and no `CAP_NET_ADMIN`. goCloak itself writes
no cryptography and no transport: the security-critical code in this repository
is the policy engine and the hello frame parser, and both are small enough to
read in one sitting.

Each peer owns one address in `10.99.0.0/24`, pinned by WireGuard cryptokey
routing to its keypair. The server holds `10.99.0.1`, which caps a deployment
at 253 peers. Because a packet sourced from `10.99.0.7` provably came from the
keypair bound to that address, `RemoteAddr()` on the server is a
cryptographically enforced peer identity rather than a claim, and the policy
lookup keys off it.

The client never learns a backend address. It sends a service name over the
tunnel, the server resolves that name against this peer's allow map, and the
connection becomes a raw byte pipe. Backends move without touching any client.
Authorization is default deny: there is no wildcard, no CIDR and no port range,
and absence is denial.

## Quickstart

This runs a whole tunnel on one machine in about a minute: a backend, a server,
and a client that sends a message through it. Every command below was run as
written, with the one placeholder in step 3 replaced by what step 2 printed.

### 1. Build

```
git clone https://github.com/jbrahy/gocloak && cd gocloak
make build
```

That puts `gocloak`, `gocloak-sink` and `gocloak-send` in `bin/`.

### 2. Mint keys into a scratch directory

```
export DEMO=$(mktemp -d)
bin/gocloak keygen --name server --dir "$DEMO"
bin/gocloak keygen --name app-01 --dir "$DEMO"
```

```
peer: server
public_key: lv7sINDEP2auW5+l46h3aWpttdKaUQSDLudoIoTp6xg=
psk: gmUxI7nfYK8FdhohMU0cw14WMHG0YNMrwICg58yvA5o=
private key written to: /tmp/.../server.key
psk written to: /tmp/.../server.psk

peer: app-01
public_key: dT8xTJL1IthNgUwCuqLxblFAdmsHkI6WKh9+Gvwa4Qg=
psk: PHFcwgmV3FfO7YeCTtiDIVwvKm4qLOVu34hVBv/qcPk=
private key written to: /tmp/.../app-01.key
psk written to: /tmp/.../app-01.psk
```

Each run writes `<name>.key` and `<name>.psk` at mode 0600 and refuses to
overwrite an existing file. The private key is never printed, only the path it
was written to. The `psk:` line is the one place this tool ever prints a live
secret, so treat that terminal as sensitive.

`server.psk` is not used by anything: a PSK belongs to a peer relationship, and
the server takes each peer's PSK from `peers.yaml`.

### 3. Write the two config files

```
cat > "$DEMO/server.yaml" <<EOF
listen_port: 51820
private_key: file:$DEMO/server.key
tunnel_ip: 10.99.0.1
mtu: 1280
peers_file: $DEMO/peers.yaml
log_format: text
EOF
```

```
cat > "$DEMO/peers.yaml" <<EOF
peers:
  - name: app-01
    public_key: PASTE_THE_app-01_public_key_HERE
    psk: file:$DEMO/app-01.psk
    tunnel_ip: 10.99.0.7
    limits:
      max_concurrent: 32
      dials_per_second: 10
    allow:
      primary-db: 127.0.0.1:19000
EOF
```

`tunnel_ip` in `server.yaml` must be `10.99.0.1`. Every `allow` entry is one
service name granted to one literal `ip:port`: a hostname is rejected at load
time, because nothing in this project resolves names. An unrecognized key
anywhere in either file is a hard error, never a silent ignore.

In production, `private_key` and `psk` would be `aws:sm:` references rather
than `file:` ones. Those come from the separate
`github.com/jbrahy/gocloak/awssecrets` module, set as `Resolver` on the
config; the library itself resolves only `file:` and `env:`. See
[secret references](docs/integration-guide.md#72-secret-references).

### 4. Start a backend and the server

`gocloak-sink` is a plain TCP service. It is deliberately **not** a goCloak
peer: it speaks no tunnel protocol, and it stands in for the ordinary backend
in the diagram above. Start it on the address `peers.yaml` grants to
`primary-db`:

```
bin/gocloak-sink --listen 127.0.0.1:19000
```

```
gocloak-sink: listening on 127.0.0.1:19000 (plain TCP, not a goCloak peer)
```

In another terminal:

```
bin/gocloak serve --config "$DEMO/server.yaml"
```

```
level=INFO msg="gocloak: starting" config=/tmp/.../server.yaml
level=INFO msg="gocloak: server listening" listen_port=51820 tunnel_ip=10.99.0.1 mtu=1280 peers_file=/tmp/.../peers.yaml peers=1
```

The process opens exactly one port to the internet, the UDP `listen_port`. It
fails closed: an unreachable secret store, a malformed config or an unreadable
key at startup exits non-zero rather than starting degraded.

You will also see an ERROR line every few seconds for any peer that has not yet
connected: `Failed to send handshake initiation: no known endpoint for peer`.
That is a known, tracked defect in idle-peer logging, not a sign anything is
broken. It is [a good first contribution](CONTRIBUTING.md#1-the-idle-peer-handshake-log-storm).

### 5. Send a message through the tunnel

In a third terminal, with `--server-key` set to the server public key from
step 2:

```
bin/gocloak-send \
  --endpoint 127.0.0.1:51820 \
  --server-key lv7sINDEP2auW5+l46h3aWpttdKaUQSDLudoIoTp6xg= \
  --key file:"$DEMO"/app-01.key \
  --psk file:"$DEMO"/app-01.psk \
  --tunnel-ip 10.99.0.7 \
  --service primary-db \
  "hello from the tunnel"
```

```
sent 21 bytes, ack in 1ms
```

and the sink's terminal shows it arriving, with the source address inside the
tunnel:

```
2026-09-12T07:17:16-07:00 127.0.0.1:62278: hello from the tunnel
```

Asking for a service this peer was not granted fails with a distinct exit code
(`10`), so a script can tell it apart from the other failure classes that
`gocloak-send --help` documents:

```
bin/gocloak-send ... --service not-granted "this should be denied"
```

```
gocloak-send: denied: this peer's allow map does not grant this service
```

Clean up with `rm -rf "$DEMO"`. Those key files are real key material.

### 6. Dial from your own application

```go
// aws:sm: references need the separate awssecrets module wired in as a
// Resolver. A config that is all file: and env: needs neither the import
// nor the Resolver field, and links no AWS SDK.
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
```

`ServerPubKey` is pinned: it is the only key this client will complete a
handshake with. `MTU` and `DialTimeout` may be omitted and default to 1280 and
10 seconds. `Dial` blocks until the WireGuard handshake completes, so an
authentication failure surfaces on the first call rather than as a connection
that hangs later.

`(*Client).DialContext(ctx, network, addr)` has the standard dialer signature,
so a `*Client` drops straight into `http.Transport.DialContext` or any database
driver that accepts a dialer. Both are worked through in the
[integration guide](docs/integration-guide.md#5-using-the-connection).

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
| No key material at rest, with `aws:sm` and `aws:ssm` | Secrets Manager to memory. Nothing in EBS snapshots. CloudTrail records every read. This holds for the `aws:sm` and `aws:ssm` schemes, which come from the separate [`awssecrets`](awssecrets/) module. `gocloak keygen` writes the private key and PSK to disk at 0600, and the `file:` scheme reads key material from disk, so both leave key material at rest by design. |
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

And, above all of these, the maturity warning at the top of this document. An
unaudited implementation of a good design is still unaudited.

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
- **No cloud SDK in the library.** `file:` and `env:` are resolved with the
  standard library and nothing else; `aws:sm:` and `aws:ssm:` live in the
  nested [`awssecrets`](awssecrets/) module, so they are a dependency of the
  programs that use them and of nothing else. Measured on a program whose
  entire body is `gocloak.ValidServiceName("x")`: v0.1.0 linked 89 AWS
  packages, 358 packages in total, and built a 4.9 MB stripped binary. v0.2.0
  links 0 AWS packages, 205 in total, and builds a 3.4 MB stripped binary. The
  size is the visible part; the point is 89 packages of attack surface that
  nobody using a `file:` reference asked for.

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
exists. The client cannot narrow it down and will not pretend to. The
integration guide has
[a procedure for working through the six causes](docs/integration-guide.md#8-troubleshooting-a-handshake-that-never-completes).

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

## Operating it

The [integration guide](docs/integration-guide.md#7-operations) covers this in
full. The four things worth knowing before you start:

- **Revocation is an edit, not a restart.** `peers.yaml` is watched. Delete a
  peer, save, and it is removed from the live device and its in-flight
  connections are closed. A reload that fails to parse keeps the previous good
  config in force and logs loudly, so a typo neither revokes everyone nor
  widens access.
- **Secrets are references, never literals**: `file:` (refused above mode
  0600) and `env:` are resolved by the library itself. `aws:sm:` and `aws:ssm:`
  come from the separate [`awssecrets`](awssecrets/) module, set as `Resolver`
  on the config, so a deployment that does not use them does not link the AWS
  SDK. An unknown scheme is an error, never a fallback to treating the string
  as a literal key.
- **Rotation is not revocation, and rotation needs a restart.** Each reference
  is resolved once and cached for the process lifetime, so changing a secret in
  place under an unchanged reference is never picked up by a reload. Rotate by
  writing the new value under a new reference and pointing `peers.yaml` at it.
- **MTU defaults to 1280, not the usual 1420, and that is deliberate.** 1280 is
  the IPv6 minimum, the largest value guaranteed to cross any path. Too large
  an MTU blackholes TCP silently, which is the most common reason a userspace
  WireGuard setup appears hung rather than broken.

## Development

```
make test    # go test -race ./... , about 200 seconds
make lint    # go vet and staticcheck
make fuzz    # fuzz the hello frame parser
make vuln    # govulncheck
make build   # build gocloak, gocloak-sink and gocloak-send into bin/
```

`awssecrets/` is a separate Go module, so `./...` from the repository root
does not reach it. `make test` and `make lint` run it too; by hand it is
`cd awssecrets && go test -race ./...`.

`go test -run '^Example$' -v .` runs a real tunnel, a real server and a real
backend in one process, end to end, in about five seconds.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the bar a change has to meet, and
[docs/implementation.md](docs/implementation.md) for how the internals fit
together.

## Security

Please do not open a public issue for a vulnerability. See
[CONTRIBUTING.md](CONTRIBUTING.md#reporting-a-security-vulnerability).

## Licence

MIT. See [LICENSE](LICENSE). Copyright 2026 John Brahy.
