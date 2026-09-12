# Release preparation for the first public open-source release

Date: 2026-09-12
Target: `github.com/jbrahy/gocloak`, first public release.

Scope of this pass: scrub an internal address out of the whole tree, add the
licence, and write the documentation a stranger needs in order to both use
goCloak and contribute to it. No `.go` file was changed except for the address
scrub. No dependency was added. Nothing new was exported. No test was weakened,
skipped or deleted.

## 1. Address scrub

Four real addresses from the owner's internal network, one of them a live
production database, had leaked into the design spec, the README and three test
files when the spec was written. Every occurrence of every address on that
internal RFC 1918 prefix was replaced with an RFC 5737 TEST-NET-1 documentation
address, which can never be a real host.

| Was | Now |
|---|---|
| the production database address | `192.0.2.10` |
| internal address 2 | `192.0.2.11` |
| internal address 3 | `192.0.2.12` |
| internal address 4 | `192.0.2.13` |

Those four were the only addresses on that prefix anywhere in the tree, so no
further mapping was needed. The originals are deliberately not written out
here: this document is going public with the repository, and repeating them
would undo the scrub it is reporting.

Files touched: `policy_test.go`, `config_test.go`, `device_test.go`,
`README.md`, `docs/example-apps-report.md`,
`docs/superpowers/specs/2026-09-09-gocloak-design.md`.

`10.99.0.0/24` was left untouched throughout: it is the documented tunnel
subnet and is correct.

The addresses are arbitrary fixtures in every test that used them, so the swap
changes no behaviour. The full race suite passes after it (section 6).

A recursive grep of the whole tree for that internal prefix, tests, docs and
spec included, now matches nothing and exits 1.

## 2. Licence

`LICENSE` added at the repository root: the canonical MIT text, copyright
"2026 John Brahy". The README states the licence and links to the file.

## 3. Files created

| File | For whom |
|---|---|
| `LICENSE` | MIT, 2026 John Brahy |
| `docs/integration-guide.md` | people using goCloak |
| `docs/implementation.md` | people contributing to goCloak |
| `CONTRIBUTING.md` | how to build, test, lint, and what the bar for a change is |
| `docs/release-prep-report.md` | this report |

`README.md` was restructured as a public project front page.

### `docs/integration-guide.md`

Install, the mental model in four sentences, what each keygen artifact is for
(including that `keygen --name server` produces a `.psk` nothing consumes), a
complete worked example with every YAML key and every CLI flag tabulated, using
the connection with `http.Transport` and `database/sql`, the full error model
with an operator action for each sentinel, operations (revocation without a
restart, the four secret reference schemes, why MTU is 1280, why rotation needs
a restart and revocation does not, the per-peer limits), and a troubleshooting
section that works through all six causes of a handshake that never completes.

It states explicitly that `ErrHandshakeTimeout` is deliberately ambiguous per
spec 8.1 and that the server log is the only place the answer exists.

Every flag, every YAML key and every default in it was read out of the source,
not written from memory. The three Go snippets in it were compiled against the
real public API in a scratch module before being published, and the
`database/sql` example was checked against `go doc` for
`github.com/go-sql-driver/mysql` v1.10.1 rather than recalled:
`RegisterDialContext(net string, dial DialContextFunc)` with
`DialContextFunc = func(ctx context.Context, addr string) (net.Conn, error)`.

### `docs/implementation.md`

The layers and why each one exists (wireguard-go for Noise, gVisor netstack for
TCP, why userspace rather than a TUN device, why netstack does not forward), a
file by file tour saying what each file owns and what it must not know about,
the full path of one connection from UDP arrival to backend bytes with the
functions named, the peer-identity invariant and why nothing the client sends
may influence it, the hot reload and revocation ordering and why it fails
closed in both directions, the shutdown ordering and the netstack `Close` race
that produced it, the testing strategy including the five threat-model tests and
what each proves, and a checklist of the invariants a contributor must not
break.

It notes that `go test -race ./...` takes about 200 seconds, which matches this
run.

### `CONTRIBUTING.md`

Build, test and lint commands, including the `-run` substring-matching trap
that silently skips a mis-named test. The bar for a change: tests that can
actually fail and are proved non-vacuous, no new exported identifiers without a
strong argument, no new dependencies, the fail-closed tie-breaker, surgical
diffs, and the no em dashes and no emojis style rule.

Security reporting says plainly not to open a public issue for a vulnerability
and not to send a pull request that fixes one, and points at
GitHub private vulnerability reporting (resolved after this report; it was briefly a placeholder rather than
an invented address.

Good first contributions, all drawn from genuinely open items:

1. **The idle-peer handshake log storm.** `devicePeer.ipcConfig` in `device.go`
   writes `persistent_keepalive_interval=25` for every peer unconditionally.
   That is right for the client, whose peer's endpoint is known at
   configuration time, and wrong for the server, whose peers have no endpoint
   until the client speaks. The result is an ERROR line roughly every six
   seconds per idle peer: `Failed to send handshake initiation: no known
   endpoint for peer`. Reproduced in this session's own live run. The write-up
   names the cause, the shape of a fix, the spec 8.2 constraint to respect, and
   where the tests go.
2. **`resolveFile` does not require a regular file** (`secret.go`), which is
   finding M1 in `docs/final-review.md` and is still open. One check plus one
   test.
3. **Documentation drift** in the three living documents.

Plus two larger items flagged for discussion first: the
`golang.org/x/crypto/curve25519` to `crypto/ecdh` swap, and the `PeersConfig`
shape question left open in `docs/residuals-closed.md`.

### `README.md`

Restructured as a front page. What survives from the old one, unchanged in
substance: the opening paragraph, the architecture diagram, the security
properties table, the whole "What goCloak does not protect against" list, the
deliberate omissions, the "Authentication failure is indistinguishable from a
dead endpoint" section with the real error text and the sentinel table.

What is new:

- **A maturity warning immediately after the opening paragraph**, before
  anything else. It says in three bolded sentences that the code has never been
  externally audited, has no production deployment, and has been exercised only
  on loopback and one live local run, and it says what that does and does not
  mean. Nobody evaluating goCloak has to dig for it.
- A documentation table linking the integration guide, the implementation
  guide, CONTRIBUTING and the design spec.
- A quickstart that was run start to finish exactly as written (section 7).
- A licence section.

The "does not protect against" list is no less prominent than the properties
table: it sits directly after it, at the same heading level, and it now closes
by pointing back at the maturity warning.

## 4. SHA references reworded

A history rewrite after this pass will invalidate every short SHA in the build
documents, so each was replaced with a description of what it was. The
substance is unchanged; only the now-meaningless identifiers are gone.

| File | Was | Now |
|---|---|---|
| `docs/final-review.md` | "Reviewed at commit e9649bd, the tip of the former `build/gocloak-v1`" | "Reviewed at the tip of the former `build/gocloak-v1` branch, the commit that recorded the build's decisions and open items" |
| `docs/build-decisions.md` | "corrected in commit a2220c2" | "corrected in the task 10 fix round" |
| `docs/build-decisions.md` | "Fixed in commit 6a9fec9" | "Fixed in the task 7 fix round" |
| `docs/build-decisions.md` | "implemented DONE (commit 0ccbb84)" | "implemented DONE" |
| `docs/build-decisions.md` | "implemented DONE (commit b30e6e0)" | "implemented DONE" |
| `docs/build-decisions.md` | "fix round 2/5 applied (commit 8958950)" | "fix round 2/5 applied" |
| `docs/build-decisions.md` | "fix round 1/5 applied (commit 1870970)" | "fix round 1/5 applied" |
| `docs/build-decisions.md` | "fix round 1/5 applied (commit 0a371c4)" | "fix round 1/5 applied" |

`docs/residuals-closed.md` and `docs/example-apps-report.md` name no SHA, so
neither needed an edit for this.

## 5. Style: em dashes and emojis

`docs/final-review.md` finding M4 recorded six em dashes in
`docs/build-decisions.md`, and they were still there. They are gone now,
replaced by a colon or a sentence break, which was possible in the same pass
that reworded the SHAs because five of the six were on those exact lines.

The whole tree is now clean of every dash in the U+2012 to U+2015 range and
U+2212, and of every emoji, pictograph, dingbat and arrow. In fact it contains
no non-ASCII byte at all:

```
$ grep -rnP '[^\x00-\x7F]' --include='*' . | grep -v '\.git/'
$ echo $?
1
```

## 6. Verification, real output

All run in the foreground, in this order, after every change above.

```
$ grep -rn <internal prefix> .
(no output, exit 1)

$ go build ./...
(no output, exit 0)

$ go vet ./...
(no output, exit 0)

$ staticcheck ./...
(no output, exit 0)

$ gofmt -l .
(no output)

$ go test -count=1 -race ./...
ok  	github.com/jbrahy/gocloak	201.022s
ok  	github.com/jbrahy/gocloak/cmd/gocloak	2.940s
ok  	github.com/jbrahy/gocloak/cmd/gocloak-send	2.374s
?   	github.com/jbrahy/gocloak/cmd/gocloak-sink	[no test files]
ok  	github.com/jbrahy/gocloak/internal/msg	1.575s

(3:22.68 total wall clock)
```

Also run, though not on the required list:

```
$ govulncheck ./...
Your code is affected by 0 vulnerabilities.
This scan also found 1 vulnerability in packages you import and 17
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
```

## 7. The quickstart, run exactly as written

Run from a clean checkout state with `make build`, into a `mktemp -d`
directory, with the demo keys deleted afterwards. Long temp paths are
abbreviated below; nothing else is edited.

```
$ export DEMO=$(mktemp -d)

$ bin/gocloak keygen --name server --dir "$DEMO"
peer: server
public_key: khkEwHd+kYccymxA7U3zeeczQh8W5Zu/LXQ9hTSDtCg=
psk: NscthSnEgdZl7O4j8TBDBcMZBx2503Lhu5iiRHCW/Hg=
private key written to: /var/folders/.../tmp.Tpt2u3AsoG/server.key
psk written to: /var/folders/.../tmp.Tpt2u3AsoG/server.psk

$ bin/gocloak keygen --name app-01 --dir "$DEMO"
peer: app-01
public_key: NQ6oMAjRbCaiqtZKUSFjZ+9GoAx+v+u2D+JEMM5lcws=
psk: LqVV/SObSlZ9NLmf1XildxTB7ux4yX21yQoISW4PLPE=
private key written to: /var/folders/.../tmp.Tpt2u3AsoG/app-01.key
psk written to: /var/folders/.../tmp.Tpt2u3AsoG/app-01.psk

# server.yaml and peers.yaml written with the heredocs from the README,
# with app-01's public_key pasted in.

$ bin/gocloak-sink --listen 127.0.0.1:19000
gocloak-sink: listening on 127.0.0.1:19000 (plain TCP, not a goCloak peer)

$ bin/gocloak serve --config "$DEMO/server.yaml"
level=INFO msg="gocloak: starting" config=/var/folders/.../server.yaml
level=INFO msg="gocloak: server listening" listen_port=51820 tunnel_ip=10.99.0.1 mtu=1280 peers_file=/var/folders/.../peers.yaml peers=1

$ bin/gocloak-send \
    --endpoint 127.0.0.1:51820 \
    --server-key khkEwHd+kYccymxA7U3zeeczQh8W5Zu/LXQ9hTSDtCg= \
    --key file:"$DEMO"/app-01.key \
    --psk file:"$DEMO"/app-01.psk \
    --tunnel-ip 10.99.0.7 \
    --service primary-db \
    "hello from the tunnel"
sent 21 bytes, ack in 2ms
exit=0

# the sink's terminal:
2026-09-12T07:31:25-07:00 127.0.0.1:62869: hello from the tunnel

$ bin/gocloak-send ... --service not-granted "this should be denied"
gocloak-send: denied: this peer's allow map does not grant this service
exit=10

# the server's log for that dial:
level=WARN msg="gocloak: service denied" peer=app-01 service=not-granted status=denied duration_ms=0

$ rm -rf "$DEMO"
```

The quickstart worked as written, so no correction to the README was needed on
that account.

The keys above were minted for this run, into a temp directory, and that
directory was deleted. They are published here because they are dead, and
because a transcript with the key material redacted would not be a transcript
of anything runnable.

### Two things the same run also verified

**Revocation without a restart**, from an earlier identical run with the server
left up throughout. Replacing `peers.yaml` with `peers: []` produced, with no
restart:

```
level=INFO msg="gocloak: connection closed" peer=app-01 service=primary-db status=ok bytes_sent=7 bytes_received=22 duration_ms=8802
level=WARN msg="gocloak: peer revoked" peer=app-01
level=INFO msg="gocloak: peers file reloaded" path=.../peers.yaml peers=0 added=[] removed=[app-01] changed=[]
```

and the next dial from that peer timed out after 10s with the full
`ErrHandshakeTimeout` text and exit code 13, which is correct: a revoked peer
must be indistinguishable from a dead endpoint.

**The idle-peer log storm**, the good first contribution in CONTRIBUTING.md:

```
level=ERROR msg="gocloak: wireguard" message="peer(dT8x...a4Qg) - Failed to send handshake initiation: no known endpoint for peer"
```

logged at 07:17:04, 07:17:09 and 07:17:14 before the peer had spoken at all,
which is the roughly six second cadence the bug report describes.

## 8. What could not be verified

- **Nothing about performance.** No throughput, latency or concurrency
  measurement was taken, and none is claimed anywhere in the new documentation.
- **Nothing across a real network.** Every run in this session was loopback on
  one machine. That is exactly why the README's maturity section says so.
- **The security contact address.** `CONTRIBUTING.md` carries the placeholder
  GitHub private vulnerability reporting, resolved after this report. Originally a placeholder rather than an invented address; the owner had to
  fill this in before the repository is made public, otherwise a reporter has
  nowhere to send a vulnerability and the instruction not to file a public
  issue becomes an instruction to do nothing.
- **The clone URL in the README quickstart** (`git clone
  https://github.com/jbrahy/gocloak`) could not be exercised, because the
  repository is not published yet. Every other command in that quickstart was
  run.
- **`go get github.com/jbrahy/gocloak`** is likewise unexercised for the same
  reason. The library snippets were compiled against the local module through a
  `replace` directive instead.

## 9. Owner checklist before making the repository public

1. RESOLVED: vulnerability reports now route through GitHub private advisories.
2. Confirm the address scrub is complete to your own satisfaction. Grepping
   the working tree for the internal prefix prints nothing, but grepping
   `git log -p` for it still matches 68 lines, because this pass changed the
   working tree and not the history. **If the history rewrite you have planned
   does not remove those addresses from every earlier commit, they are
   published the moment the repository is.** The working-tree scrub alone is
   not sufficient.
3. Re-read the maturity section and confirm it says what you want it to say. It
   is deliberately blunt.
