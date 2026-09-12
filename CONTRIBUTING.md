# Contributing to goCloak

Thanks for looking at this. goCloak is a small security library, and the bar
for a change is correspondingly high: the code is meant to be readable in one
sitting by someone deciding whether to trust it, and every addition spends some
of that budget.

Read [docs/implementation.md](docs/implementation.md) before you change
anything under `package gocloak`. It has the architecture, a file by file tour,
and the invariants checklist at the end. That checklist is the review criteria.

## Reporting a security vulnerability

**Do not open a public issue for a vulnerability.** Do not send a pull request
that fixes one either, because the diff is the disclosure.

Use GitHub's private vulnerability reporting, which is enabled on this
repository: go to the Security tab and choose "Report a vulnerability". That
opens a private advisory visible only to you and the maintainer, so nothing is
disclosed while the issue is being fixed.

Include:

- what the issue is, and which file and function it lives in;
- how to reproduce it, ideally as a failing test;
- what an attacker gets out of it.

You will get an acknowledgement. There is no bug bounty and no formal SLA: this
is a personal project, and pretending otherwise would be one more thing in this
repository that is not true.

Everything else, bugs, questions, feature discussion, belongs in a public issue.

## Build and test

```
go build ./...
make build          # gocloak, gocloak-sink and gocloak-send into bin/
make test           # go test -race ./...
make lint           # go vet ./... and staticcheck ./...
make vuln           # govulncheck ./...
make fuzz           # go test -fuzz=FuzzHelloFrame -fuzztime=60s .
gofmt -l .          # must print nothing
```

The full set a change has to pass, in the order worth running them:

```
go build ./...
go vet ./...
staticcheck ./...
gofmt -l .
go test -count=1 -race ./...
govulncheck ./...
```

`go test -race ./...` takes about 200 seconds. It is not hung. Most of that is
real WireGuard handshakes and real gVisor netstack TCP running in-process,
which is the point: the integration and threat-model tests are real tunnels,
not mocks.

If you do not have the linters:

```
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

Two faster loops while you work:

```
go test -run TestPolicy ./...        # or TestConfig, TestWire, TestSecret
go test -run '^Example$' -v .        # a real tunnel end to end, about 5s
```

Note that `-run` matches by substring, so a test whose name does not contain
the prefix the verification command uses is **silently skipped, not failed**.
Name new tests to match the file they belong to (`TestPolicy...`,
`TestServer...`, `TestSecurity...`).

## The bar for a change

**Tests that can actually fail.** A test that passes whether or not the code is
correct is worse than no test, because it manufactures evidence. For a bug fix,
write the test first and watch it fail. For a change to a security property,
prove non-vacuity: break the code deliberately, confirm the test fails, put it
back. Say in the pull request how you proved it. Several existing tests document
exactly this, and that is the standard.

**No test weakened, skipped or deleted** to make a change pass. If an existing
test is wrong, say so explicitly and argue it, rather than quietly loosening an
assertion.

**No new exported identifiers without a strong argument.** The public API is
fixed and listed in the invariants checklist in
[docs/implementation.md](docs/implementation.md). A caller wanting something is
not by itself an argument; the question is whether the whole surface is still
small enough to audit. New unexported helpers are fine.

**No new dependencies without a strong argument.** The dependency list is part
of the attack surface, and every direct dependency in `go.mod` today earns its
place.

**The fail-closed tie-breaker.** When two implementations are defensible,
choose the one that denies. When you cannot tell which way is safer, say so in
the pull request rather than picking silently. Several existing comments in
`server.go` and `config.go` exist purely to record which direction fails closed
and why; match that habit.

**Surgical diffs.** Change what the issue requires and no more. Do not reformat
adjacent code, do not "improve" comments you happened to read, and do not
refactor things that are not broken. If you spot unrelated dead code, mention
it rather than deleting it in the same change.

**Style: no em dashes and no emojis, anywhere.** Not in code, not in comments,
not in documentation, not in commit messages. The whole tree is consistent on
this and the consistency is the point. Use a comma, a colon or a sentence break.

**Comments explain why, not what.** The existing comments are dense and they
are load bearing: several of them record an ordering that a future edit would
otherwise silently break. If you change such a code path, change its comment in
the same commit.

## Good first contributions

These are real, currently open, and scoped small enough to finish. They come
from [docs/build-decisions.md](docs/build-decisions.md) and
[docs/final-review.md](docs/final-review.md), where the reasoning is recorded in
more detail.

### 1. The idle-peer handshake log storm

**The symptom.** A running server logs, at ERROR level, roughly every six
seconds for every peer that has not yet completed a handshake:

```
level=ERROR msg="gocloak: wireguard" message="peer(dT8x...a4Qg) - Failed to send handshake initiation: no known endpoint for peer"
```

A deployment with twenty peers that connect occasionally produces a continuous
stream of ERROR lines describing nothing wrong. It trains operators to ignore
the log, which is precisely the log this project tells them to read when a
handshake fails.

**The cause.** `devicePeer.ipcConfig` in `device.go` writes
`persistent_keepalive_interval=25` for every peer unconditionally. That is
correct for the client, whose peer is the server and whose endpoint is known at
configuration time. It is wrong for the server, whose peers have no endpoint at
all until the client speaks first: the keepalive timer fires, wireguard-go tries
to send, there is no endpoint, and it logs an error.

**The shape of a fix.** The keepalive belongs to the side that knows its peer's
endpoint. The narrow version is to emit the line only when `p.Endpoint` is set;
note that the server does learn a peer's endpoint after the first valid packet,
so consider whether the setting should be applied then, and check what
wireguard-go does with `persistent_keepalive_interval` on an `update_only`
call. Spec section 8.2 is the constraint to respect:
`persistent_keepalive_interval=25` is there to keep NAT bindings alive and to
detect a dead tunnel quickly, so do not simply delete it from the client path.

**Tests.** `device_test.go` already asserts on the rendered UAPI config;
add cases covering a peer with an endpoint and a peer without. A server-side
test asserting that no such ERROR line appears for an idle peer would be
stronger still.

### 2. `resolveFile` does not require a regular file

`secret.go`, `resolveFile`. `os.Open` succeeds on a directory, and a directory
at mode 0700 passes the `info.Mode().Perm()&0o077 != 0` permission check. The
failure only surfaces when `io.ReadAll` returns an opaque, platform-specific
error. The fix is one check after the `Stat` and before the permission check:

```go
if !info.Mode().IsRegular() {
	return secret{}, fmt.Errorf("secret: file:%s: is not a regular file", path)
}
```

with a test in `secret_test.go` pointing a `file:` reference at a directory.
This is recorded as finding M1 in `docs/final-review.md`.

### 3. Documentation that has drifted

The three docs in `docs/` that describe the build (`build-decisions.md`,
`final-review.md`, `residuals-closed.md`) are historical records and should stay
that way, but anything in `README.md`,
[docs/integration-guide.md](docs/integration-guide.md) or
[docs/implementation.md](docs/implementation.md) that does not match the code is
a bug worth a pull request. Verify against the source, never from memory: a
wrong flag in a public quickstart is worse than no quickstart.

### Larger, and worth discussing in an issue first

- **Swap `golang.org/x/crypto/curve25519` for the standard library's
  `crypto/ecdh`.** Four call sites (one in `cmd/gocloak/main.go`, three in
  tests), and `crypto/ecdh`'s `X25519().NewPrivateKey` handles clamping itself,
  which would also let `clampPrivateKey` go. It removes a direct dependency that
  is not in the design spec's pinned table. It also rewrites the code that mints
  every key in the system, so it needs a careful review and byte-for-byte
  verification that the derived public keys are unchanged.
- **`PeersConfig` is exported with no exported members.** `LoadPeersConfig`
  returns it so a caller must be able to name it, but there is nothing a caller
  can read. Whether that is the right shape is a genuine API design question,
  not a bug; it is flagged in `docs/residuals-closed.md`.

## Pull requests

- One logical change per pull request.
- Say what you changed, why, and how you verified it. Paste the real output of
  the verification commands rather than asserting that they passed.
- If you touched a security property or a test that proves one, say how you
  proved the test still fails when the property is broken.
- Expect review to focus on the invariants checklist first and the code second.
