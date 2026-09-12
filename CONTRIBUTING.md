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

`awssecrets/` is a **separate Go module**, so `./...` from the repository root
does not include it. `make test`, `make lint` and `make vuln` cover both; run
the same set again inside `awssecrets/` if you are working there.

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

**A secret store's SDK is never a core dependency.** The core module resolves
`file:` and `env:` with the standard library, and every other scheme comes
from a caller-supplied `gocloak.SecretResolver`. Support for a new store is a
nested module alongside `awssecrets/`, with its own `go.mod`, never a package
inside the core module: a subpackage would put the SDK back in the core
`go.mod` and `go.sum`, where every consumer downloads it and every audit has
to cover it. See section 6.1 of the design spec for the measurements that
motivated this.

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

### 1. `deviceLogVerbose` is defined and nothing outside the tests uses it

**What it is.** `device.go` defines three log levels, `deviceLogSilent`,
`deviceLogError` and `deviceLogVerbose`, as named mirrors of wireguard-go's
own constants so a caller does not have to import
`golang.zx2c4.com/wireguard/device` to pick one. The client and the server
both run at `deviceLogError`. `deviceLogVerbose` is referenced only from
`device_test.go`, twice.

**Why it is worth closing.** The build's constraint 5 is "prefer deleting code
over adding a flag", and an identifier that exists only because its neighbours
do is the mildest possible version of the thing that constraint is about. It
is recorded as finding M3 in [docs/final-review.md](docs/final-review.md),
which also makes the argument for the other side: the constant is
self-documenting next to the two that are used, and deleting it leaves a gap
in an enumeration. Both readings are defensible, which is why this is a
contribution and not a bug.

**The trap.** The obvious way to make an unused constant used is to add a
configuration knob that selects the log level, and that is the wrong fix here.
Every knob is a way to be deployed insecurely, and this particular one turns on
a log stream from a dependency, in a library whose logging rules are absolute.
It is not that verbose output leaks key material; it does not, and
`TestDeviceVerboseLogNeverLeaksKeyMaterial` is there to keep it that way. It is
that "an identifier is unused" is not an argument for new configuration. If you
believe the knob is right anyway, open an issue and make that case first.

**The shape of a fix.** Delete `deviceLogVerbose` and point the two test
references at `device.LogLevelVerbose` directly, which `device_test.go` already
imports. `TestDeviceVerboseLogNeverLeaksKeyMaterial` must still run the device
at the verbose level afterwards, because that test is the reason anyone can be
relaxed about wireguard-go's logging at all. Fix the comment on
`deviceOptions.LogLevel`, which lists all three names, in the same commit.

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
