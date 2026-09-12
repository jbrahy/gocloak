# Decoupling the core module from AWS (v0.2.0)

## What changed, in one line

The `aws:sm:` and `aws:ssm:` secret schemes moved out of the core `gocloak`
module into a nested module, `github.com/jbrahy/gocloak/awssecrets`, and the
core module now resolves `file:` and `env:` itself and delegates every other
scheme to a caller-supplied `SecretResolver`.

## Why

`secretResolver.Resolve` switched on the scheme at runtime. A runtime switch
makes every branch reachable from any use of the package, so every branch
links. A program whose entire body was `gocloak.ValidServiceName("x")` linked
the whole AWS SDK.

That is a supply-chain problem wearing a binary-size costume. Someone keeping
key material in a `file:` or `env:` reference paid for Secrets Manager and SSM
in dependency count, download size and audit surface, and never found out why.
For a library whose reason to exist is a small auditable attack surface, 89
packages nobody asked for is worse than the megabytes.

A subpackage inside the core module would not have fixed it. `go.mod` and
`go.sum` would still carry `aws-sdk-go-v2`, `go mod download` would still
fetch it, and an audit of the core module would still have to cover it. The
requirement was zero AWS packages in the core dependency graph, absent rather
than merely unlinked, and only a separate module with its own `go.mod`
achieves that.

## The measurement

Method: a throwaway module outside the repository, whose entire body is
`gocloak.ValidServiceName("x")`, with a `replace` onto the working tree.

```go
package main

import "github.com/jbrahy/gocloak"

func main() {
	gocloak.ValidServiceName("x")
}
```

```
go list -deps . | wc -l
go list -deps . | grep -c aws
go build -o probe .
go build -ldflags="-s -w" -o probe-stripped .
```

| Measurement | v0.1.0 (before) | v0.2.0 (after) | Change |
|---|---|---|---|
| AWS packages in the graph (`go list -deps . \| grep -c aws`) | 89 | 0 | -89 |
| Total packages (`go list -deps . \| wc -l`) | 358 | 205 | -153 |
| Binary, unstripped | 7,131,218 bytes (7.1 MB) | 4,900,610 bytes (4.9 MB) | -2,230,608 bytes, -31% |
| Binary, stripped (`-ldflags="-s -w"`) | 4,948,530 bytes (4.9 MB) | 3,409,586 bytes (3.4 MB) | -1,538,944 bytes, -31% |

Dependency graph by group, before: aws 89, gvisor 42, wireguard 9. AWS was
larger than gvisor and wireguard-go combined. After: aws 0, gvisor 42,
wireguard 9, both unchanged, which is the point. Nothing else moved.

`grep -rn 'aws' go.mod` and `grep -n 'aws' go.sum` in the core module both
return nothing.

## The design

### Core keeps two schemes

`file:<path>` and `env:<VAR>`, resolved with the standard library and nothing
else. Behaviour is byte for byte what it was, including `file:` refusing any
file whose mode is looser than 0600, checked against the same open handle as
the read so the file cannot be swapped between the check and the read.

### One new exported interface

```go
// SecretResolver resolves a scheme that the core library does not
// implement. Returning an error for an unrecognised scheme is correct.
type SecretResolver interface {
	ResolveSecret(ctx context.Context, ref SecretRef) ([]byte, error)
}
```

It returns a plain `[]byte` rather than the unexported `secret` type, because
an external module has to be able to implement it. The core wraps the bytes in
`secret` the moment they arrive, so the redaction guarantees (`String` and
`GoString` both return `[REDACTED]`) hold everywhere internally. No error the
core produces on this path formats the value: it names the scheme and nothing
more.

### Two new config fields, wired explicitly

```go
Resolver SecretResolver   // optional; nil means file: and env: only
```

on both `ClientConfig` and `ServerConfig`. A nil `Resolver` behaves exactly as
before for `file:` and `env:`.

A `database/sql`-style global `Register` was considered and rejected. Global
mutable state in a security library means any imported package can silently
install a secret resolver; whoever builds the config should be the one who
decides where key material comes from. Explicit beats action at a distance
here.

### Resolution order

1. `file:` or `env:`: resolved by the core, and a `Resolver` is **never**
   consulted, so a `Resolver` can add schemes but can never take those two
   over.
2. Any other scheme: delegated to the `Resolver` if there is one.
3. Otherwise: an error naming the two schemes the core supports and saying
   which module provides the AWS ones. It does not echo the reference's
   payload, which may be a pasted secret.

### Parsing became shape-checking

`parseSecretRef` used to hold an allowlist of four scheme names. It now checks
shape only: an RFC 3986-shaped lowercase scheme, a colon, and a non-empty
payload.

It had to. Config decoding happens long before a `Resolver` is in sight, so a
`peers.yaml` naming a scheme the core does not implement has to decode, or the
interface would be useless for anything but schemes the core already knows.
Shape is still enough for the mistake `SecretRef` exists to catch: a literal
key pasted where a reference belongs is base64 or hex, and neither alphabet
contains a colon.

The coverage this moved rather than deleted is in
`TestConfigSecretRefUnknownSchemeDecodesAndFailsAtResolution`: `vault:secret/x`
now decodes and is refused at resolution, and at neither layer is it treated
as a literal key.

### One redaction improvement, forced by the above

`scrubRef` used to scrub the whole reference plus the payload that
`parseSecretRef` returned. With a generic parse, `aws:sm:gocloak/server/private`
has the payload `sm:gocloak/server/private`, which would have left the bare
`gocloak/server/private` in a message. It now scrubs every suffix after every
colon, which is a strict superset of what it scrubbed before.

## The nested module

```
awssecrets/
  go.mod              module github.com/jbrahy/gocloak/awssecrets
  awssecrets.go       Resolver, New, aws:sm and aws:ssm
  awssecrets_test.go  unit tests against fake AWS clients
  integration_test.go wires a Resolver into a real gocloak.ClientConfig
  README.md           why it is a separate module
```

`New(ctx) (*Resolver, error)` builds real clients from the ambient AWS region
and credentials. `*Resolver` satisfies `gocloak.SecretResolver`, asserted at
compile time by `var _ gocloak.SecretResolver = (*Resolver)(nil)`.

Behaviour of the two schemes is unchanged, `WithDecryption` on every SSM read
included, and that one is pinned by its own test because it is invisible in
the result and fatal to get wrong: without it a `SecureString` comes back as
ciphertext, is accepted as key material, and fails later as an unexplained
handshake failure.

`go.mod` carries `replace github.com/jbrahy/gocloak => ../` so the module
builds against the working tree. A `replace` in a dependency module is ignored
by anything that depends on it, so this affects builds of this module only.

## What is breaking

An `aws:sm:` or `aws:ssm:` reference that worked in v0.1.0 now fails at
startup unless the program imports `awssecrets` and sets `Resolver`. The error
names the module to import. This is deliberate: a fallback that linked AWS
anyway would defeat the entire change. Pre-1.0, shipped as v0.2.0.

Migration is two lines:

```go
resolver, err := awssecrets.New(ctx)   // + the import
// ...
cfg.Resolver = resolver
```

Note that `cmd/gocloak` lives in the core module and therefore resolves
`file:` and `env:` only. Wiring `awssecrets` into it would put the AWS SDK
back into the core module's `go.mod`, which is the thing this change exists to
prevent.

## Verification

Core module:

| Check | Result |
|---|---|
| `grep -rn 'aws' go.mod` | no matches |
| `grep -n 'aws' go.sum` | no matches |
| `grep -rn '"github.com/aws' --include='*.go' .` | matches inside `awssecrets/` only |
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `staticcheck ./...` | clean |
| `gofmt -l .` | empty |
| `go test -count=1 -race ./...` | ok, 196.1s for the root package, all packages pass |

Nested module, from `awssecrets/`:

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `staticcheck ./...` | clean |
| `gofmt -l .` | empty |
| `go test -count=1 -race ./...` | ok, 2.1s, 8 tests pass |

The headline proof is the table under [The measurement](#the-measurement).

## Test coverage added or moved

Core, `secret_test.go`:

- delegation to a supplied `Resolver` for `aws:sm:`, `aws:ssm:` and a
  third-party `vault:` scheme
- every one of those with no `Resolver`, which must be an error
- `file:` and `env:` with a `Resolver` installed that fails the test if it is
  ever consulted
- the unknown-scheme error naming `file:`, `env:`, `Resolver` and
  `awssecrets`, and not echoing the payload
- a `Resolver` returning both a value and an error: the value must not reach
  the error string and must not be used
- a `Resolver` returning an empty value: an error
- a delegated value renders as `[REDACTED]` through `%v` and `%#v`
- the unchanged cases: 0600 enforcement, redaction, and that an unknown scheme
  is never treated as a literal

Core, elsewhere:

- `client_test.go`: a whole client comes up on key material that arrived
  through `ClientConfig.Resolver`; the same config without one fails closed
  with an error naming the private key and the need for a `Resolver`
- `server_test.go`: `Run` builds its resolver from `ServerConfig.Resolver`,
  proved by `errors.Is` on the resolver's own error surviving to `Run`'s
  return, and fails closed without one
- `config_test.go`: the moved unknown-scheme coverage described above

`awssecrets/`: both schemes against fake clients, `SecretBinary`, backend
errors, empty responses, `WithDecryption`, malformed references, a zero
`Resolver`, an error that names the reference but never the value, and the
end-to-end wiring into `gocloak.ClientConfig`.

No test was weakened, skipped or deleted.

## Documentation updated

- `docs/superpowers/specs/2026-09-09-gocloak-design.md`: section 6.1 rewritten
  with the split, the reasoning and the numbers; the dependency table marks
  `aws-sdk-go-v2` as not a dependency of this module; the repository layout
  lists `awssecrets/`
- `docs/integration-guide.md`: section 7.2 rewritten with the interface, the
  wiring and `go get`; the client example shows the import and the `Resolver`
  field
- `README.md`: the client example, the secret-reference bullet, the security
  table row, a deliberate-omissions bullet carrying the before and after
  numbers, and a note that `awssecrets/` is a separate module for testing
- `docs/implementation.md`: the `secret.go` tour and the test inventory
- `CONTRIBUTING.md`: the separate module in the verification commands, and a
  rule that a secret store's SDK is never a core dependency
- `awssecrets/README.md`: new, why it is a separate module
- `Makefile`: `test`, `lint` and `vuln` now cover both modules

## Out of scope, deliberately

The keepalive behaviour in `device.go` and the endpoint-resolution behaviour
in `client.go` are both real and both being fixed in a separate change. This
diff is the AWS decoupling and nothing else.
