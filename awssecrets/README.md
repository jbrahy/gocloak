# awssecrets

AWS secret resolution for [goCloak](https://github.com/jbrahy/gocloak): the
`aws:sm:<secret-id>` and `aws:ssm:<parameter>` reference schemes.

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
	ListenPort: 51820,
	PrivateKey: "aws:sm:gocloak/server/private",
	TunnelIP:   netip.MustParseAddr("10.99.0.1"),
	PeersFile:  "/etc/gocloak/peers.yaml",
	Resolver:   resolver,
})
```

The same field exists on `gocloak.ClientConfig`. `New` builds its clients from
the ambient AWS region and credentials. `aws:ssm:` is always read with
`WithDecryption`, so a `SecureString` parameter comes back as plaintext.

## Why this is a separate module, not a package

Resolution used to switch on the scheme inside the core `gocloak` package. A
runtime switch makes every branch reachable, so every branch links: a program
whose entire body was `gocloak.ValidServiceName("x")` pulled in 89 AWS
packages and produced a 4.9 MB stripped binary. Anyone keeping key material in
a `file:` or `env:` reference paid for Secrets Manager and SSM in binary size,
dependency count and supply-chain exposure, and never found out why.

A package inside the core module would not have fixed that. `go.mod` and
`go.sum` would still carry `aws-sdk-go-v2`, `go mod download` would still
fetch it, and an audit of the core module would still have to cover it. Only a
separate module takes AWS out of the core dependency graph. The same program
now links 0 AWS packages, 205 packages in total rather than 358, and builds to
3.4 MB stripped.

So the cost of AWS support falls on the programs that use AWS. For a library
whose reason to exist is a small auditable attack surface, that is the only
defensible place to put it.

## Tests

The tests use fake Secrets Manager and SSM clients, so they need no AWS
credentials and no network:

```
go test -race ./...
```

`integration_test.go` goes further and wires a `Resolver` built on a fake
client into a real `gocloak.ClientConfig`, proving this module satisfies the
interface the core module declares and that the core module actually delegates
to it.
