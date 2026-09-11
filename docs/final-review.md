# goCloak final review

Date: 2026-09-10
Reviewed at commit e9649bd, the tip of the former `build/gocloak-v1`.
Reviewer had no prior context on the build: independent eyes on the finished product.

Repository state at the time of writing: the branch was fast-forward merged into `main`
on the owner's instruction while this review was in progress. `build/gocloak-v1` no
longer exists as a ref. There is no remote and nothing has been pushed, so every fix
below goes on a new branch off `main`. The merge does not change any finding in this
document; the pre-merge / post-merge language below means "before or after the fixes
land", not "before or after that merge".

Verification state taken as given, not re-run:
`go build`, `go vet`, `staticcheck`, `govulncheck`, `gofmt -l` all clean;
`go test -race ./...` passing at 245s + 3.1s; `FuzzHelloFrame` 1,333,333 execs, no crash.

---

## 1. Verdict

**Ready with fixes.**

No Critical findings. The assembled security core is sound. I traced a connection from
arrival through to the backend and found no path where anything the client sends
influences the authorization key, and no revocation ordering in which a revoked peer is
granted access. Four small fixes should land before this is treated as done, two of them
in production code and two in tests.

### Ordered pre-merge fix list

1. `client.go:481`: round the handshake-timeout duration to 100ms, not 1ms.
2. `config.go:765`: make `PeerWatcher.Reload` invoke the reload callback, or unexport it.
3. `README.md:234`: qualify the "No key material at rest" row.
4. `server.go:557`: one sentence in the `refreshPeers` comment (parked residual 3).

Test-only, same pass:

5. `server_test.go:174`: retry the port pick on bind failure.
6. `security_test.go:300` and `:310`: invert the 4s / 5s deadline pair.

---

## 2. Findings

### Critical

**None.** This class is empty.

Specifically ruled out by tracing the real code:

- The authorization key cannot be confused, substituted or spoofed. `handleConn` derives
  the peer identity from `conn.RemoteAddr()` via `remoteTunnelIP` (`server.go:498`), which
  is cryptokey-routed and normalized with `Unmap()`. `Policy.Resolve` (`policy.go:88`)
  unmaps identically, so the two spellings of an address cannot diverge. The service name
  from the hello frame only selects a key *within* that peer's own allow map; it can never
  reach another peer's map.
- No peer-to-peer path exists inside the tunnel. The netstack instance
  (`tun/netstack/tun.go` in the pinned wireguard-go) calls neither `SetForwarding` nor
  `SetSpoofing` nor `SetPromiscuousMode`, and holds one address, so a packet a peer
  addresses to another peer's tunnel IP is dropped rather than forwarded.
- No secret reaches a log or an error on any path I could find. Key material enters only
  the UAPI config strings at `device.go:155` and `device.go:254`, which are never logged.
  wireguard-go's own key parse errors (`device/noise-types.go:27-80`) never echo the
  value. `scrubRef` (`server.go:817`) removes both the reference and its payload before
  an error can reach a log line, and deliberately over-redacts.
- Revocation is reported honestly. `applyDiff` (`server.go:665`) collects every error
  rather than swallowing it, logs `PEER REVOCATION FAILED` on a removal error, and
  `handleReload` logs "reloaded but NOT fully applied" rather than success when
  `applyErr != nil`.

### Important

#### I1. `client.go:481` and `client_test.go:385`: the handshake-timeout duration varies at 1ms resolution

`handshakeBound`:

```go
func handshakeBound(budget context.Context, start time.Time) time.Duration {
	if deadline, ok := budget.Deadline(); ok {
		return deadline.Sub(start).Round(time.Millisecond)   // :481, always taken from Dial
	}
	return time.Since(start).Round(100 * time.Millisecond)   // :484, unreachable from Dial
}
```

`Dial` always constructs `budget` with `context.WithTimeout` (`client.go:313`), so the
deadline always exists and the first branch always runs. The second branch, with its
100ms rounding, is dead for every caller in this repository.

The value returned is `deadline - start`, where `deadline` is stamped inside
`context.WithTimeout` at `client.go:313` and `start` is stamped at the top of
`dialControl` at `client.go:446`. The work between them is a mutex acquire on the parent
context, a children-map insert, a `time.AfterFunc`, and one non-inlined call: about a
microsecond normally, so the result rounds to a clean `3s`. Any preemption longer than
500 microseconds in that window yields `2.999s` instead.

This is a defect twice over.

First, it is a side channel the function's own doc comment says it exists to close.
`client.go:474-476` reads: "a message that varies with the failure is the beginning of
exactly the distinguishing signal section 8.1 exists to deny." A duration reported to
1ms resolution does vary with the failure, faintly, because different failure modes
schedule differently.

Second, it is the best explanation available for the single unreproduced test failure.
`TestClientWrongKeyAndWrongPSKAreIndistinguishable` (`client_test.go:361`) compares the
two error strings byte for byte at `:387`, and its comment at `:385` asserts a cushion
the code does not provide:

```go
// The duration is the one part that legitimately differs, and it is
// rounded to 100ms in the message, so both land on the same budget.
if keyErr.Error() != pskErr.Error() {
```

The comment is describing the unreachable branch. The real tolerance is plus or minus
500 microseconds, the tightest margin anywhere in the suite. A distribution measurement
over 3,000,000 samples of this code path under 10x CPU oversubscription found `3s` in
99.9977 percent of cases, with a genuine tail spread across `2.983s` to `2.999s`. That
is roughly 2.3e-5 per dial and 4.7e-5 for the pair, low in isolation, but the real path
carries far more allocation and GC pressure than the microbenchmark did, and this is the
only mechanism in the suite that produces a one-character diff rather than a timeout.
It is a `t.Errorf` in a test whose name gives no hint that timing is involved, which
matches "failed once, identity lost in truncated output".

**Fix.** Round the deadline branch to 100ms as well:

```go
return deadline.Sub(start).Round(100 * time.Millisecond)
```

One token. It makes the test comment true, removes the flake, and closes the side
channel. Do not "fix" this by returning `c.dialTimeout` instead: `budget` legitimately
inherits an earlier deadline from the caller's context when the caller's is sooner, and
reporting the configured timeout in that case would over-report the bound the client
actually applied.

#### I2. `config.go:765`: exported `Reload` swaps the policy but never applies the diff to the device

**The defect.** `PeerWatcher` has two reload entry points that are not equivalent, and
the more visible one is the incomplete one.

The watcher's own loop calls `w.report(w.Reload())` at `config.go:862`. `report`
(`config.go:791`) is what invokes the `onReload` callback, which for a running server is
`Server.handleReload` (`server.go:611`). `handleReload` is where all the work actually
happens: it calls `refreshPeers` to rebuild the limiter set and reap the removed peer's
in-flight connections, then `applyDiff` to issue `IpcSet ... remove=true` against the
live WireGuard device, then `pruneSecretCache`.

`Reload` itself does none of that:

```go
func (w *PeerWatcher) Reload() ReloadResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reloadLocked()
}
```

`reloadLocked` (`config.go:770`) parses, validates, computes the diff, and performs the
atomic `w.cur.Store(cfg)`. Then it returns. The caller receives a `ReloadResult`
containing the diff and is silently responsible for doing something with it.

`Reload` is exported, and its doc comment at `config.go:763` actively invites the
misuse: "It is exported so a server can also reload on SIGHUP." A SIGHUP handler written
exactly as that sentence describes, `watcher.Reload()`, produces this:

- The policy swaps atomically, so a revoked peer is denied at authorization time. Access
  still fails closed. This is not an access-control bug.
- `applyDiff` never runs, so the revoked peer's keypair stays on the live WireGuard
  device indefinitely. Spec 7.1's stated revocation mechanism, "a peers file change
  triggers IpcSet with `remove=true`", simply does not occur.
- `refreshPeers` never runs, so the limiter set is stale and the revoked peer's in-flight
  proxied connections are never reaped. The fix wave's late addition is bypassed.
- Worst of the four: the removal is lost permanently. `reloadLocked` computes the diff
  against `w.cur.Load()` and then overwrites it. The next reload diffs against the
  already-advanced `prev`, so the removed peer never appears in a `Removed` list again.
  No later reload, no matter how correct, will ever take that keypair off the device. Only
  a process restart will.

No caller in this repository does this today. `grep` finds `Reload()` at `config.go:862`
and at four places in `config_test.go`. So this is latent, which is why it is Important
and not Critical. But it is a loaded gun with the instructions printed on the barrel, in
the one subsystem where a silent failure is the worst outcome the design has.

**What "must report" means concretely, and which fix I recommend.**

Two options:

- Option A, make `Reload` complete. Move the `report` call inside it, and give the
  watcher loop an unexported helper so it does not double-report:

  ```go
  // Reload re-reads, re-validates and swaps in the peers file, then hands the
  // result to the reload callback so the caller's device is updated too.
  func (w *PeerWatcher) Reload() ReloadResult {
  	r := w.reloadAndReport()
  	return r
  }

  func (w *PeerWatcher) reloadAndReport() ReloadResult {
  	w.mu.Lock()
  	r := w.reloadLocked()
  	w.mu.Unlock()
  	w.report(r)
  	return r
  }
  ```

  and change `config.go:862` from `w.report(w.Reload())` to `w.reloadAndReport()`. Note
  that `report` must be called outside `w.mu`, matching the existing rearm path at
  `config.go:869-878`, which already releases the lock before reporting.

- Option B, unexport `Reload` to `reload`, delete the SIGHUP sentence from the doc
  comment, and let `config.go:862` call it. The tests at `config_test.go:591,613,625,636`
  are in-package and keep compiling unchanged.

**I recommend Option B.** Three reasons, in order.

1. Constraint 5 of the goal document is "prefer deleting code over adding a flag", and
   more broadly prefer the smaller surface. Nothing in this repository needs a public
   reload trigger. `cmd/gocloak` installs handlers for SIGINT and SIGTERM only
   (`cmd/gocloak/main.go:295`) and has no SIGHUP path, so Option A would be building out
   an API for a caller that does not exist.
2. Option A leaves a second hazard standing that Option B removes for free. `Reload` is
   safe to call concurrently with the watcher goroutine only in the sense that `w.mu`
   serializes the swap. It does not serialize the *application* of two diffs.
   `handleReload` is documented at `server.go:609` as running "in the watcher's
   goroutine", and `Server.applyDiff` and `refreshPeers` assume that. Making `Reload`
   report means an external SIGHUP goroutine and the watcher goroutine can both be inside
   `handleReload` at once, with two diffs applied to the device in an order neither
   computed against. That is a harder problem than the one being fixed.
3. If a SIGHUP trigger is genuinely wanted later, the right shape is a method on
   `*Server` that posts to the watcher's own goroutine, not a second entry point into the
   watcher. Unexporting now does not foreclose that; it just stops the wrong version from
   being written by accident in the meantime.

If the owner prefers to keep a public reload for library consumers, take Option A, but
also make `Server.handleReload` safe under concurrent entry (a single mutex around the
`refreshPeers` / `applyDiff` / `pruneSecretCache` sequence is enough) and say so in the
doc comment.

#### I3. `README.md:234`: the "No key material at rest" row overclaims

**Current wording**, in the "Security properties that hold" table:

> | No key material at rest | Secrets Manager to memory. Nothing in EBS snapshots. CloudTrail records every read. |

The row is copied verbatim from spec 7.1, where it describes the *server's secret
resolution path*, and there it is accurate: `SecretResolver` (`secret.go:92`) returns a
`Secret` held in memory only, and nothing in the library writes a resolved value to disk.

**Why it overclaims as written.** The README is the public face of the whole tool, not
just the resolution path, and the tool's own documented onboarding puts long-term key
material on disk in two places, both of them on the README's happy path:

- `README.md:84-93`: "Each run writes `<name>.key` and `<name>.psk` at mode 0600". The
  quickstart tells the operator to run `gocloak keygen` for the server and every peer,
  and that command writes a Curve25519 private key and a 32-byte PSK to the filesystem
  (`cmd/gocloak/main.go:126-141`). These are exactly the artifacts an EBS snapshot would
  capture.
- `README.md:127-129`: "To get a first deployment running without AWS, point it at the
  file keygen just wrote: `private_key: file:/etc/gocloak/server.key`". This recommends a
  configuration in which the server's private key is permanently at rest on the instance.

An operator who reads the property table and stops there will conclude that following the
quickstart leaves no key material on disk. It does. A security tool's README is exactly
where that inference must not be available. The rest of the document is scrupulous, which
makes this row stand out more, not less.

**Replacement.** Change the table row to:

> | No key material at rest, with `aws:sm` | Secrets Manager to memory. Nothing in EBS snapshots. CloudTrail records every read. This holds for the `aws:sm` and `aws:ssm` schemes. `gocloak keygen` writes the private key and PSK to disk at 0600, and the `file:` scheme reads key material from disk, so both leave key material at rest by design. |

and add this sentence to the quickstart immediately after `README.md:102`, in the
paragraph that already warns about the PSK in scrollback:

> Once the private key and PSK are loaded into your secret store, delete the `.key` and
> `.psk` files. They are the only key material this tool puts at rest, and the property
> table above holds only once they are gone.

Both edits are additive and neither weakens a true claim.

#### I4. `server.go:557`: the `refreshPeers` comment omits the reap exception

This is parked residual 3 from `docs/build-decisions.md`, and I am promoting it from a
doc nit to Important, because it is the documentation of a live gap in the property the
README states most strongly.

The comment at `server.go:557-567` correctly explains that a limiter is keyed by tunnel
address and that a new peer at a recycled address inherits the old peer's live
concurrency count, and correctly argues that the inheritance is the fail-closed reading.
It never says the consequence that actually matters: because the limiter object survives,
it is not in the `gone` list, so `closeLive` is never called on it, and the departed
peer's in-flight proxied connections are **not** reaped. That is parked residual 2, and
the code currently carries it undocumented.

**Fix.** Append one sentence to the existing comment, after "The inherited count drains
as those connections close.":

```go
// Because the limiter object survives, it is not in the gone set below, so the
// departed peer's in-flight connections are NOT reaped in this one case. They
// hold their backend file descriptors until they close on their own. The
// departed peer's keypair is destroyed by applyDiff, so it can neither send
// nor receive on them: the cost is leaked descriptors, not access.
```

### Minor

#### M1. `secret.go:196`: `resolveFile` does not require a regular file

`os.Open` succeeds on a directory, and a directory at mode 0700 passes the
`info.Mode().Perm()&0o077 != 0` permission check. The failure surfaces only when
`io.ReadAll` returns an opaque platform-specific error. Symlinks are followed silently.

**Fix.** One line after the `Stat`, before the permission check:

```go
if !info.Mode().IsRegular() {
	return Secret{}, fmt.Errorf("secret: file:%s: is not a regular file", path)
}
```

#### M2. `secret.go:33`: `Secret` is exported but inert

After the fix wave correctly unexported `Secret.Bytes()`, the `Secret` type has no
exported constructor, no exported accessor and no exported field. Outside the package it
can be named but not built, read or usefully inspected. This is worse than either
endpoint of the API decision: it advertises a type that does nothing.

**Fix.** Unexport it to `secret`, or leave it and resolve it as part of the parked API
reduction (see section 5, ruling at line 181). Not urgent, but do not ship it as the
permanent shape.

#### M3. `device.go:25`: `deviceLogVerbose` has no non-test caller

Defined at `device.go:25`, referenced only at `device_test.go:550` and
`device_test.go:774`. Constraint 5 prefers deleting. Low priority: it is a named mirror
of a wireguard-go constant and its presence is self-documenting next to
`deviceLogSilent` and `deviceLogError`.

#### M4. `docs/build-decisions.md`: six em dashes, violating the project style rule

Lines 50, 91, 107, 137, 167 and 179. The goal document's style constraint is "no em
dashes, no emojis in any file", and this file was created during the build, so the
"existing document convention wins" exemption does not apply. No emojis anywhere in the
repository; that half of the rule is clean.

**Fix.** Replace each with a comma, a colon, or a sentence break.

---

## 3. Spec 7.1, row by row

| Property | Delivered | Evidence |
|---|---|---|
| Endpoint invisibility | Yes | `TestSecurityWrongClientKeyGetsZeroBytesBack` measures two distinct silences (unknown static key, and a packet failing MAC1) and carries a mandatory positive control through the same relay, so the zero is not vacuous. Only two sockets exist in the process: the WireGuard UDP port and the in-tunnel listener at `10.99.0.1:443`. |
| Mutual auth and confidentiality | Yes | wireguard-go IKpsk2, unmodified. The server public key is pinned client-side as the peer's only key (`client.go:240`). |
| Forward secrecy | Yes | wireguard-go, untouched. No code in this repository can affect it. |
| Replay resistance | Yes | `TestSecurityReplayedHandshakeInitiationIsRejected` is genuinely non-vacuous: each captured initiation is its own positive control (first delivery must be answered), and the high-water-mark case, replaying an older initiation after a newer one was accepted, is covered explicitly. |
| Post-quantum hedge | Yes | The PSK is mandatory, never optional. `ipcConfig` (`device.go:254`) always emits a `preshared_key` line, and `keyToHex` rejects an empty or wrong-length value before it reaches the UAPI. A peer cannot be configured without one. |
| Anti-DoS | Yes | wireguard-go's cookie path, unmodified. Not independently tested here, which is the right call: testing someone else's cookie implementation is out of scope for this build. |
| Blast radius | Yes | `policy.go` has no wildcard, no CIDR and no port range; `validatePeer` (`config.go:296`) requires a literal `ip:port` and rejects hostnames outright, so nothing resolves names at any point. netstack does no forwarding, so a stolen client key cannot pivot to another peer or scan the VPC. |
| No key material at rest | **Partially** | True of the secret resolution path, which is what spec 7.1 means. Not true of `gocloak keygen` or the `file:` scheme, both of which the README puts on the quickstart path. See finding I3. |
| Instant revocation | Yes for access | The ordering in `handleReload` (`server.go:611`) is correct in both directions and every step of the window denies: the policy swap happens inside the watcher before the callback, `refreshPeers` then drops the limiter and reaps in-flight connections, and only then does `applyDiff` destroy the keypair. A connection arriving mid-window finds no limiter and is closed in silence (`server.go:330`). Two caveats, neither an access leak: parked residuals 1 and 2 leak file descriptors, and the `Reload` trap in finding I2 would bypass the device removal entirely. |

### Spec 7.2 cross-check

Does the code fail to hold something 7.1 promises? Only the "no key material at rest" row,
and only because the README's scope is wider than the spec's. Everything else holds.

Does it accidentally deliver more than claimed? Yes, in one place worth recording. Spec
7.2 item 2 concedes that anyone holding the server public key can confirm the endpoint
exists. The implementation is stronger than that concession for one important case: a
syntactically perfect handshake initiation from a static key the server has never seen
gets exactly zero bytes back, because the peer lookup fails before any response is
generated. Only a party holding a *valid client key* draws a response. The README states
this correctly at `README.md:247-254` and does not overclaim it.

---

## 4. README honesty

**Overclaims beyond the 7.1 row:** none found. Finding I3 is the only one.

I checked the positive claims against the code individually. "The process opens exactly
one port to the internet" (`README.md:162`) is true. "A hostname is rejected at load time"
(`README.md:152`) is true (`config.go:305`). "Refuses to overwrite an existing file"
(`README.md:84`) is true (`O_EXCL` at `cmd/gocloak/main.go:205`). The
`ErrHandshakeTimeout` sample text at `README.md:300-306` matches what
`handshakeTimeoutError` (`client.go:494`) actually produces. The error sentinel table at
`README.md:317-324` matches `client.go:46-79` exactly.

**Are spec 7.2's five items stated as plainly as the positive claims?** Yes, and in two
respects better than required.

- They get their own H2 heading, "What goCloak does not protect against"
  (`README.md:237`), immediately after the positive properties table rather than buried at
  the end.
- They are linked from the third sentence of the document (`README.md:13-16`), with
  "Before you deploy it, read ..." and "it is the part that decides whether this tool fits
  your threat model". A reader cannot reach the quickstart without being pointed at them.
- All five are present, numbered, in the same order as the spec, each in bold with a
  plain-language expansion. None is softened. Item 2 goes *beyond* the spec by explaining
  the IKpsk2 message-2 nuance and conceding that a wrong-PSK party still draws a response,
  which is a disclosure the spec does not require.
- The framing sentence at `README.md:239-240`, "These are not gaps waiting to be fixed.
  They are the boundaries of what the design can do", is the honest formulation.

Two further voluntary disclosures deserve credit because neither was required: the
"Rotation is not revocation, and rotation does need a restart" section
(`README.md:357-363`), which discloses a real operator hazard the spec never mentions, and
the PSK scrollback warning at `README.md:98-102`.

---

## 5. Ruling audit, all 25

Line references are into `docs/build-decisions.md`.

### Correct, no action

| Line | Ruling | Assessment |
|---|---|---|
| 49 | Work on a branch in the primary directory, not a worktree | Correct. One-commit-old repo, nothing in flight, a worktree buys no isolation. |
| 54 | `policy.go` defines its own `PeerPolicy` / `Policy`, no dependency on `config.go` | Correct, and one of the better structural calls. The security-critical unit is testable from a Go literal with no YAML fixture, and `config.go` pays a small mapping cost (`config.go:281-287`). |
| 60 | `device.go` generates test keypairs inline rather than shelling out to the CLI | Correct. The library must be testable without its own CLI. |
| 65 | `gocloak.go` created in task 1, `go mod tidy` deferred to task 11 | Correct and necessary. Tidy before the imports exist would strip the pinned deps. |
| 71 | `staticcheck` and `govulncheck` installed via `go install` | Correct. Task 11 is otherwise unrunnable. Cost is two binaries in GOPATH/bin. |
| 77 | `SecretRef` defined in `secret.go`, not `config.go` | Correct. Spec 10 assigns resolution to `secret.go`, and defining it early is what stopped tasks 5, 7 and 8 inventing three incompatible versions. |
| 82 | Minor C, the TOCTOU fix, pulled into the fix round despite minors being deferred | Correct. `os.Open` plus `Fstat` is strictly safer at identical cost, and the binding tie-breaker is fail-closed. |
| 87 | No second writer while an implementer holds the repo | Correct process call. `.git/index.lock` contention is real. |
| 93 | Every later brief carries an explicit test-naming warning | Correct, and it caught a real hazard: a mis-named test under a `-run TestX` substring filter is silently skipped, which manufactures false verification evidence. |
| 99 | Minor F, the `.Unmap()` fix, pulled into task 4's fix round | Correct and load-bearing. netstack really does hand back IPv4-in-IPv6 addresses, and the two sites (`policy.go:64`, `policy.go:91`) now agree. Fixing it cannot widen access. |
| 103 | Minor G assigned to task 5, not task 4 | Correct. `policy.go` has no knowledge of the server's own tunnel IP; `config.go` owns the operator-facing YAML and does. |
| 109 | Task 5 fix round takes Important H plus minors I, J, K | Correct. H was a constraint-4 violation, which is not deferrable. |
| 115 | The `deviceLogSilent` zero-value minor is not fixed in `device.go` but carried as a requirement into tasks 7 and 8 | Correct, and it held: both `server.go:213` and `client.go:230` set `deviceLogError` explicitly, each with a comment saying why. Residual risk is a future caller outside those two forgetting, which is real but small. |
| 121 | Round 2 does NOT whitelist both new yaml substrings verbatim | **The best call in the build.** The two message classes differ in whether they can carry attacker-influenced text: "field %s already set in type %s" embeds a resolved struct field name and is safe verbatim; "mapping key %#v already defined at line %d" embeds an arbitrary document key and is not. The naive whitelist really would leak a whole key pasted into a key position, and the implementer proved non-vacuity twice, including by applying the forbidden version and watching the test leak the key. |
| 127 | Task 7 fix round takes Important N plus minors O, P, Q, R | Correct. Q in particular: a test comment claiming coverage that does not exist is the kind of false claim that misleads every later reader, and adding the missing cases rather than softening the comment is the right direction. |
| 133 | Recording that the task 7 brief, not the implementer, was the defect source | Correct and worth having recorded. The reviewer was told not to assume the brief was correct, and that is the only reason the unbounded pre-hello window was found. |
| 139 | Adopt option (c) with the `yamlFieldNameRE` guard as task 5 fix round 3 | Correct. It closes a full-key leak while preserving the "you typed `psk_ref` instead of `psk`" diagnostic, which operators need in a file whose typos silently change access. Rejecting (a) on constraint 4 being unqualified, and (b) on diagnostic value, are both right. |
| 145 | Task 8 fix round takes Critical U plus minors V and W | Correct. U, the `finishHello` use-after-return window at `client.go:392`, is a genuine correctness fix: returning a connection the watchdog is already closing surfaces in production only as an unexplained reset. |
| 157 | Fix Important Y by making `log_format` govern the whole process | Correct. The alternative was a mixed-format stream on one file descriptor, and this keeps spec 5's `ServerConfig` verbatim with no logger field added. `cmd/gocloak/main.go:286` calls `slog.SetDefault`, `server.go:166` reads `slog.Default()`. Clean. |
| 163 | Task 9 fix round takes Y plus minors Z, AA, AB | Correct. Z especially: an unchecked `Close` on the key file can leave a zero-length key that the `O_EXCL` guard then permanently refuses to regenerate, a self-inflicted outage with no recovery short of manual deletion. |
| 169 | Raise the `go` directive from 1.26.5 to 1.26.6 | Correct. It converts "silently builds against a vulnerable stdlib" into a hard build failure for consumers below 1.26.6, which is the fail-closed direction. Raising the consumer minimum is the right trade for a security library. |
| 175 | Task 12's two README minors rolled into the final fix wave rather than their own round | Correct process call, two sentences in one file. |

### Correct decision, but revisit the packaging

| Line | Ruling | Assessment |
|---|---|---|
| 151 | Reviewer finding 4, "writing the PSK to disk exceeds the brief", REJECTED | **Decision correct, consequence needs handling.** The task 9 brief did explicitly ask for a `.psk` file alongside the `.key` file, the file is 0600 with `O_EXCL`, and it is directly consumable by spec 6.1's `file:` scheme, so this is spec-aligned rather than scope creep. Keeping it is right. But it is one of the two things that turn the README's "No key material at rest" row into an overclaim (finding I3). Either is fine on its own; both together are not. Resolve it in the README, not by removing the file. |

### The two flagged for particular attention

| Line | Ruling | Assessment |
|---|---|---|
| 181 | The final review's Important 3, "exported surface is about 4x what any consumer uses", SCOPED DOWN to unexporting `Secret.Bytes()` only, rest parked for the owner | **Correct, and I would not have decided differently.** The reasoning is sound and worth endorsing explicitly: `Secret.Bytes()` was the security-relevant sliver, the only API handing raw key material to an arbitrary caller, with no external caller. That is not a judgment call, so fixing it at the gate was right. The rest, the wire codec, `Policy`, `PeerWatcher`, `ReloadResult`, `PeerDiff`, is an API *design* decision with legitimate arguments on both sides (a consumer may reasonably want to build a policy in code, or to drive the watcher themselves), and design decisions made unilaterally at a final gate are how good APIs get broken. Parking it for the owner is the correct disposition. **One loose end the ruling created:** unexporting `Bytes()` left `Secret` exported with no exported constructor, accessor or field, so it is now nameable but unusable from outside the package (finding M2). That is worse than either endpoint. When the owner takes up the parked reduction, `Secret` should go one way or the other. |
| 187 | REJECTED the suggestion to swap `golang.org/x/crypto/curve25519` for `crypto/ecdh` to satisfy constraint 6 exactly | **Correct, and I would keep the rejection.** The risk trade is the right one: rewriting the code that mints every key in the system, at the final gate, to resolve a bookkeeping technicality is a bad bargain, and the key-minting path was verified byte for byte by the task 9 review. The "already in the module graph transitively via wireguard-go" argument is also factually right, so the direct require pulls in no new code. **Two things the ruling understates, both worth recording rather than acting on.** First, the swap is smaller than "rewriting the crypto" suggests: `curve25519.X25519(priv, curve25519.Basepoint)` appears once in production code (`cmd/gocloak/main.go:167`) and three times in tests (`device_test.go`, `example_test.go`, `cmd/gocloak/main_test.go`), and `crypto/ecdh`'s `X25519().NewPrivateKey(b)` handles clamping itself, which would also let `clampPrivateKey` at `cmd/gocloak/main.go:177` be deleted. Four call sites, not a rewrite. Second, the outcome is nonetheless a real deviation: `golang.org/x/crypto v0.51.0` is now a **direct** require in `go.mod` and is not in spec 11's pinned dependency table. That is a constraint 6 deviation, accepted on merit, and the build-decisions entry should say so in those words rather than calling it "a bookkeeping technicality". The distinction matters because the next person to read constraint 6 needs to know the table has one accepted exception, not that the constraint was judged unimportant. Recommendation: keep the code exactly as is, amend the ruling's wording, and note the exception in `go.mod` with a comment. |

### Summary

24 of 25 rulings are sound as decided. The 25th (line 151, writing the PSK to disk) is
also sound as a decision but has an unhandled documentation consequence. Two rulings
(181 and 187) are correct but left loose ends that should be recorded rather than
reversed: an inert exported `Secret` type, and an unacknowledged constraint 6 deviation.

Nothing in the 25 traded away a security property. That is the headline, and it is the
right headline for a build executed without human review gates.

---

## 6. Parked residual triage

### Parked 1: the `limiterFor` to `track` gap, roughly 15 seconds

**Acceptable to leave. Fix in the first commit after merge.**

The window spans the hello read (up to 5s) plus the backend dial (up to 10s). A reload
landing inside it drains an empty live set, and the handler then calls `track` on an
orphaned limiter, so that connection is never reaped.

The cost is bounded and does not touch access. By the time the orphaned connection exists,
`applyDiff` has destroyed the peer's keypair, so the peer can neither send nor receive on
it. The connection is dead in the water, and what leaks is a backend file descriptor plus
a concurrency count on a limiter that is itself garbage. The descriptor is released when
the backend closes the connection.

The ruling to park it was right: the process allowed one fix wave, and a further
concurrency edit at the final gate carries more risk than the residual it removes. The
one-line close is still correct and should land soon:

```go
limiter.track(live)
if current, ok := s.limiterFor(peerIP); !ok || current != limiter {
	return
}
defer limiter.untrack(live)
```

Note the ordering: the re-check must come after `track`, and the `defer untrack` after the
re-check, or the early return leaks the registration it just made.

### Parked 2: a peer removed and a different peer added at the same tunnel IP

**Acceptable to leave. Genuinely an owner call.**

Limiters are keyed by tunnel address, so a reload that removes peer A at `10.99.0.7` and
adds peer B at `10.99.0.7` finds the existing limiter, keeps it, and therefore never puts
it in the `gone` set. A's in-flight connections are not reaped.

The re-reviewer's characterization is correct and I confirmed it independently: A's
keypair is destroyed by `applyDiff`, so A can neither send nor receive; B cannot attach to
A's sessions because they are keyed to A's static key; the impact is leaked backend
descriptors plus an inherited concurrency count. The inherited count is the fail-closed
direction, since it is stricter than starting B at zero.

This one is properly an owner decision because the fix has a design consequence: keying
the limiter set by public key rather than tunnel address, or reaping whenever the identity
at an address changes, changes what "a peer's concurrency" means across a rename. Do not
let an agent decide that unilaterally.

What must not stay is the silence about it, which is residual 3.

### Parked 3: the `refreshPeers` comment

**Must fix before this is called done.** Promoted to finding I4 above.

One sentence, zero risk, and it documents exactly parked 2. Shipping a revocation path
with an undocumented reap exception is how the next reader concludes the reap is total
when it is not. The full replacement text is in finding I4.

---

## 7. Flaky test analysis

### Conclusion

The most likely candidate is **`TestClientWrongKeyAndWrongPSKAreIndistinguishable`**,
`client_test.go:361`, assertion at `client_test.go:387`. Full mechanism in finding I1.

In short: the test compares two error strings byte for byte, its comment claims a 100ms
rounding cushion, and the code path actually taken rounds to 1ms
(`client.go:481`). The real tolerance is plus or minus 500 microseconds, the tightest
margin in the suite. A measured distribution over 3,000,000 samples under 10x CPU
oversubscription put `3s` at 99.9977 percent with a real tail into `2.983s`-`2.999s`.
This is the only mechanism found anywhere in the suite that produces a one-character
string diff rather than a timeout, it fires as `t.Errorf` rather than a panic, and the
test name gives no hint that timing is involved, all of which fits a failure whose
identity was lost in truncated output.

Second candidate, a different and also plausible mechanism: the **bind-then-release port
reservation** at `device_test.go:67` (`deviceTestFreeUDPPort`) and its TCP twin at
`server_test.go:370` (`serverTestClosedPort`). Both bind a port, read the number, close
it, and return the number to be re-bound later:

```go
c, err := net.ListenPacket("udp", "127.0.0.1:0")
port := c.LocalAddr().(*net.UDPAddr).Port
c.Close()
return port
```

In `serverTestStart` the gap spans `NewServer` (file read, YAML decode, full validation)
plus the scheduling of `go srv.Run(ctx)` before wireguard-go binds: milliseconds, widened
by load. macOS allocates ephemeral UDP ports from the same range the reservation came
from, and the suite performs roughly 45 server bring-ups per run alongside every client
device, every `securityProbe` socket, and two sockets per `securityRelay`. A collision
surfaces as a bind failure inside `Run`, which harness cleanup reports as
`Run returned %v, want nil after cancellation` (`server_test.go:262`), attributed to
whichever test happened to be running. Unreproducible by construction. On the TCP side,
a stolen `serverTestClosedPort` turns an expected `ErrBackendUnavailable` into
`StatusOK`.

### Candidates ruled out, with the evidence that cleared them

I had initially ranked two server tests first. Both were measured and cleared. Recording
this because reasoning about a margin is not the same as measuring it, and in this case
the reasoning was wrong.

| Test | Why it looked suspicious | Evidence that cleared it |
|---|---|---|
| `TestServerMaxConcurrentBoundsConnectionsThatSendNothing`, `server_test.go:608`, loop at `:640` | A 3s retry loop racing the 5s `HelloReadDeadline` that holds the slots. If opening three silent connections took more than about 2s, the first slot would free mid-loop and the assertion could never be satisfied. | Warm in-tunnel dials measure sub-millisecond. Breaking this needs per-connection latency near a full second, three times over. Roughly 2s of slack remains. Cleared. |
| `TestServerDialsPerSecondIsEnforced`, `server_test.go:664` | Bucket of 1 per second, three back-to-back dials, needs at least one refusal; three consecutive gaps over 1s would let all three through. | Same measurement. Three consecutive one-second inter-dial gaps against sub-millisecond warm dials is not a realistic failure. Cleared. |
| `TestClientDialUnderRepeatedCancellationNeverReturnsADeadConn`, `client_test.go:811` | Looked like the strongest candidate on paper: `typical` is a single-sample measurement at `:838`, the cancel delay is `rand.Int64N(2*typical)`, and there is a hard `returned < 4` floor at `:888`. | Run under 8x CPU oversubscription: `typical` clamps to the 1ms floor at `client_test.go:840`, and 244 of 244 dials returned a usable conn. The clamp supplies enormous headroom because a warm dial is far under 1ms. Cleared. |
| `TestConfigHotReloadDebounced`, `config_test.go:523`, threshold at `:554` | Ten `os.WriteFile` calls against a 50ms debounce, asserting `n > 3` is a failure. | All four `TestConfigHotReload*` tests run with `-count=40` under 12x CPU oversubscription: all passed, 21s total. Four or more reloads would need three separate stalls over 50ms inside one burst. `stopTimer` / `resetTimer` at `config.go:898-910` were also reviewed: the drain is non-blocking and correct. The 30s `watchRearmInterval` cannot fire inside this test. Cleared. |
| `TestSecurityWrongClientKeyGetsZeroBytesBack` retransmit guard, `security_test.go:379`, window at `:46` | The one assertion in the suite directly coupled to WireGuard's 5s handshake retransmit: `toServer.ByType[wgTypeInitiation] < 2` inside a 12s window. | wireguard-go emits initiations at t=0, t=5.0 to 5.33, t=10.0 to 10.7, so 12s normally yields three. Falling below two requires the first initiation to be delayed by more than 6.7s, and the device is fully constructed before the window opens. Roughly 6.7s of slack. Not a serious suspect. If margin is wanted anyway, raise `securityHandshakeWindow` to 17s at a cost of 10s across the two tests that use it. |
| `cmd/gocloak/main_test.go`, whole file | Worth checking, since `go test ./...` runs it as a concurrent process. | Contains no timing, no concurrency and no network binding. Every `serve` test fails during config or secret resolution, before a port is touched. Cannot be the source. |
| `securityRelay`, `security_test.go:143-182` | Shared counters read across goroutines. | Mutex-correct. The census ordering in both positive controls is causally established before `snapshot()` is called. The "stranger runs first" ordering at `security_test.go:361` correctly prevents the server-learned-endpoint contamination that would otherwise break the zero-bytes assertion. |

Note that no test in the root package calls `t.Parallel()`, so intra-package contention
comes from the wireguard-go and gVisor netstack goroutines each harness spins up, plus
the concurrently-running `cmd/gocloak` test binary. The suite's own 245s runtime is the
load that makes a marginal sleep fail.

### The two test-only fixes

#### T1. `server_test.go:174`: retry the port pick on bind failure

This removes the whole bind-race class rather than narrowing it. The clean fix is to pass
the reserved `net.PacketConn` through to wireguard-go so the port is never released, but
that is invasive. The cheap fix is to retry:

```go
// in serverTestStart, around the NewServer plus go srv.Run(ctx) sequence
var srv *Server
for attempt := 0; ; attempt++ {
	cfg.ListenPort = deviceTestFreeUDPPort(t)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Run binds the UDP socket. Give it a moment to fail fast on a
	// stolen port, and re-pick rather than failing the test.
	if err := serverTestRunUntilListening(t, s); err == nil {
		srv = s
		break
	} else if attempt == 2 {
		t.Fatalf("server did not bind after 3 port picks: %v", err)
	}
}
```

The exact shape depends on how `serverTestStart` currently sequences `Run`; the point is
three attempts instead of one. Apply the same treatment to `serverTestClosedPort` at
`server_test.go:370`, or accept it there, since a stolen TCP port is far less likely
given how few TCP listeners the suite creates.

#### T2. `security_test.go:300` and `:310`: invert the 4s / 5s deadline pair

`securityCaptureInitiation` provokes a handshake in a goroutine bounded at 4 seconds, then
waits 5 seconds to read the initiation off the sink:

```go
ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)   // :300
go func() { ... deviceTestDialRetry(ctx, d, serverTestTunnelAddr) ... }()
if err := sink.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil // :310
```

The goroutine that would emit a retransmit is killed one full second before the reader
gives up, and the two clocks start at different moments, since the sink deadline is
stamped after the goroutine launches. WireGuard's `RekeyTimeout` is 5 seconds, so a
delayed first initiation would retransmit at about 5.3s, past both deadlines. In practice
the initiation goes out within a millisecond of the first SYN, so exposure is small, but
the coupling is backwards and costs nothing to fix. This helper is called twice per run by
`TestSecurityReplayedHandshakeInitiationIsRejected`.

**Fix.** Make the provoker outlive the reader:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)  // :300
...
if err := sink.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil // :310
```

The failure message at `security_test.go:318` should be updated from "within 5s" to match.
