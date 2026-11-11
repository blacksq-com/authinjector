# AuthInjector

**The broker that holds your API keys so your agents never do.**

[Website](https://authinjector.com) · Built by [Black Squid](https://blacksq.com) · License: [Elastic License 2.0](LICENSE.md)

An AI coding agent that can run commands can print any credential in its reach.
Blocklists of risky commands keep failing, because the ways to print an
environment cannot all be listed. **The fix is absence:** the agent never holds
a key. AuthInjector, a small static Rust binary beside it, does, and every
outbound call goes through it.

## How it works

- **Unix socket, no credential.** A caller sends plain HTTP to a local socket,
  with the service as the first path segment: `POST /tavily/search`.
- **Caller identity from the kernel.** `SO_PEERCRED` says which user opened the
  connection. Nothing the caller writes can change that answer.
- **Per-key allowlists and rate limits.** Each key names who may use it, which
  methods and paths, and how often. Everything else is refused, and the
  refusal is logged.
- **Inject, forward, return.** The broker adds the key on the way out, strips
  any copy the caller tried to send, and returns the upstream response
  unchanged. Redirects are never followed.
- **A full audit log.** One JSON line per call, refusals included. Never a
  body, a header or a query string.
- **Push secrets without seeing them.** Deliver a held key to a Cloudflare
  Worker secret or a GitHub Actions secret (sealed for GitHub). Where a key may
  go is set in config, never by the caller.

`PROTOCOL.md` is the specification; the reasoning behind every refusal lives
there. The rest of this file is how to run it.

## Install

Download the latest release and run the installer (Linux, amd64 or arm64):

```bash
curl -fsSL https://github.com/blacksq-com/authinjector/releases/latest/download/authinjector-$(uname -m)-unknown-linux-musl.tar.gz | tar xz
cd authinjector-$(uname -m)-unknown-linux-musl
sudo ./install.sh --caller "$USER"
```

Each release lists `SHA256SUMS.txt`; check the tarball against it before you run it
(`sha256sum -c SHA256SUMS.txt --ignore-missing`).

`install.sh` creates the service user, the `authinjector-clients` group, the
catalogue and an **empty** config. It never touches a credential.

### Build from source

Static musl build inside Docker with [`cross`](https://github.com/cross-rs/cross):

```bash
git clone https://github.com/blacksq-com/authinjector && cd authinjector
cargo install cross
cross build --release --target x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
sudo ./install.sh --caller "$USER"
```

### Docker

Every release is also published to `ghcr.io/blacksq-com/authinjector`
(amd64 and arm64). The broker reads its config and resolves caller uids
against `/etc/passwd`, so mount both from the host and share the socket
directory with the callers:

```bash
docker run -d --name authinjector \
  --user "$(id -u authinjector):$(getent group authinjector-clients | cut -d: -f3)" \
  --group-add "$(getent group authinjector | cut -d: -f3)" \
  -v /etc/authinjector/config.toml:/etc/authinjector/config.toml:ro \
  -v /etc/passwd:/etc/passwd:ro \
  -v /run/authinjector:/run/authinjector \
  ghcr.io/blacksq-com/authinjector:latest
```

The socket is created `0660`, so members of `authinjector-clients` on the host
can connect. Running `install.sh` once on the host sets up the users, groups and
config the container expects.

## Use it from your AI tools

Agent instructions are generated from the catalogue (`authinjector gen-docs`),
so they always list the services the broker actually knows:

- Claude skill: [`skills/authinjector/SKILL.md`](skills/authinjector/SKILL.md), copy the folder into `~/.claude/skills/`
- Cursor rule: [`.cursor/rules/authinjector.mdc`](.cursor/rules/authinjector.mdc)
- Codex, Cursor and others: [`AGENTS.md`](AGENTS.md)
- GitHub Copilot: [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
- Per-service reference: [`docs/services.md`](docs/services.md)

A help-only MCP server (no keys, no API calls) answers questions about setup and
every service: `https://authinjector.com/mcp` (Streamable HTTP), e.g.
`claude mcp add --transport http authinjector-help https://authinjector.com/mcp`.
It serves [`docs/help.json`](docs/help.json).

## Releases

Tagging a version (`git tag v0.2.0 && git push origin v0.2.0`) runs
`.github/workflows/release.yml`: static musl tarballs for x86_64 and arm64 built
with `cross`, `SHA256SUMS.txt`, a GitHub Release with all of them attached, and
the multi-arch image on ghcr.io. `ci.yml` runs the test suite on every push and
pull request.

## License

AuthInjector is source-available under the Elastic License 2.0 (ELv2).
You may read, use, copy, modify and redistribute it. You may not provide it to
others as a hosted or managed service, and you may not remove or get around any
licence key functionality or licensing notices. AuthInjector is not open source
and does not convert to an open source licence. See [LICENSE.md](LICENSE.md) for
the full terms.

Copyright 2026 Velesco Inc. o/a Black Squid.

---

## The idea in one paragraph

A caller sends plain HTTP to a Unix socket with **no credential at all** —
`POST /tavily/search`. The broker reads the caller's identity from the kernel,
matches the first path segment to a configured key, checks that this caller may
use it, checks the method and path against an allowlist, checks the rate limit,
injects the credential, forwards, and returns the response unchanged. One audit
line per call. Nothing in the caller's reach ever holds a key.

```
caller (no credential)                  broker (holds the keys)          upstream
  curl --unix-socket … /pexels/v1/search  ──►  SO_PEERCRED: who are you?
                                               allowlist: may you?
                                               rate limit: how often?
                                               inject credential  ──────►  api.pexels.com
                                          ◄──  audit line, no secret  ◄──  200
```

---

## Quick start

After installing:

```bash
sudo ./install.sh --caller alice          # users, binary, catalogue, empty config
authinjector list                       # what is available
sudo authinjector add pexels -c alice -r 20   # prompts for the key, echo off
sudo systemctl restart authinjector
authinjector show                       # lengths, never values
```

Then, holding no credential:

```bash
curl --unix-socket /run/authinjector/authinjector.sock \
     'http://localhost/pexels/v1/search?query=toronto&per_page=1'
```

> **A shell started before `install.sh` ran will not have the group yet** and
> fails with a bare "connection refused" that looks nothing like a permission
> problem. Log out and back in, or borrow the group for one command:
> `sg authinjector-clients -c '…'`.

---

## Two files, and only one holds a secret

| Path | Holds | Mode |
|---|---|---|
| `/usr/share/authinjector/catalogue.toml` | what each service **is** | public, shipped |
| `/etc/authinjector/config.toml` | your keys, and who may use them | `0640 root:authinjector` |

*Where Tavily lives and which header it wants* is identical for everyone who
uses Tavily. Only the key and the permission are yours. So supporting a new
service is a catalogue update, never a change anyone makes by hand.

### The catalogue — public

```toml
[services.tavily]
name = "Tavily"
base_url = "https://api.tavily.com"
auth_in = "header"            # or "query"
auth_header = "Authorization"
auth_prefix = "Bearer "       # "" for a raw key header
signup_url = "https://tavily.com/"
cost_per_call_cad = 0.008
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]
```

`base_url` must be `https://`. Exactly one of `auth_header` and `auth_param`
may be set, and it must be the one `auth_in` names — an entry carrying both is
refused at load, because where a credential goes must never depend on which
branch of the injector happened to run.

### The config — private, one key per label

```toml
[services.tavily.blacksq]
key = "tvly-…"
callers = ["alice"]
rate_per_minute = 20

[services.tavily.personal]
key = "tvly-…"
callers = ["alice"]
rate_per_minute = 5
```

| Field | Meaning |
|---|---|
| table name | `[services.{service}.{label}]`; label `default` is addressed bare |
| `key` | the credential — the only secret in either file |
| `callers[]` | usernames permitted to use **this key** |
| `rate_per_minute` | per caller, per key |
| `endpoints[]` | optional **narrowing** of the catalogue's list, never a widening |
| `version` | increments when the block changes; appears in `policy_id` |

---

## Several keys per service

A service may hold many keys, each under a **label**, and the label is the
address:

```
[services.tavily.default]   →  /tavily/search
[services.tavily.personal]  →  /tavily:personal/search
```

**Permission is per key, not per service.** `callers`, the rate limit and any
endpoint narrowing all attach to the label — *"alice may use the Black Squid
account, the build service may not"* is not a sentence one-key-per-service can
express, and a broker that cannot express it gets handed the more privileged
key by default.

The label is the same string everywhere: the first path segment, the policy map
key, the secrets map key, the rate-limit bucket, and the audit line's
`upstream` field. One definition, in `config::instance_key`, so no resolution
step can disagree with another and no call can be served by one key and
attributed to a different one.

A service need not have a `default`. If every key is labelled, the bare form
returns 404 and the body lists the labels that do exist.

---

## Where the credential goes

| `auth_in` | Effect |
|---|---|
| `header` (default) | sets `auth_header: <auth_prefix><key>` |
| `query` | appends `?<auth_param>=<key>`, percent-encoded |

Query mode exists because some services accept nothing else. **It is the weaker
of the two:** the credential travels in the URL and reaches the upstream's
access logs and any intermediary. We strip it from our audit line; we cannot
strip it from theirs. Prefer a header wherever a service offers both.

**Strip, then set — never set alone.** Both transports allow repetition: HTTP
permits repeated header names, a query string permits `?key=a&key=b`. A naive
"set" would leave the caller's value beside ours, and which one an upstream
honours is not something to bet a credential on. Header names are matched
case-insensitively; query parameter names are matched after percent-decoding,
so `?k%65y=theirs` cannot ride along beside `?key=ours`.

### Headers the caller can never send

Credential slots — `authorization`, `cookie`, `proxy-authorization`.

Connection-scoped headers — `host`, `content-length`, `connection`,
`keep-alive`, `transfer-encoding`, `upgrade`, `te`, `trailer`, `expect`,
`proxy-authenticate`, `proxy-connection`. These describe the hop the caller
made *to the broker* and are wrong on the separate connection the broker makes
to the upstream.

> `host` is the one that mattered in practice. Forwarding the caller's
> `Host: localhost` produced two failures that looked like unrelated outages:
> nginx front ends (Stripe, Meta, Outscraper) answered 400/502 with their own
> HTML error page, never reaching the API behind them; and every HTTP/2 host
> (all `googleapis.com`, ElevenLabs) rejected it *client-side* while deriving
> the `:authority` pseudo-header, so the request never left the machine and
> surfaced as "upstream unreachable". Both read as "that service is down" or
> "that key is bad". Neither was.

### Credentials are scrubbed on the way back, too

A query-mode upstream that answers with a redirect echoes the request URL —
credential included — in `Location`. Since the broker returns upstream response
headers verbatim, that would hand the caller the exact secret the broker exists
to withhold. Response headers are scrubbed of the injected parameter by name.
The forwarder also **never follows redirects**, which matters: the redirect
that exposed this pointed at plaintext `http://`.

---

## Pushing a key to where it is used

A key is not only called with — it has to be *installed*: a Cloudflare Worker's
secret, a GitHub Actions secret. That is the one moment a provisioning script
traditionally handles the value, and it is exactly the moment worth removing.

```
POST /_broker/push
{"source": "resend:blacksq", "dest": "cf-worker:blacksq-example/RESEND_API_KEY"}
  -> {"ok": true, "source": "resend:blacksq", "dest": "…", "via": "cloudflare-rw"}
```

The broker holds the key and holds the destination's credential, so it puts one
into the other and answers with the fact. Nothing in the caller's process ever
sees the value — the same guarantee `/tavily/search` makes, applied to
provisioning.

Destinations:

| Form | Lands as |
|---|---|
| `cf-worker:{script}/{NAME}` | a Worker secret |
| `gh-repo:{owner}/{repo}/{NAME}` | a repository Actions secret |
| `gh-env:{owner}/{repo}/{environment}/{NAME}` | an environment secret |

GitHub takes the value **sealed** — libsodium's anonymous sealed box against the
target's own public key, so the ciphertext is opened only by GitHub. Cloudflare
takes it over TLS. Either way the broker builds the envelope; the caller never
holds the contents.

### Where a key may go

One section says where anything may be delivered. A key names its own rule only
when it needs a different one:

```toml
[push]
default = [
  "cf-worker:blacksq-*/*",       # our workers, any secret name
  "gh-repo:Black-Squid/*/*",     # our repositories
  "gh-env:Black-Squid/*/*/*",    # and their environments
]

[services.resend.blacksq]
push_deny = ["gh-repo:*/*/*"]    # everywhere the default allows, but never a repo

[services.stripe.live]
push_to = []                     # …and this one goes nowhere at all
```

Most installations set the default once and never touch it again. The three
per-key lines are for when one key is not like the others:

| On a key | Means |
|---|---|
| *(nothing)* | inherits `[push] default` |
| `push_allow = [...]` | **and also** these — the default keeps doing its job |
| `push_deny = [...]` | **but never** these. Deny wins over everything |
| `push_to = [...]` | instead of the default |
| `push_to = []` | nowhere at all, whatever the default says |

Absent and empty are deliberately different: one is a gap, the other is a
decision. Set all of it with the CLI, never by hand — that file holds every key
on the box, and a sudo-edit to add one line risks all of them:

```sh
sudo authinjector push-to --default 'cf-worker:blacksq-*/*' 'gh-repo:Black-Squid/*/*'
sudo authinjector push-to resend:blacksq --deny 'gh-repo:*/*/*'
sudo authinjector push-to resend:blacksq --allow 'cf-worker:promo-*/*'
sudo authinjector push-to stripe:live            # naming none = nowhere
sudo systemctl restart authinjector.socket
```

### 🔴 What a rule may never say

"Send secret X to destination Y" is, unconstrained, an exfiltration primitive.
The destination is therefore never the caller's to choose — it is the config's,
and the config may not say certain things:

- **A bare `*` may not be a first segment of a rule that PERMITS.**
  `cf-worker:*/…` reads "any account" and `gh-repo:*/…` reads "any
  organisation"; that is the one shape that turns delivery into theft.
  `blacksq-*` and `Black-Squid` are the point. A **deny** may say it, because a
  deny can only ever narrow: "this key reaches no GitHub repository, wherever it
  is" is a sentence worth being able to write.
- **Deny wins.** A destination is reachable only if something permits it and
  nothing forbids it — the only precedence that is safe to get wrong in the
  tired direction, since a broadened allow-list cannot quietly re-open what a
  deny closed.
- `*` matches inside one segment and never crosses `/`, so a rule cannot be
  walked out of with `..`.
- **Only a rule may wildcard the secret's name.** A request always names one
  real secret — `/_broker/push` refuses `…/*`.
- Rules are parsed at **startup**, the default included. A typo is a refusal to
  serve, not a surprise the first time someone provisions a client.
- Delivery goes through an ordinary upstream (`cloudflare-rw`, `github-rw`), and
  the caller must be permitted to use **that** too. Pushing through a credential
  is at least as consequential as calling with it.
- A push spends the source key's rate limit, so a loop that pushes cannot outrun
  one that fetches.

## Refusals

| Code | Meaning |
|---|---|
| 404 | unknown upstream, or a service addressed bare that has no `default` label |
| 403 | caller not in `callers[]`, or path off the allowlist |
| 405 | path known, method not allowed |
| 429 | per-caller, per-key rate limit exceeded |
| 502 | upstream unreachable |

**Default deny, three times over:** unknown upstream, caller not permitted, or
method/path unmatched. **Every exit writes an audit line, refusals included** —
a broker that logged only successes would make a caller probing the allowlist
invisible, which is exactly the traffic worth seeing.

---

## Audit

```json
{"ts":"2026-09-18T05:38:41Z","caller":"alice","uid":1000,"upstream":"tavily:personal",
 "method":"POST","path":"/search","status":200,"bytes_in":142,"bytes_out":8311,
 "duration_ms":740,"cost_cad":0.008,"policy_id":"tavily:personal@3","outcome":"forwarded"}
```

**Never a request or response body. Never any request header** — not "every
header except the one we added": an allowlist of headers-not-to-log is the same
enumeration mistake as a blocklist of ways-to-print-an-environment, one layer
down. The `Line` struct holds primitives only, so there is nowhere to put a
header map even by accident.

**Never a query string.** `?key=`, `?api_key=` and `?access_token=` are all
live conventions, and a query-mode service puts our own credential there. The
path is recorded up to the first `?` and no further.

Because `upstream` and `policy_id` carry the label, an audit line says *which
of a service's keys* served the call — so spend, and a leak, are attributable
to one account rather than to "Tavily".

---

## CLI

```
authinjector list                          catalogue, and which keys are configured
authinjector show                          configured keys — lengths, never values
authinjector add <service> -c <who> [-l <label>] [-r <n>] [-f]
authinjector del <service>[:<label>]
authinjector push-to <service>[:<label>] <dest>...   where that key may be delivered
authinjector import <file> [-f]            service[/label]:key:callers[:rate]
authinjector migrate                       move pre-label entries under `default`
authinjector serve [--check]

authinjector status                        what this caller may use (asks the broker)
authinjector help [service]                overview, or how to call one service
authinjector call <service[:label]> <METHOD> <path> [--data JSON|@file|-] [-H 'Name: value']
authinjector catalogue update [--yes] [--from <https url>]
authinjector gen-docs [--out <dir>]        regenerate skill, rules and docs from the catalogue
```

**For agents: `status`, `help`, `call`.** `call` is plain HTTP/1.1 over the
socket; it prints the upstream body unchanged to stdout and the status line to
stderr, and exits non-zero on 4xx/5xx with what to tell the user (403: allow
this caller with `sudo authinjector add <service> -c <you>`; 404: unknown
service or label; 429: wait). It refuses `Authorization`, `Cookie` and
`Proxy-Authorization` outright: the caller never sends a credential. When the
socket cannot be reached, both commands say whether the broker is not running
or the caller is not in `authinjector-clients`, with the commands to fix it.

**`catalogue update`** fetches `catalogue.toml` from this repository's `main`
over HTTPS (redirects not followed), validates it with the same loader the
broker uses, and prints what was added, removed and changed. A change to
`base_url` or to where the key goes, on a service that has a configured key,
must be confirmed by a person at a terminal; `--yes` does not cover it. The
file is written atomically, then restart the broker.

**A key never arrives as an argument.** `argv` is readable at
`/proc/PID/cmdline` by every user on the box while the command runs, and lands
in shell history besides. `add` reads stdin with echo off; `import` reads a file
whose permissions it checks. `-k` is refused with the reason rather than
ignored.

**An existing key is never replaced by accident.** `add` refuses a label that
already exists — *before* prompting, so nobody types a credential only to have
it rejected — and `import` skips configured keys and reports them, so
re-running an import file does nothing at all. `-f` replaces, and is the
deliberate path for rotation. Writing a key is silent and irreversible (`show`
reports a length, not a value), so a rotation you did not intend would
otherwise look exactly like one you did.

Import format, and why the separators differ:

```
tavily:tvly-xxx:alice:20                 # default label
tavily/blacksq:tvly-aaa:alice:20         # labelled
```

A request path cannot use `/` to mean a label (it already separates the
upstream from the path), and an import line cannot use `:` (a **key may contain
colons**, so `tavily:a:b:alice:20` would be genuinely ambiguous). Fields are
parsed outside-in, so a key with colons survives intact — a truncated key
authenticates as nothing and looks exactly like a revoked one.

---

## Security model

**What it protects against.** A caller cannot print, copy or exfiltrate a
credential, because it never has one. Keys live in one root-owned file the
caller cannot read; the broker runs as its own uid; `ProtectProc=invisible` and
a seccomp filter denying `@debug` stop a caller attaching to the process.
`Secret` is `ZeroizeOnDrop`, has a redacted `Debug`, no `Display`, no
`Serialize`, and exactly one accessor — `grep -rn expose_for_injection src/`
should list one call.

**What it does not.** A caller permitted to reach an upstream can *use* it
freely. The broker stops disclosure, not usage. That is why `callers[]` is
mandatory per key and why a write-capable credential is never listed for an
agent's user — see the separate `cloudflare` and `cloudflare-rw` entries, which
are the same API with very different consequences.

**Startup refuses what can never work:** a service not in the catalogue, empty
`callers`, an empty key, a config that widens the catalogue's endpoints, a key
containing a byte no HTTP header may carry, and a key with leading or trailing
whitespace. Fail loudly, once, while someone can still act on it — not as a 502
per request that points at the network.

**`catalogue update` and what still is not built.** The catalogue decides
`base_url` and which field takes the key, so a tampered one would redirect
credentials while every audit line looked ordinary. What exists: the update is
fetched over HTTPS from GitHub, redirects are refused, the result is validated,
the diff is shown, and any change that would move a configured key to a new
host or slot waits for a human at a terminal. What does not: signatures. The
fetched file is trusted as far as GitHub and this repository are; signing the
catalogue is still to be built.

---

## Building

Fully static, no runtime dependencies.

```bash
cargo install cross                                        # once, needs docker
cross build --release --target x86_64-unknown-linux-musl    # amd64
cross build --release --target aarch64-unknown-linux-musl   # arm64, the VM
```

`Cross.toml` pins the `:main` images deliberately: cross 0.2.5 ships 2022
images whose glibc predates `GLIBC_2.28`, which current Rust build scripts
require, so the aarch64 build dies before any of our code compiles. The pin
affects the build container only; the binaries need no glibc at all.

A native `cargo build --release` links against the host glibc — local
development only, never for distribution.

## Testing

```bash
cargo test                 # 98 unit tests, no network
tests/smoke.sh             # the serving path, against a real upstream
tests/cli.sh               # add / show / list / del / import round trip
```

Both scripts take an optional binary path and default to the x86_64 static
build. Neither needs a credential and neither installs anything.

Two `#[ignore]`d diagnostics exist for when an upstream misbehaves — they print
full error chains with no credential involved:

```bash
cargo test --bin authinjector -- --ignored --nocapture network_diag
cargo test --bin authinjector -- --ignored --nocapture stage_diag
```

`cli.sh` asserts the config keeps its mode after a write. That is not
decoration: `add` writes via a temp file and a rename, a rename replaces the
inode, and the first version handed the config back as `root:root` — after
which the broker could not read its own config and died with an error that
looked nothing like "the command you just ran did this".

## Layout

| Path | What |
|---|---|
| `PROTOCOL.md` | the spec: request shape, catalogue + config, audit schema, conformance |
| `catalogue.toml` | public. What each service is; ships to `/usr/share/authinjector/` |
| `keys.example.txt` | import template, placeholders only |
| `src/secret.rs` | the only type allowed to hold key material |
| `src/inject.rs` | strip-then-set, both transports, and the response scrub |
| `src/config.rs` | the private config and the catalogue+config merge |
| `src/server.rs` | socket listener and the refusal pipeline |
| `src/peer.rs` | `SO_PEERCRED` — identity from the kernel, per connection |
| `systemd/` | unit + socket; the config is root-owned, readable only by the service |
| `install.sh` | users, binary, catalogue, and an **empty** config |

## Operating notes

- **Rotation:** `authinjector add <service> -f` (prompts), then
  `systemctl restart authinjector`. No caller changes anything.
- **The service reads its config itself — there is no `EnvironmentFile`.**
  `EnvironmentFile=` would load every credential into the process environment,
  readable at `/proc/PID/environ` for the life of the process and in a region
  no wipe-on-drop can reach.
- **The socket is created by systemd**, mode `0660`, group
  `authinjector-clients`. The broker never needs write permission in `/run` and
  cannot widen its own access.
- A key that fails to authenticate is usually **scoped, not wrong**. Resend
  answers `"This API key is restricted to only send emails"`; ElevenLabs
  answers `"missing the permission voices_read"`. Both keys work for what they
  are for. Check the message before replacing a key.
