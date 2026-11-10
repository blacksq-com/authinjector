# AuthInjector protocol

**Spec first, implementation second** (ruled in `2026-09-17-secretless-broker.md`).

The `authinjector` binary implements this. **Rust, one implementation, no
prototype** — the binary running on our VM
is the same binary a customer would run if the hosted product ever unparks, so
nothing is written twice and the protocol is the thing both ends agree on.

A static binary with no runtime is a tool dropped on the box like `nmap` or
`testssl.sh`, so this does not touch the standing ruling that the VM's own
services are Python.

---

## 1. Why this exists

An agent that can run commands can print any credential within its reach. Four
leaks in this workspace since August, the last one straight through a blocklist
written after the third. Blocklists enumerate the ways to print an environment;
that set is not enumerable. In one session alone three distinct routes appeared:
a backtick inside a double-quoted string, `${!name}` indirection, and a plain
`$VAR` expanded into captured output.

**So the control is absence, not prohibition.** The caller never holds a key.
A process beside it does, under a different user, and every outbound call is
made through that process.

### What this does NOT solve

🔴 **The broker stops a caller printing a key. It does not stop a caller using
one.** A caller that can reach the socket can make any call the policy allows,
at any volume. For a read-only upstream that is an acceptable trade. For an
upstream that sends mail, moves money or changes infrastructure it is not, and
the answer is policy (§4), not the socket's existence.

Two properties do the real work, and both are per-caller, not per-broker:

- an upstream a caller is not permitted to reach is refused
- a credential a caller must never hold is never resolvable by that caller

---

## 2. Transport

| | Local broker (built now) | Hosted agent (parked) |
|---|---|---|
| Transport | HTTP over a Unix domain socket | mTLS to `localhost` |
| Identity | peer credentials of the connecting process (`SO_PEERCRED`) | client certificate |

🔴 **Identity is the kernel's answer, never the caller's claim.** The local
broker reads uid/gid from `SO_PEERCRED` on the accepted connection. It must
never accept an identity asserted in a header, a query parameter or a body
field. A caller can write any header it likes; it cannot forge the uid the
kernel reports.

Filesystem permission on the socket is a coarse first gate, not the policy. Two
callers in the same group are distinct principals and are policed separately.

## 3. Request shape

```
{METHOD} /{upstream}/{path...}
```

- `{upstream}` — the first path segment, naming one configured KEY. It is
  `{service}` for the key labelled `default`, and `{service}:{label}` for every
  other. Unknown: **404**, and nothing is forwarded.
- `{path...}` — everything after, appended to the upstream's `base_url`.
- Query string, body and headers pass through **except** the field the
  credential occupies (§4), plus `Authorization`, `Cookie` and
  `Proxy-Authorization`.

🔴 **THE LABEL IS THE ADDRESS, AND IT IS THE SAME STRING EVERYWHERE.** The
first path segment, the policy map key, the secrets map key, the rate-limit
bucket and the `upstream` field of the audit line are one string, built in one
place. There is no resolution step that could disagree with another, and so no
way for a call to be served by one key and attributed to a different one.

A service need not have a `default`. If every key is labelled, the bare
`/{service}/...` form returns 404 and the body lists the labels that do exist.

🔴 **The injected field is stripped from the inbound request before ours is
set, never merely overwritten.** A caller must not be able to influence the
credential slot, including by sending a differently-cased duplicate header or
a percent-encoded duplicate query parameter. Strip first, then set.

The broker returns the upstream response unchanged: status, headers, body. It
is a proxy, not a client library. It parses no payloads.

## 4. Catalogue and config

🔴 **TWO FILES, AND ONLY ONE OF THEM HOLDS A SECRET.**

| File | Holds | Mode |
|---|---|---|
| `/usr/share/authinjector/catalogue.toml` | what each service IS | public, shipped |
| `/etc/authinjector/config.toml` | the keys, and who may use them | `0640 root:authinjector` |

The split is why supporting a new service is a catalogue update rather than a
change every user makes by hand. *Where Tavily lives and which header it wants*
is identical for everyone who uses Tavily; only the key and the permission are
yours. Note the asymmetry: a catalogue entry is per **service**, while a config
may hold several labelled keys for that one service.

### The catalogue — public, no secrets

```toml
[services.tavily]
name = "Tavily"
base_url = "https://api.tavily.com"
auth_in = "header"              # or "query"
auth_header = "Authorization"
auth_prefix = "Bearer "         # "" for a raw key header
signup_url = "https://tavily.com/"
cost_per_call_cad = 0.008
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]
```

| Field | Meaning |
|---|---|
| `base_url` | scheme + host. **https only** — a plaintext entry is refused at load |
| `auth_in` | `header` (default) or `query` |
| `auth_header` / `auth_prefix` | header mode: the broker sets `auth_header: <prefix><key>` |
| `auth_param` | query mode: the broker appends `?<auth_param>=<key>`, percent-encoded |
| `endpoints[]` | everything the service offers; a config may narrow this, never widen it |
| `cost_per_call_cad` | indicative; feeds the audit line and the site check's cost line |

Exactly one of `auth_header` and `auth_param` may be populated, and it must be
the one `auth_in` names. An entry carrying both is refused at load: where a
credential goes must never depend on which branch of the injector happened to
run. `auth_param` is restricted to letters, digits, `_`, `-` and `.`, because
it is spliced into a URL.

🔴 **QUERY MODE IS THE WEAKER OF THE TWO AND IS NEVER THE DEFAULT.** The
credential travels in the URL, so it reaches the upstream's access logs and any
intermediary between here and there. We strip it from our own audit line (§5);
we cannot strip it from theirs. It exists because several services accept
nothing else, and the alternative to brokering those keys is the caller holding
them — which is worse. Prefer a header wherever a service offers both.

🔴 **THE CATALOGUE ROUTES CREDENTIALS.** `base_url` together with the auth
field decides which host receives a key and in which slot. A catalogue swapped
by an attacker would redirect every credential while the audit log recorded a
perfectly ordinary forward. So a fetched catalogue must be signature-verified
before it is written, and `catalogue update` must show a diff and wait for a
human for any service already configured. **Neither is implemented yet; both
belong before the fetch command exists, not after.**

### The config — private, one key per label

```toml
[services.tavily.default]
key = "tvly-..."
callers = ["svc-blacksq", "code"]
rate_per_minute = 20

[services.tavily.personal]
key = "tvly-..."
callers = ["alice"]
rate_per_minute = 5
```

| Field | Meaning |
|---|---|
| table name | `[services.{service}.{label}]`; label `default` is addressed bare |
| `key` | the credential — the only secret in either file |
| `callers[]` | usernames permitted to use **this key** (§2 identity) |
| `rate_per_minute` | per caller, per key |
| `endpoints[]` | optional NARROWING of the catalogue's list |
| `version` | increments when the block changes; appears in `policy_id` |

🔴 **PERMISSION IS PER KEY, NOT PER SERVICE.** `callers`, the rate limit and
any narrowing all attach to the label. That is the whole point of labels:
*"alice may use the Black Squid account, the build service may not"* is not a
sentence a single key per service can express, and a broker that cannot express
it will be given the more privileged key by default.

A configured service absent from the catalogue is a **startup error**, not a
warning — it is a typo or a stale catalogue, and either way it should be heard
about while someone can still act on it.

**Default deny, three times over:** unknown upstream, caller not in `callers`,
or path/method not matching the allowlist — all refused, nothing forwarded.

### Refusal codes

| Code | Meaning |
|---|---|
| 404 | unknown upstream id, or a service addressed bare that has no `default` label |
| 403 | caller not permitted, or path/method off the allowlist |
| 429 | per-caller rate limit exceeded |
| 502 | upstream unreachable |
| 503 | the key for that label is unavailable (unreachable: §6 refuses to start) |

## 5. Audit

One line per call, append-only, JSON. This is also where the site check's cost
line comes from, so the schema lives here and is not duplicated in that repo.

```json
{"ts":"2026-09-17T20:14:02Z","caller":"code","uid":1000,"upstream":"tavily",
 "method":"POST","path":"/search","status":200,"bytes_in":142,"bytes_out":8311,
 "duration_ms":740,"cost_cad":0.008,"policy_id":"tavily@3","outcome":"forwarded"}
```

🔴 **Never log request or response bodies. Never log any request header.**

Not "never log the header the broker added" — *no request headers at all*. An
allowlist of headers-not-to-log is the same enumeration mistake as a blocklist
of ways-to-print-an-environment, one layer down. A caller that puts a token in
`X-Debug` would have it written to disk by a broker that logs everything except
one known name.

🔴 **Never log a query string.** `?key=`, `?api_key=` and `?access_token=` are
all live conventions, and a query-mode service (§4) puts our own credential
there. The path is recorded up to the first `?` and no further, so neither the
caller's parameters nor ours can reach the file whose promise is that it holds
no secret.

`policy_id` is `{id}@{n}`, where `n` increments whenever that key's config
block changes, so an audit line is attributable to the exact rule in force.
Because `id` carries the label, `upstream` and `policy_id` also say **which of
a service's keys served the call** — so spend, and a leak, are attributable to
one account rather than to "Tavily".

## 6. Secret handling

- A key appears in **exactly one place**: `config.toml`, mode `0640
  root:authinjector`. Never in an audit line, never in an error, never in any
  response to a caller.
- 🔴 **The broker opens that file itself. It is NOT an `EnvironmentFile`.**
  systemd's `EnvironmentFile=` would load every credential into the process
  environment, where it is readable at `/proc/PID/environ` for the life of the
  process and sits in a region no wipe-on-drop can reach. Reading the file
  directly means key material goes straight into a zeroizing type and never
  enters the environment at all — which is what makes the memory check in §8
  meaningful rather than theatre.
- 🔴 **A key is never accepted as a command argument.** `argv` is readable at
  `/proc/PID/cmdline` by every user on the box for as long as the command runs,
  and lands in shell history besides. `add` reads from stdin with echo off;
  `import` reads a file whose permissions it checks. There is no `--key` flag,
  and passing one is refused with the reason rather than ignored.
- An error never quotes back the line, the URL or the headers that carried a
  credential. A transport failure is described by its kind, because the
  underlying client's own error text includes the URL — which, for a query-mode
  service, is the key.
- The config is read once **at start**. A blank or missing key is a startup
  error naming the service and label, not a runtime 500 per request: fail
  loudly, once, while someone can still act on it.
- The broker exposes no route that returns, echoes or confirms a key. There is
  no "test my credential" endpoint; a real call to the upstream is the test.
- Rotation is: `authinjector add <service>` (which prompts) or edit the file as
  root, then `systemctl restart authinjector`. No caller changes anything.

## 7. Health and introspection

`GET /_broker/health` →

```json
{"ok":true,"caller":"alice","upstreams":[
  {"id":"tavily","service":"tavily","label":"default",
   "allow":[{"methods":["POST"],"path_prefix":"/search"}],"rate_per_minute":20},
  {"id":"tavily:personal","service":"tavily","label":"personal",
   "allow":[{"methods":["POST"],"path_prefix":"/search"}],"rate_per_minute":5}]}
```

A caller may list **the keys it is itself permitted to use**, with their allow
rules and rate limits. That is deliberate: a caller needs to know what it may
do, and `id` is exactly the string it must put in a request path. It reveals no
key material and no other caller's permissions — a key whose `callers` omits
the requester does not appear at all, so the response doubles as the answer to
"which accounts am I trusted with?"

## 8. Conformance

An implementation conforms when all hold:

1. An allowed request succeeds and the upstream sees the credential.
2. The same request from a caller outside `callers[]` returns 403.
3. A path outside the allowlist returns 403 and never reaches the upstream;
   a known path with an unlisted method returns 405.
4. A caller-supplied credential field is stripped, not forwarded and not
   merged — including a differently-cased header name, and a percent-encoded
   query parameter name that decodes to the one we inject.
5. Exceeding `rate_per_minute` returns 429 and does not reach the upstream.
6. **Two labelled keys for one service are independently addressable:** each
   request carries the key its label names and no other, each label enforces
   its own `callers`, and exhausting one label's rate limit leaves its
   sibling's budget untouched.
7. A query-mode service receives its credential in the URL, the caller's own
   copy of that parameter is gone, and a key containing `&` or `=` cannot
   introduce a second parameter.
8. The audit log contains the call and no header, body or secret — including
   the credential of a query-mode service, which travelled in a URL, and it
   records which label served the call.
9. `strings` over the log and the config yields no credential.
10. Reading the broker process's memory as the caller's user is **permission
    denied** — the property `strings` on a file cannot demonstrate, and the one
    the design actually rests on.

---

# Part 2 additions: enrolment and secret storage

Everything above describes the broker resolving a key **locally**, by reading
its own root-owned `config.toml` (§6). This section describes resolving one
**remotely**, from the hosted service. Same binary, same request path, same
labels, different resolver.

🔴 **The portal never receives, holds or can derive a plaintext secret.** It
authorises and it records. If a design change would require the portal to see a
value, the design change is wrong.

## 9. Why the value is never typed into a web page

If a customer pastes a key into a page we serve, we serve the JavaScript that
encrypts it — and could serve different JavaScript to one targeted customer
tomorrow. That reduces *"we have never had your key"* to *"trust today's
bundle"*. So enrolment and `secret add` happen in the **binary**, which is
versioned, hashable and installed deliberately.

The portal handles teams, devices, policy, audit, spend and revocation, and
displays secret **names** and metadata. Never a value.

## 10. Identity: per-device keypair

At `authinjector enrol --code <code>`:

- The agent generates an **X25519 keypair**. The private key never leaves the
  device — OS keyring or a `0600` file, TPM-sealed where available; DPAPI/CNG
  on Windows.
- The agent registers its **public key** and a device name against the account.
- The device gets an mTLS client certificate for calling the service. That is
  *identity*, and it is separate from the crypto: a stolen certificate lets an
  attacker ask for ciphertext they still cannot decrypt.

🔴 **No account-wide passphrase-derived KEK.** A shared KEK can be phished,
must be typed on every device, and cannot be revoked for one laptop without
re-keying every secret. Per-device keys give per-device revocation.

## 11. `secret add`: what leaves the machine

```
authinjector secret add TAVILY_API_KEY
```

🔴 **The value is read from stdin, never from argv.** There is no `--value`
flag, and there will not be one. A value in argv is written to shell history
and is visible in `ps` to every user on the box.

1. Agent generates a random **data key** (DEK) and AEAD-encrypts the value.
2. Agent wraps the DEK **to every enrolled device's public key** — one wrap per
   device, so any of the account's devices can open it and no shared secret
   exists.
3. Agent `POST`s `{name, ciphertext, wraps[]}` to the service. **No plaintext,
   no DEK, no private key.**
4. Service wraps the whole blob again with the **per-tenant key** it holds in
   Secrets Store, and stores the result.
5. Agent zeroizes the DEK and the plaintext buffer.

Stored at rest: `E_ours(E_devices(value))`. A full breach of our storage *and*
our tenant key yields `E_devices(value)` — which we cannot open, because no
device private key has ever been sent to us.

## 12. Retrieval at call time

1. Agent requests the secret **by name** over mTLS.
2. Service checks policy — device identity, revocation, upstream, path, rate,
   time window — then strips **only its own layer** and returns the blob.
   Refusals and grants are both audited.
3. Agent unwraps the DEK with its device private key, decrypts, injects the
   header, sends the upstream request, then zeroizes.

Plaintext exists only in agent memory, only for the duration of one request.

**Revocation cuts from either end:** the service refuses to unwrap, or the
customer destroys the device key. Either alone is sufficient, which is the
point — a customer who stops trusting us is not asking our permission.

## 13. Portability

Both are traits from the start, because the VM binary and the customer binary
are the same binary:

| | Linux | Windows |
|---|---|---|
| Local transport | Unix domain socket, `SO_PEERCRED` | named pipe, `GetNamedPipeClientProcessId` |
| Device key storage | kernel keyring / `0600` file, TPM-sealed where present | DPAPI or CNG, TPM where present |

## 14. Residual exposure, stated plainly

Say these out loud in the product, because a serious evaluator will find them.

- **Agent process memory** during a call. Mitigated by its own uid (an AI agent
  on the same box cannot `ptrace` it) and by `zeroize`. This is the whole
  reason for Rust, and Stage 5 test 3 is what proves it.
- **A compromised customer device** yields that device's private key. Revoke the
  device; other devices and other secrets are untouched.
- **Device enrolment and recovery** is the hard operational problem, not the
  cryptography: a new device needs an existing device to approve, or an offline
  recovery key.
- **Our availability.** If the service is unreachable the agent cannot get its
  layer stripped, hence a policy-bounded cache of our-layer-stripped ciphertext.
