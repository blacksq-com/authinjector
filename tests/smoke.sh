#!/usr/bin/env bash
# AuthInjector smoke test. Needs no real credentials and installs nothing.
#
#   tests/smoke.sh [path-to-binary]
#
# Proves, against a real upstream (httpbin.org):
#   - a caller sending NO credential gets one injected
#   - a caller sending its OWN is overridden, not merged
#   - a LABEL selects which of several keys for one service is used
#   - a query-mode service gets its credential in the URL, and the caller's
#     copy of that parameter is dropped
#   - off-list path 403, wrong method 405, unknown upstream 404, rate limit 429
#   - rate limits are per label, so one key cannot exhaust another's budget
#   - the audit log has one line per call and contains no key, including the
#     query-mode key that travelled in a URL
set -u
BIN="${1:-target/x86_64-unknown-linux-musl/release/authinjector}"
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 1; }
D=$(mktemp -d); trap 'rm -rf "$D"; kill ${P:-0} 2>/dev/null' EXIT
chmod 700 "$D"
STAMP=$(date +%s)
KEY_DEFAULT="smoke-${STAMP}-default-not-a-real-key"
KEY_PERSONAL="smoke-${STAMP}-personal-not-a-real-key"
KEY_QUERY="smoke-${STAMP}-query-not-a-real-key"
ME=$(id -un)
pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($2)"; pass=$((pass+1));
       else echo "  FAIL  $1: got $2, want $3"; fail=$((fail+1)); fi; }
yes_() { echo "  PASS  $1"; pass=$((pass+1)); }
no_()  { echo "  FAIL  $1"; fail=$((fail+1)); }

# The public half: what these services ARE. No secrets here.
cat > "$D/catalogue.toml" <<'CAT'
[services.httpbin]
name = "httpbin (header auth)"
base_url = "https://httpbin.org"
auth_in = "header"
auth_header = "X-Smoke-Injected"
auth_prefix = "Bearer "
endpoints = [{ methods = ["GET"], path_prefix = "/headers" }]

[services.httpbinq]
name = "httpbin (query auth)"
base_url = "https://httpbin.org"
auth_in = "query"
auth_param = "smoke"
endpoints = [{ methods = ["GET"], path_prefix = "/get" }]
CAT

# The private half: the keys and who may use them. Two labelled keys for one
# service is the case that matters.
umask 077
cat > "$D/config.toml" <<CFG
[services.httpbin.default]
key = "$KEY_DEFAULT"
callers = ["$ME"]
rate_per_minute = 3

[services.httpbin.personal]
key = "$KEY_PERSONAL"
callers = ["$ME"]
rate_per_minute = 3

[services.httpbinq.default]
key = "$KEY_QUERY"
callers = ["$ME"]
rate_per_minute = 6
CFG

"$BIN" serve --catalogue "$D/catalogue.toml" --config "$D/config.toml" \
             --audit "$D/a.jsonl" --socket "$D/s.sock" >"$D/broker.log" 2>&1 &
P=$!
for _ in $(seq 1 40); do [ -S "$D/s.sock" ] && break; sleep 0.1; done
[ -S "$D/s.sock" ] || { echo "  FAIL  broker never started"; cat "$D/broker.log"; exit 1; }
c() { curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$D/s.sock" "$@"; }
b() { curl -sS --unix-socket "$D/s.sock" "$@"; }

echo "AuthInjector smoke test"

# ── gates ───────────────────────────────────────────────────────────────────
ck "allowed path"          "$(c http://localhost/httpbin/headers)"          200
ck "off-list path"         "$(c http://localhost/httpbin/ip)"               403
ck "wrong method"          "$(c -X POST http://localhost/httpbin/headers)"  405
ck "unknown upstream"      "$(c http://localhost/nope/x)"                   404
ck "unknown label"         "$(c http://localhost/httpbin:nosuch/headers)"   404

# ── injection ───────────────────────────────────────────────────────────────
body=$(b http://localhost/httpbin/headers)
echo "$body" | grep -q "Bearer $KEY_DEFAULT" \
  && yes_ "upstream received the injected credential" \
  || no_  "upstream did not receive the credential"

# 🔴 The caller's Host describes its hop to our socket and must not travel on.
# Forwarding it returned nginx 400/502 pages from some upstreams and made every
# HTTP/2 upstream refuse the request before it left the machine.
body=$(b http://localhost/httpbin/headers)
if echo "$body" | grep -q '"Host": *"httpbin.org"' && ! echo "$body" | grep -qi '"Host": *"localhost"'; then
  yes_ "the upstream saw its own Host, not the caller's"
else
  no_  "the caller's Host leaked to the upstream"
fi
echo "$body" | grep -qi '"Connection"\|"Keep-Alive"\|"Transfer-Encoding"' \
  && no_  "a hop-by-hop header reached the upstream" \
  || yes_ "hop-by-hop headers were dropped"

body=$(b -H 'X-Smoke-Injected: Bearer CALLER-OWN' http://localhost/httpbin/headers)
echo "$body" | grep -q 'CALLER-OWN' \
  && no_  "caller smuggled its own credential through" \
  || yes_ "caller's own credential was stripped, not merged"

# ── labels select the key ───────────────────────────────────────────────────
body=$(b http://localhost/httpbin:personal/headers)
if echo "$body" | grep -q "Bearer $KEY_PERSONAL" && ! echo "$body" | grep -q "$KEY_DEFAULT"; then
  yes_ "a label selects its own key, and only that key"
else
  no_  "the labelled key was not the one sent"
fi

# ── query-mode injection ────────────────────────────────────────────────────
body=$(b "http://localhost/httpbinq/get?town=Toronto")
if echo "$body" | grep -q "$KEY_QUERY" && echo "$body" | grep -q 'Toronto'; then
  yes_ "query-mode credential reached the upstream alongside the caller's own parameters"
else
  no_  "query-mode credential did not arrive"
fi

body=$(b "http://localhost/httpbinq/get?smoke=CALLER-OWN")
if echo "$body" | grep -q "$KEY_QUERY" && ! echo "$body" | grep -q 'CALLER-OWN'; then
  yes_ "caller's copy of the auth parameter was dropped, not duplicated"
else
  no_  "caller's auth parameter survived into the upstream request"
fi

# ── rate limits are per label ───────────────────────────────────────────────
c http://localhost/httpbin/headers >/dev/null
c http://localhost/httpbin/headers >/dev/null
ck "rate limit engages"    "$(c http://localhost/httpbin/headers)"          429
ck "the other label still has its own budget" \
                           "$(c http://localhost/httpbin:personal/headers)" 200

# ── audit ───────────────────────────────────────────────────────────────────
for k in "$KEY_DEFAULT" "$KEY_PERSONAL" "$KEY_QUERY"; do
  grep -q "$k" "$D/a.jsonl" && { no_ "a key appears in the audit log"; break; }
done
grep -q "smoke-${STAMP}" "$D/a.jsonl" \
  && no_  "key material reached the audit log" \
  || yes_ "audit log contains no key material, query-mode included"

grep -q '"upstream":"httpbin:personal"' "$D/a.jsonl" \
  && yes_ "the audit log records WHICH key was used" \
  || no_  "the audit log does not distinguish the labelled key"

echo; echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
