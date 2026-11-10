#!/usr/bin/env bash
# AuthInjector CLI round trip. Fake keys, a temp config, nothing installed.
#
#   tests/cli.sh [path-to-binary]
#
# smoke.sh proves the SERVING path. This proves the path a person actually
# types first -- add, show, list, del, import -- against a config seeded the
# way install.sh seeds it.
#
# 🔴 THE OWNERSHIP AND MODE CHECKS ARE NOT DECORATION. `add` writes via a temp
# file and a rename, and a rename replaces the inode. The first version of that
# code handed the config back as root:root, the broker could then not read its
# own config, and the service died with an error that looked nothing like "the
# command you just ran did this". That regression is cheap to reintroduce and
# expensive to diagnose, so it is asserted here every run.
set -u
BIN="${1:-target/x86_64-unknown-linux-musl/release/authinjector}"
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 1; }
[ -f catalogue.toml ] || { echo "run from the repo root"; exit 1; }

D=$(mktemp -d); trap 'rm -rf "$D"' EXIT; chmod 700 "$D"
cp catalogue.toml "$D/catalogue.toml"

# Seeded exactly as install.sh seeds it, comment block and all.
cat > "$D/config.toml" <<'SEED'
# AuthInjector private config.
#
# KEEP-THIS-COMMENT — proves the writer preserves what you annotate.

[services]
SEED
chmod 640 "$D/config.toml"

A="$BIN --catalogue $D/catalogue.toml --config $D/config.toml"
ok=0; bad=0
say() { if [ "$1" = ok ]; then echo "  PASS  $2"; ok=$((ok+1));
        else echo "  FAIL  $2"; bad=$((bad+1)); fi; }

echo "AuthInjector CLI round trip"

# ── add, including two labels for one service ───────────────────────────────
echo "fake-pexels-default-key"  | $A add pexels -c alice -r 20             >/dev/null 2>&1
echo "fake-pexels-personal-key" | $A add pexels -c alice -l personal -r 5  >/dev/null 2>&1
echo "fake-tavily-key"          | $A add tavily -c alice,svc-blacksq       >/dev/null 2>&1

n=$($A show 2>/dev/null | tail -n +2 | wc -l)
[ "$n" = 3 ] && say ok "add wrote 3 keys, incl. two labels for one service" \
             || say no "expected 3 keys, got $n"

$A show 2>/dev/null | grep -q '^pexels:personal' \
  && say ok "show lists a labelled key by the address you call it with" \
  || say no "show is missing pexels:personal"

$A show 2>/dev/null | grep -qE 'fake-' \
  && say no "show leaked key material" \
  || say ok "show prints lengths, never values"

$A list 2>/dev/null | grep -q 'pexels, pexels:personal' \
  && say ok "list shows every configured label" \
  || say no "list did not show both labels"

# ── the file you are invited to read stays readable ─────────────────────────
grep -q 'KEEP-THIS-COMMENT' "$D/config.toml" \
  && say ok "your comments survived the writes" || say no "a comment was eaten"
grep -q '^\[services\]' "$D/config.toml" \
  && say ok "the [services] header survived" || say no "the [services] header was eaten"
[ "$(stat -c %a "$D/config.toml")" = 640 ] \
  && say ok "mode is still 0640 after add" \
  || say no "mode became $(stat -c %a "$D/config.toml") — the broker would stop reading its config"

$A serve --check >/dev/null 2>&1 \
  && say ok "the written config validates" || say no "the written config fails --check"

# ── del is per label ────────────────────────────────────────────────────────
$A del pexels:personal >/dev/null 2>&1
if $A show 2>/dev/null | grep -q '^pexels ' && ! $A show 2>/dev/null | grep -q 'pexels:personal'; then
  say ok "del removed one label and left its sibling"
else
  say no "del of one label hit the wrong key"
fi

$A del pexels >/dev/null 2>&1
grep -q 'services.pexels' "$D/config.toml" \
  && say no "an empty [services.pexels] was left behind" \
  || say ok "removing the last label removed the emptied service section too"
$A serve --check >/dev/null 2>&1 \
  && say ok "config still validates after dels" || say no "dels left an unstartable config"

# ── import, with labels ─────────────────────────────────────────────────────
cat > "$D/keys.txt" <<'IMP'
# labelled batch
tavily/blacksq:tvly-aaa:alice:20
tavily/personal:tvly-bbb:alice:5
geocoding:AIza-ccc:alice
IMP
chmod 600 "$D/keys.txt"
$A import "$D/keys.txt" >/dev/null 2>&1
n=$($A show 2>/dev/null | tail -n +2 | wc -l)
[ "$n" = 4 ] && say ok "import wrote 3 more keys beside the existing one" \
             || say no "expected 4 keys after import, got $n"
$A show 2>/dev/null | grep -q '^tavily:blacksq' \
  && say ok "import honoured the service/label form" || say no "import ignored labels"
$A serve --check >/dev/null 2>&1 \
  && say ok "the imported config validates" || say no "the imported config fails --check"

# ── the rule that does not bend ─────────────────────────────────────────────
$A add pexels -c alice -k some-secret >/dev/null 2>&1 \
  && say no "-k was accepted — a key must never come from argv" \
  || say ok "-k is refused"

# ── an existing key is never replaced by accident ───────────────────────────
#
# 🔴 THE REGRESSION THIS CATCHES. Both writers used to overwrite silently, so
# re-running an import file -- a template still holding placeholders, say --
# replaced every working key and the first sign of it was a 401 from an
# upstream. Re-running must be a no-op.

before=$($A show 2>/dev/null | tail -n +2 | wc -l)
out=$($A import "$D/keys.txt" 2>&1)
echo "$out" | grep -q 'nothing to do' \
  && say ok "re-importing the same file does nothing" \
  || say no "re-import did not report a no-op"
[ "$($A show 2>/dev/null | tail -n +2 | wc -l)" = "$before" ] \
  && say ok "re-import left the key count unchanged" || say no "re-import changed the config"

# A placeholder must not be able to overwrite a real key without -f.
sed 's/tvly-aaa/PLACEHOLDER/' "$D/keys.txt" > "$D/keys2.txt"; chmod 600 "$D/keys2.txt"
$A import "$D/keys2.txt" >/dev/null 2>&1
# tvly-aaa is 8 chars, PLACEHOLDER is 11. Still 8 means the write was refused.
$A show 2>/dev/null | grep '^tavily:blacksq' | grep -q ' 8 chars' \
  && say ok "a placeholder could not overwrite a configured key without -f" \
  || say no "a placeholder overwrote a configured key without -f"

# -f is the deliberate escape hatch, and it must actually work.
$A import "$D/keys2.txt" -f >/dev/null 2>&1
$A show 2>/dev/null | grep '^tavily:blacksq' | grep -q ' 11 chars' \
  && say ok "-f replaces an existing key" || say no "-f did not replace the key"

# Mixed file: one new line beside already-configured ones.
printf 'openai:sk-brandnew:alice:10\n' >> "$D/keys2.txt"
out=$($A import "$D/keys2.txt" 2>&1)
echo "$out" | grep -q 'skipped' \
  && say ok "a mixed file imports the new line and skips the rest" \
  || say no "a mixed file did not report skips"
$A show 2>/dev/null | grep -q '^openai' \
  && say ok "the new line in a mixed file was written" || say no "the new line was not written"

# add refuses an existing label, and -f lets it through.
echo "another-key" | $A add openai -c alice >/dev/null 2>&1 \
  && say no "add overwrote an existing label without -f" \
  || say ok "add refuses an existing label"
echo "replacement-key" | $A add openai -c alice -f >/dev/null 2>&1 \
  && say ok "add -f replaces an existing label" || say no "add -f failed"
echo "sibling-key" | $A add openai -c alice -l second >/dev/null 2>&1
$A show 2>/dev/null | grep -q '^openai:second' \
  && say ok "a new label alongside an existing one still just works" \
  || say no "adding a sibling label was blocked"

$A serve --check >/dev/null 2>&1 \
  && say ok "config validates after the skip/force round" || say no "config broken after skip/force"

# ── migrate is idempotent ───────────────────────────────────────────────────
$A migrate 2>&1 | grep -q 'nothing to migrate' \
  && say ok "migrate on an already-labelled config changes nothing" \
  || say no "migrate touched an already-labelled config"

echo; echo "  $ok passed, $bad failed"
[ "$bad" -eq 0 ]
