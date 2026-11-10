#!/usr/bin/env bash
# AuthInjector installer. Run as root:
#
#     sudo ./install.sh [--caller USER]...
#
# Idempotent: safe to re-run after a rebuild or a catalogue update.
#
# 🔴 THIS SCRIPT NEVER TOUCHES A CREDENTIAL. It creates config.toml empty and
# root-owned; keys go in afterwards with `authinjector add` or
# `authinjector import`, which read them from stdin or a file -- never from a
# command argument.
#
# Two files, two purposes:
#
#   /usr/share/authinjector/catalogue.toml   what each service IS.
#                                            Public, shipped, no secrets.
#   /etc/authinjector/config.toml            who may use it, and the key.
#                                            0640 root:authinjector.
#
# And two identities:
#
#   user  authinjector          its OWN uid, so no caller can ptrace the broker
#                               or read its config
#   group authinjector-clients  callers join this; it grants socket access and
#                               nothing else
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0"; exit 1; }

CALLERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --caller) CALLERS+=("$2"); shift 2 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
[ ${#CALLERS[@]} -gt 0 ] || CALLERS=("$(logname 2>/dev/null || echo "${SUDO_USER:-$USER}")")

SRC="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
  x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture: $(uname -m)"; exit 1 ;;
esac
# A release tarball ships the binary next to this script; a source checkout
# has it where `cross build` put it.
if [ -x "$SRC/authinjector" ]; then
  BIN="$SRC/authinjector"
else
  BIN="$SRC/target/$TARGET/release/authinjector"
fi
[ -x "$BIN" ] || { echo "no static binary at $BIN -- download a release or build it first (see README)"; exit 1; }

echo "== user and group =="
getent group authinjector-clients >/dev/null || groupadd --system authinjector-clients
id -u authinjector >/dev/null 2>&1 || \
  useradd --system --no-create-home --home-dir /nonexistent \
          --shell /usr/sbin/nologin --user-group authinjector
echo "   authinjector user + authinjector-clients group present"

for u in "${CALLERS[@]}"; do
  if id -u "$u" >/dev/null 2>&1; then
    usermod -aG authinjector-clients "$u"
    echo "   $u added to authinjector-clients"
  else
    echo "   WARNING: user $u does not exist, skipped"
  fi
done

echo "== binary =="
install -m 0755 -o root -g root "$BIN" /usr/local/bin/authinjector
echo "   /usr/local/bin/authinjector ($(stat -c %s /usr/local/bin/authinjector) bytes, static)"

echo "== catalogue (public) =="
install -d -m 0755 -o root -g root /usr/share/authinjector
install -m 0644 -o root -g root "$SRC/catalogue.toml" /usr/share/authinjector/catalogue.toml
echo "   /usr/share/authinjector/catalogue.toml ($(grep -c '^\[services\.' /usr/share/authinjector/catalogue.toml) services)"

echo "== config (private) =="
install -d -m 0755 -o root -g root /etc/authinjector
# 🔴 Created empty and NEVER overwritten. A re-run must not clobber your keys.
if [ ! -f /etc/authinjector/config.toml ]; then
  cat > /etc/authinjector/config.toml <<'SEED'
# AuthInjector private config.
#
# Your keys and who may use them. Never leaves this machine.
# Managed with the CLI -- comments you add here are preserved:
#
#   authinjector list                          what is available
#   authinjector add tavily -c alice -r 20       prompts for the key
#   authinjector add tavily -c alice -l personal a SECOND key for the same service
#   authinjector import keys.txt               batch
#   authinjector show                          what is configured (never keys)
#   authinjector del tavily:personal           remove one key
#
# Every key lives under a label. The label is how it is addressed:
#
#   [services.tavily.default]    ->  /tavily/search
#   [services.tavily.personal]   ->  /tavily:personal/search
#
# Each label has its OWN callers and its own rate limit, so a key can be given
# to one caller and withheld from another.

[services]
SEED
  echo "   /etc/authinjector/config.toml created EMPTY"
else
  echo "   /etc/authinjector/config.toml exists, left untouched"
fi
chown root:authinjector /etc/authinjector/config.toml
chmod 0640 /etc/authinjector/config.toml

# The pre-catalogue layout, if this is an upgrade. Left in place, not deleted:
# it may still hold the only copy of a key.
for old in /etc/authinjector/env /etc/authinjector/upstreams.json; do
  [ -f "$old" ] && echo "   NOTE: $old is from the previous layout and is no longer read"
done || true

install -d -m 0750 -o authinjector -g authinjector /var/log/authinjector

echo "== systemd =="
install -m 0644 "$SRC/systemd/authinjector.socket"  /etc/systemd/system/
install -m 0644 "$SRC/systemd/authinjector.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now authinjector.socket
echo "   socket enabled"

cat <<'NEXT'

== next ==

  authinjector list                        see what is available
  authinjector add pexels -c alice -r 20     type the key at the prompt
  systemctl restart authinjector           pick it up
  authinjector show                        confirm (shows lengths, never keys)

Upgrading from a config written before labels existed:

  authinjector migrate                     moves each key under `default`
                                           (addresses do not change)

Callers must log out and back in for the group to take effect: a shell that was
already running when this script added the group still carries its old group
set, and its calls fail with a bare connection refused that looks nothing like
a permission problem. To test without logging out, borrow the group for one
command:

  sg authinjector-clients -c 'curl --unix-socket \
      /run/authinjector/authinjector.sock http://localhost/_broker/health'

Then, from a fresh login and holding no credential at all:

  curl --unix-socket /run/authinjector/authinjector.sock \
       http://localhost/_broker/health

NEXT
