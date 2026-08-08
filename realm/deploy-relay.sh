#!/usr/bin/env bash
# Deploy the relay to a host you already have SSH access to.
#
#   ./deploy-relay.sh user@host [relay-dir]
#
# Copies the relay, generates a NONCE_SECRET if the host does not have one,
# rebuilds, and verifies. Safe to run repeatedly: an existing secret is left
# alone so restarting does not invalidate credentials mid-session.
set -euo pipefail

TARGET="${1:?usage: deploy-relay.sh user@host [relay-dir]}"
# Point KEY at a private key outside this repo. Never copy one in here.
# One multiplexed connection for the whole run. Opening a fresh session per
# step trips fail2ban and similar, which bans the source mid-deploy and leaves
# you locked out of the box you were deploying to.
CTL="${TMPDIR:-/tmp}/deploy-relay-%r@%h:%p"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15
          -o ControlMaster=auto -o "ControlPath=$CTL" -o ControlPersist=120)
[ -n "${KEY:-}" ] && SSH_OPTS+=(-i "$KEY")
ssh_run(){ ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
cleanup(){ ssh "${SSH_OPTS[@]}" -O exit "$TARGET" 2>/dev/null || true; }
trap cleanup EXIT
SRC="${2:-$(cd "$(dirname "$0")" && pwd)/relay}"
REMOTE_DIR="~/realm-relay"

[ -d "$SRC" ] || { echo "no such directory: $SRC" >&2; exit 1; }
[ -f "$SRC/compose.yaml" ] || { echo "$SRC has no compose.yaml" >&2; exit 1; }

echo "==> testing locally before shipping anything"
( cd "$SRC" && node --test test/*.test.mjs >/dev/null 2>&1 ) \
  && echo "    tests pass" \
  || { echo "    tests FAIL, refusing to deploy" >&2; exit 1; }

echo "==> copying $SRC to $TARGET:$REMOTE_DIR"
ssh_run "mkdir -p $REMOTE_DIR"
rsync -a --delete \
  --exclude node_modules --exclude .DS_Store --exclude .env \
  -e "ssh ${SSH_OPTS[*]}" "$SRC"/ "$TARGET:$REMOTE_DIR/"

echo "==> ensuring a NONCE_SECRET exists on the host"
# Generated on the host and never printed here, so it stays out of local shell
# history and scrollback. Left alone if already present.
ssh_run "cd $REMOTE_DIR && \
  if [ ! -f .env ]; then \
    printf 'NONCE_SECRET=%s\nRELAY_REALM=realm-relay\nPERSIST_MESSAGES=false\n' \
      \"\$(openssl rand -hex 32)\" > .env && chmod 600 .env && echo '    created .env'; \
  else echo '    .env already present, leaving it'; fi"

echo "==> building and starting"
ssh_run "cd $REMOTE_DIR && docker compose up -d --build"

echo "==> health check on the host"
# compose binds 8080 to 127.0.0.1, so this only answers from the box itself.
ssh_run "curl -sS -m 5 localhost:8080/health && echo" \
  || echo "    health check failed, see: ssh $TARGET 'cd $REMOTE_DIR && docker compose logs --tail 50'"

echo "==> listening sockets"
ssh_run "ss -ulnp 2>/dev/null | grep -E '347[89]|348[0-3]' || echo '    no UDP lanes bound'"

HOSTNAME_ONLY="${TARGET#*@}"
cat <<EOF

Deployed. Verify reachability from here, which also tests the security group:

  python3 local/stunping.py $HOSTNAME_ONLY

A running relay answers every lane with a binding success or a 401. Silence on
all six means the security group is not admitting UDP 3478-3483 from this
address.

Restrict those ports to the addresses that need them. An open TURN relay is an
open packet forwarder, and the rate limiter in server.mjs bounds how fast one
source can shout rather than which sources may shout at all.
EOF
