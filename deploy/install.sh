#!/usr/bin/env bash
# NyanCoin server installer for Linux with systemd (Debian/Ubuntu/Fedora/RHEL-likes).
#
#   sudo ./deploy/install.sh --public-url https://YOUR.IP:8001        # public seed node
#   sudo ./deploy/install.sh                                          # private node (localhost only)
#   sudo ./deploy/install.sh --public-url https://IP:8001 --miner NYAN...   # node + miner
#   sudo ./deploy/install.sh --uninstall                              # remove (keeps chain data)
#
# Re-running it upgrades the code and keeps your data, keys and settings.
set -euo pipefail

PORT=8001
PUBLIC_URL=""
PEERS=()
MINER=""
MINER_PROCS=""
UNINSTALL=0

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-url) PUBLIC_URL="${2:?--public-url needs a value}"; shift 2 ;;
    --port)       PORT="${2:?--port needs a value}"; shift 2 ;;
    --peer)       PEERS+=("${2:?--peer needs a value}"); shift 2 ;;
    --miner)      MINER="${2:?--miner needs an address}"; shift 2 ;;
    --procs)      MINER_PROCS="${2:?--procs needs a number}"; shift 2 ;;
    --uninstall)  UNINSTALL=1; shift ;;
    -h|--help)    usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root, e.g. sudo $0 $*"
command -v systemctl >/dev/null || die "systemd is required (or use the Docker setup instead)"
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1024 || PORT > 65535 )); then die "--port must be 1024-65535"; fi
[[ -z "$PUBLIC_URL" || "$PUBLIC_URL" == https://* ]] || die "--public-url must start with https://"
[[ -z "$MINER" || "$MINER" =~ ^NYAN[0-9a-f]{44}$ ]] || die "--miner must be a NYAN... address"
[[ -z "$MINER_PROCS" || "$MINER_PROCS" =~ ^[0-9]+$ ]] || die "--procs must be a number"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/nyancoin
DATA=/var/lib/nyancoin
ETC=/etc/nyancoin

if (( UNINSTALL )); then
  systemctl disable --now nyancoin-miner.service nyancoin-node.service 2>/dev/null || true
  rm -f /etc/systemd/system/nyancoin-node.service /etc/systemd/system/nyancoin-miner.service \
        /usr/local/bin/nyan-wallet
  systemctl daemon-reload
  rm -rf "$APP"
  echo "Removed NyanCoin. Kept chain data + node key in $DATA and settings in $ETC (delete them yourself if wanted)."
  exit 0
fi

for f in node.py miner.py wallet.py requirements.txt deploy/nyancoin-node.service deploy/nyancoin-miner.service; do
  [[ -f "$SRC/$f" ]] || die "missing $f - run this from the unpacked release folder"
done

echo "==> Checking Python"
if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv
  elif command -v dnf >/dev/null; then
    dnf install -y -q python3
  else
    die "please install python3 with the venv module, then re-run"
  fi
fi

echo "==> Creating service user and folders"
id nyancoin >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin nyancoin
install -d -m 755 "$APP"
install -d -m 700 -o nyancoin -g nyancoin "$DATA"
install -d -m 755 "$ETC"

echo "==> Installing code to $APP"
for f in node.py miner.py wallet.py README.md requirements.txt; do
  [[ -f "$SRC/$f" ]] && install -m 644 "$SRC/$f" "$APP/$f"
done
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"
"$APP/venv/bin/python" "$APP/node.py" --version >/dev/null   # also runs the rules-lock check

cat > /usr/local/bin/nyan-wallet <<EOF
#!/bin/sh
exec $APP/venv/bin/python $APP/wallet.py "\$@"
EOF
chmod 755 /usr/local/bin/nyan-wallet

echo "==> Writing settings"
if [[ ! -f "$ETC/node.env" || -n "$PUBLIC_URL" || ${#PEERS[@]} -gt 0 || "$PORT" != 8001 ]]; then
  ARGS="--port $PORT"
  [[ -n "$PUBLIC_URL" ]] && ARGS+=" --public-url $PUBLIC_URL"
  (( ${#PEERS[@]} )) && ARGS+=" --peers ${PEERS[*]}"
  printf '# NyanCoin node settings (used by nyancoin-node.service)\nNODE_ARGS="%s"\n' "$ARGS" > "$ETC/node.env"
  chmod 644 "$ETC/node.env"
else
  echo "    keeping existing $ETC/node.env"
fi
NODE_PORT=$(sed -n 's/.*--port \([0-9]*\).*/\1/p' "$ETC/node.env"); NODE_PORT=${NODE_PORT:-8001}

install -m 644 "$SRC/deploy/nyancoin-node.service" /etc/systemd/system/nyancoin-node.service
install -m 644 "$SRC/deploy/nyancoin-miner.service" /etc/systemd/system/nyancoin-miner.service
systemctl daemon-reload

echo "==> Starting node"
systemctl enable nyancoin-node.service >/dev/null
systemctl restart nyancoin-node.service

if [[ -n "$MINER" ]]; then
  ARGS="--address $MINER --node https://127.0.0.1:$NODE_PORT"
  [[ -n "$MINER_PROCS" ]] && ARGS+=" --procs $MINER_PROCS"
  printf '# NyanCoin miner settings (used by nyancoin-miner.service)\nMINER_ARGS="%s"\n' "$ARGS" > "$ETC/miner.env"
  chmod 644 "$ETC/miner.env"
fi
if [[ -f "$ETC/miner.env" ]]; then
  echo "==> Starting miner"
  systemctl enable nyancoin-miner.service >/dev/null
  systemctl restart nyancoin-miner.service
fi

if grep -q -- "--public-url" "$ETC/node.env"; then
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "==> Opening port $NODE_PORT in ufw"; ufw allow "$NODE_PORT/tcp" >/dev/null
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    echo "==> Opening port $NODE_PORT in firewalld"
    firewall-cmd -q --permanent --add-port="$NODE_PORT/tcp" && firewall-cmd -q --reload
  else
    echo "    (no active ufw/firewalld found - make sure TCP $NODE_PORT is open in your provider's firewall)"
  fi
fi

echo "==> Waiting for the node"
for _ in $(seq 1 20); do
  systemctl is-active -q nyancoin-node.service && journalctl -u nyancoin-node.service -n 50 --no-pager -q \
    | grep -q "NyanCoin node" && break
  sleep 1
done
systemctl is-active -q nyancoin-node.service || { journalctl -u nyancoin-node.service -n 30 --no-pager; die "node failed to start"; }
echo
journalctl -u nyancoin-node.service -n 50 --no-pager -q -o cat | grep -E "NyanCoin node|TLS pin|Share this" | tail -3
cat <<EOF

Done! Useful commands:
  systemctl status nyancoin-node        journalctl -fu nyancoin-node
  nyan-wallet status --node https://127.0.0.1:$NODE_PORT
  sudo nano $ETC/node.env && sudo systemctl restart nyancoin-node
Back up $DATA/node/tls.key (your node's identity). Put the "Share this seed address"
line into SEEDS in node.py before giving node.py to other people.
EOF
