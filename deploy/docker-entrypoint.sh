#!/bin/sh
# One image, three roles:  node (default) | miner | wallet ...   (settings come from .env)
set -e
role="${1:-node}"
[ $# -gt 0 ] && shift
case "$role" in
  node)
    # shellcheck disable=SC2086  # PEERS is intentionally split into several arguments
    exec python -u /app/node.py --data /data/node --port "${PORT:-8001}" \
      ${PUBLIC_URL:+--public-url "$PUBLIC_URL"} ${PEERS:+--peers $PEERS} "$@" ;;
  miner)
    exec python -u /app/miner.py --address "${MINER_ADDRESS:?set MINER_ADDRESS in .env}" \
      --node "${MINER_NODE:-https://127.0.0.1:${PORT:-8001}}" ${MINER_PROCS:+--procs "$MINER_PROCS"} "$@" ;;
  wallet)
    exec python -u /app/wallet.py "$@" ;;
  *)
    exec "$role" "$@" ;;
esac
