#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

# Allow running outside a venv just like run_node.sh does
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="${ROOT}:${PYTHONPATH:-}"

if command -v uvloop >/dev/null 2>&1; then
  export UVLOOP=1
fi

P2P_HOST="${P2P_HOST:-0.0.0.0}"
P2P_PORT="${P2P_PORT:-9000}"

echo "[p2p] starting relay on ${P2P_HOST}:${P2P_PORT}"
exec "${PYTHON}" -m src.p2p.node
