#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
export PYTHONPATH="${ROOT}:${PYTHONPATH:-}"

if [[ -f requirements.txt ]]; then
  "${PYTHON}" -m pip install -r requirements.txt >/tmp/privacy-crypto-install.log
fi

echo "[test] Running pytest"
pytest -q

echo "[test] Starting API node for smoke test"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8050}"
"${PYTHON}" -m uvicorn src.api:app --host "$API_HOST" --port "$API_PORT" --log-level warning &
API_PID=$!

sleep 1

echo "[test] Starting P2P relay for smoke test"
P2P_HOST="${P2P_HOST:-127.0.0.1}"
P2P_PORT="${P2P_PORT:-9100}"
PEERS="${PEERS:-}" P2P_HOST="$P2P_HOST" P2P_PORT="$P2P_PORT" \
  "${PYTHON}" -m uvicorn src.p2p.node:app --host "$P2P_HOST" --port "$P2P_PORT" --log-level warning &
P2P_PID=$!

sleep 1

cleanup() {
  echo "[test] Cleaning up background services"
  kill "$API_PID" "$P2P_PID" >/dev/null 2>&1 || true
  wait "$API_PID" "$P2P_PID" 2>/dev/null || true
}
trap cleanup EXIT

STATUS=0
API_HOST="$API_HOST" API_PORT="$API_PORT" P2P_HOST="$P2P_HOST" P2P_PORT="$P2P_PORT" \
"${PYTHON}" - <<'PY'
import os
import time

import httpx

api = f"http://{os.environ['API_HOST']}:{os.environ['API_PORT']}"
p2p = f"http://{os.environ['P2P_HOST']}:{os.environ['P2P_PORT']}"


def wait_for(url: str, path: str = "/chain", timeout: float = 20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(url + path, timeout=2.0)
            if resp.status_code < 500:
                return resp
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Service at {url}{path} did not become ready in time")


wait_for(api)
wait_for(p2p, "/p2p/peers")

wallet_a = httpx.post(api + "/wallets", timeout=5.0)
wallet_b = httpx.post(api + "/wallets", timeout=5.0)
_ = httpx.post(api + "/wallets", timeout=5.0)  # decoy pool
wallet_a.raise_for_status()
wallet_b.raise_for_status()

sender = wallet_a.json()
recipient = wallet_b.json()

payload = {
    "sender_wallet_id": sender["wallet_id"],
    "recipient_wallet_id": recipient["wallet_id"],
    "amount": 9,
    "ring_size": 3,
    "memo": "full system test",
}

resp = httpx.post(api + "/transactions", json=payload, timeout=10.0)
resp.raise_for_status()

pending = httpx.get(api + "/pending", timeout=5.0)
pending.raise_for_status()
if not pending.json().get("pending"):
    raise RuntimeError("Pending transaction list is empty")

mine = httpx.post(api + "/mine", timeout=10.0)
mine.raise_for_status()
chain = httpx.get(api + "/chain", timeout=5.0)
chain.raise_for_status()
data = chain.json()
if data.get("length", 0) < 2 or not data.get("valid"):
    raise RuntimeError("Blockchain validation failed")

peers = httpx.get(p2p + "/p2p/peers", timeout=5.0)
peers.raise_for_status()
submit = httpx.post(p2p + "/p2p/submit", json={"tx": {"fee": 0, "payload": "ping"}}, timeout=5.0)
submit.raise_for_status()
print("Full system smoke test completed successfully")
PY
STATUS=$?

if [[ "$STATUS" -ne 0 ]]; then
  exit "$STATUS"
fi

echo "[test] All tests completed successfully"
