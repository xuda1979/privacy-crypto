import asyncio
import base64
import hashlib
import json as std_json
import os
import time
import traceback
from typing import Any, Dict, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketState

try:
    import orjson as _json

    def _dumps(obj: Any) -> bytes:
        return _json.dumps(obj)

    def _loads(b: bytes) -> Any:
        return _json.loads(b)
except Exception:  # pragma: no cover

    def _dumps(obj: Any) -> bytes:
        return std_json.dumps(obj).encode("utf-8")

    def _loads(b: bytes) -> Any:
        return std_json.loads(b.decode("utf-8"))

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random as nacl_random

from .dandelion import DandelionRouter

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
HOST = os.getenv("P2P_HOST", "0.0.0.0")
PORT = int(os.getenv("P2P_PORT", "9000"))
BOOTSTRAP = [u.strip() for u in os.getenv("PEERS", "").split(",") if u.strip()]
MIN_FEE_RATE = int(os.getenv("MIN_FEE_RATE", "0"))
UVLOOP = bool(os.getenv("UVLOOP"))

try:
    if UVLOOP:
        import uvloop  # type: ignore

        uvloop.install()
except Exception:
    pass  # optional

# ------------------------------------------------------------------------------
# App scaffolding
# ------------------------------------------------------------------------------
app = FastAPI(title="privacy-crypto P2P relay", version="0.1.0")

# Peer bookkeeping
PEERS: Dict[str, "Peer"] = {}
SEEN_TX: Set[str] = set()
ROUTER = DandelionRouter()

# Minimal mempool: tx_id -> (tx, first_seen_ts, fee)
MEMPOOL: Dict[str, tuple[dict, float, int]] = {}
TX_TTL_S = float(os.getenv("TX_TTL_S", "600"))

# ------------------------------------------------------------------------------
# Crypto helpers
# ------------------------------------------------------------------------------
class Cipher:
    def __init__(self, sk: PrivateKey, pk: PublicKey):
        self.box = Box(sk, pk)

    def encrypt(self, payload: bytes) -> bytes:
        nonce = nacl_random(Box.NONCE_SIZE)
        return self.box.encrypt(payload, nonce)

    def decrypt(self, blob: bytes) -> bytes:
        return self.box.decrypt(blob)


# ------------------------------------------------------------------------------
# Peer
# ------------------------------------------------------------------------------
class Peer:
    def __init__(self, ws: Optional[WebSocket], peer_id: str, cipher: Cipher):
        self.ws = ws
        self.peer_id = peer_id
        self.cipher = cipher
        self.alive = True
        self._lock = asyncio.Lock()

    async def send_json(self, obj: dict):
        # Encrypt JSON payload and send as base64
        blob = self.cipher.encrypt(_dumps(obj))
        b64 = base64.b64encode(blob).decode("ascii")
        async with self._lock:
            if self.ws and self.ws.application_state == WebSocketState.CONNECTED:
                await self.ws.send_json({"type": "cipher", "v": 1, "blob": b64})

    async def close(self):
        self.alive = False
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass


# ------------------------------------------------------------------------------
# Utility
# ------------------------------------------------------------------------------
def tx_id_from_obj(tx: dict) -> str:
    # Stable hash of canonical bytes
    h = hashlib.sha256(_dumps(tx)).hexdigest()
    return h


def mempool_prune():
    now = time.time()
    to_del = [tid for tid, (tx, ts, fee) in MEMPOOL.items() if (now - ts) > TX_TTL_S]
    for tid in to_del:
        MEMPOOL.pop(tid, None)
        SEEN_TX.discard(tid)


def peer_ids() -> list[str]:
    return list(PEERS.keys())


# ------------------------------------------------------------------------------
# WebSocket endpoint: /p2p
# ------------------------------------------------------------------------------
@app.websocket("/p2p")
async def p2p_socket(ws: WebSocket):
    await ws.accept()
    # 1) handshake: client sends {"type":"hello","pubkey": b64}
    hello = await ws.receive_json()
    if hello.get("type") != "hello" or "pubkey" not in hello:
        await ws.close(code=4000)
        return

    remote_pk = PublicKey(base64.b64decode(hello["pubkey"]))
    sk = PrivateKey.generate()
    local_pk_b64 = base64.b64encode(bytes(sk.public_key)).decode("ascii")
    await ws.send_json({"type": "hello", "pubkey": local_pk_b64})

    cipher = Cipher(sk, remote_pk)
    peer_id = base64.b16encode(hashlib.sha256(bytes(remote_pk)).digest()[:8]).decode(
        "ascii"
    )
    peer = Peer(ws, peer_id, cipher)
    PEERS[peer_id] = peer

    try:
        while True:
            msg = await ws.receive_json()
            if msg.get("type") != "cipher":
                continue
            try:
                blob = base64.b64decode(msg["blob"])
                payload = cipher.decrypt(blob)
                inner = _loads(payload)
                await handle_peer_message(peer, inner)
            except CryptoError:
                # Drop malformed/unauthenticated frames
                continue
    except WebSocketDisconnect:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        PEERS.pop(peer_id, None)
        try:
            await ws.close()
        except Exception:
            pass


# ------------------------------------------------------------------------------
# P2P control endpoints
# ------------------------------------------------------------------------------
@app.get("/p2p/peers")
async def p2p_peers():
    mempool_prune()
    return JSONResponse(
        {
            "peers": peer_ids(),
            "mempool_size": len(MEMPOOL),
            "seen_tx": len(SEEN_TX),
            "min_fee_rate": MIN_FEE_RATE,
        }
    )


@app.post("/p2p/submit")
async def p2p_submit(body: dict):
    """
    Submit a transaction into the relay. The relay treats the tx as an opaque
    object; validity checks are expected to happen at the API/miner. We still
    enforce a minimal fee-rate knob if provided in the tx.
    """

    tx = body.get("tx")
    if not isinstance(tx, dict):
        return JSONResponse({"error": "tx must be an object"}, status_code=400)
    fee = int(tx.get("fee", 0))
    if fee < MIN_FEE_RATE:
        return JSONResponse({"error": "fee below MIN_FEE_RATE"}, status_code=400)
    tid = tx_id_from_obj(tx)
    await relay_tx_local(tx, tid)
    return JSONResponse({"ok": True, "tx_id": tid})


# ------------------------------------------------------------------------------
# Outbound connector (client) to bootstrap peers
# ------------------------------------------------------------------------------
async def connector_task(url: str):
    """
    Maintain a client connection to `url` (ws://host:port/p2p).
    """

    import websockets  # lazy import

    while True:
        peer_id: Optional[str] = None
        try:
            async with websockets.connect(url + "/p2p", max_size=None) as ws:
                # Hello (client -> server)
                sk = PrivateKey.generate()
                pk_b64 = base64.b64encode(bytes(sk.public_key)).decode("ascii")
                await ws.send(std_json.dumps({"type": "hello", "pubkey": pk_b64}))
                # Receive server key
                resp = std_json.loads(await ws.recv())
                remote_pk = PublicKey(base64.b64decode(resp["pubkey"]))
                cipher = Cipher(sk, remote_pk)
                peer_id = base64.b16encode(
                    hashlib.sha256(bytes(remote_pk)).digest()[:8]
                ).decode("ascii")

                # Register a synthetic Peer object that writes via this client socket
                class ClientPeer(Peer):
                    async def send_json(self, obj: dict):
                        blob = cipher.encrypt(_dumps(obj))
                        b64 = base64.b64encode(blob).decode("ascii")
                        await ws.send(
                            std_json.dumps({"type": "cipher", "v": 1, "blob": b64})
                        )

                client_peer = ClientPeer(None, peer_id, cipher)  # type: ignore[arg-type]
                PEERS[peer_id] = client_peer

                # Read loop
                while True:
                    data = await ws.recv()
                    msg = std_json.loads(data)
                    if msg.get("type") != "cipher":
                        continue
                    blob = base64.b64decode(msg["blob"])
                    inner = _loads(cipher.decrypt(blob))
                    await handle_peer_message(client_peer, inner)
        except Exception:
            # Reconnect on errors with jitter
            await asyncio.sleep(1.0 + (hash(url) % 100) / 100.0)
        finally:
            # On disconnect, ensure synthetic peer is dropped
            if peer_id:
                PEERS.pop(peer_id, None)
            await asyncio.sleep(1.0)


# ------------------------------------------------------------------------------
# Message handling
# ------------------------------------------------------------------------------
async def handle_peer_message(sender: Peer, inner: dict):
    typ = inner.get("msg")
    if typ == "tx-stem":
        tx = inner["tx"]
        tid = inner["tx_id"]
        fee = int(tx.get("fee", 0))
        if fee < MIN_FEE_RATE:
            return
        if tid in SEEN_TX:
            return
        SEEN_TX.add(tid)
        MEMPOOL[tid] = (tx, time.time(), fee)
        ROUTER.on_stem_forwarded(tid)
        if ROUTER.should_fluff(tid):
            await broadcast_fluff(sender, tx, tid)
        else:
            await forward_stem(sender, tx, tid)

    elif typ == "tx-fluff":
        tx = inner["tx"]
        tid = inner["tx_id"]
        fee = int(tx.get("fee", 0))
        if fee < MIN_FEE_RATE:
            return
        if tid in SEEN_TX:
            return
        SEEN_TX.add(tid)
        MEMPOOL[tid] = (tx, time.time(), fee)
        await broadcast_fluff(sender, tx, tid)


async def forward_stem(sender: Optional[Peer], tx: dict, tid: str):
    peers = [pid for pid in peer_ids() if not sender or pid != sender.peer_id]
    s = ROUTER.assign_or_get(peers, tid)
    if not s:
        # no peers -> fluff locally
        await broadcast_fluff(sender, tx, tid)
        return
    peer = PEERS.get(s.peer_id)
    if not peer:
        await broadcast_fluff(sender, tx, tid)
        return
    msg = {"msg": "tx-stem", "tx": tx, "tx_id": tid}
    await peer.send_json(msg)


async def broadcast_fluff(sender: Optional[Peer], tx: dict, tid: str):
    msg = {"msg": "tx-fluff", "tx": tx, "tx_id": tid}
    for pid, p in PEERS.items():
        if sender and pid == sender.peer_id:
            continue
        await p.send_json(msg)


async def relay_tx_local(tx: dict, tid: str):
    if tid in SEEN_TX:
        return
    SEEN_TX.add(tid)
    fee = int(tx.get("fee", 0))
    MEMPOOL[tid] = (tx, time.time(), fee)
    # Try stem first; fall back to fluff if no peers
    await forward_stem(sender=None, tx=tx, tid=tid)


# ------------------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------------------
@app.on_event("startup")
async def _startup():
    # Periodic mempool pruning
    async def _prune():
        while True:
            mempool_prune()
            await asyncio.sleep(10)

    asyncio.create_task(_prune())

    # Connect to bootstrap peers
    for url in BOOTSTRAP:
        asyncio.create_task(connector_task(url))


def main():
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
