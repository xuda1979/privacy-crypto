import os
import random
import time
from dataclasses import dataclass
from typing import Optional, Sequence

STEM_MIN_HOPS = int(os.getenv("DANDELION_STEM_MIN_HOPS", "2"))
STEM_MAX_HOPS = int(os.getenv("DANDELION_STEM_MAX_HOPS", "8"))
STEM_TIMEOUT_S = float(os.getenv("DANDELION_STEM_TIMEOUT_S", "12.0"))

@dataclass
class StemState:
    peer_id: str
    hops_left: int
    started_at: float

class DandelionRouter:
    """
    Minimal Dandelion++-style router:
      - choose a pseudo-random stem peer per-tx
      - forward along 'hops_left'
      - fall back to fluff on timeout or hops_left == 0
    """
    def __init__(self):
        self._stem: dict[str, StemState] = {}

    @staticmethod
    def _choose_stem_peer(peers: Sequence[str], tx_id: str) -> Optional[str]:
        if not peers:
            return None
        # Deterministic choice per tx_id for stability in small nets
        rnd = random.Random(tx_id)
        return rnd.choice(list(peers))

    def assign_or_get(self, peers: Sequence[str], tx_id: str) -> Optional[StemState]:
        now = time.time()
        s = self._stem.get(tx_id)
        if s and (now - s.started_at) < STEM_TIMEOUT_S and s.hops_left > 0:
            return s
        peer_id = self._choose_stem_peer(peers, tx_id)
        if not peer_id:
            return None
        hops = random.randint(STEM_MIN_HOPS, STEM_MAX_HOPS)
        s = StemState(peer_id=peer_id, hops_left=hops, started_at=now)
        self._stem[tx_id] = s
        return s

    def on_stem_forwarded(self, tx_id: str):
        s = self._stem.get(tx_id)
        if s:
            s.hops_left -= 1

    def should_fluff(self, tx_id: str) -> bool:
        s = self._stem.get(tx_id)
        if not s:
            return True
        if s.hops_left <= 0:
            return True
        if (time.time() - s.started_at) >= STEM_TIMEOUT_S:
            return True
        return False
