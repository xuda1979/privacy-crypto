"""Utility helpers for deterministic serialisation of payloads."""

from __future__ import annotations

import json
from typing import Any, Dict

from ..crypto_utils import hash_bytes


def canonical_hash(payload: Dict[str, Any]) -> bytes:
    """Return a SHA-256 hash of *payload* with stable JSON encoding."""

    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hash_bytes(serialised.encode("utf-8"))


__all__ = ["canonical_hash"]
