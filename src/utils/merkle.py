"""Merkle tree utilities."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .serialization import canonical_hash


def compute_merkle_root(transactions: List[Dict[str, Any]]) -> str:
    """Compute the Merkle root for a list of transaction dicts."""

    if not transactions:
        return hashlib.sha256(b"").hexdigest()

    leaves = [hashlib.sha256(canonical_hash(tx)).digest() for tx in transactions]
    current_level = leaves

    while len(current_level) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        current_level = next_level

    return current_level[0].hex()


__all__ = ["compute_merkle_root"]
