"""Implementation of a Schnorr-style ring signature scheme."""

from __future__ import annotations

from typing import Dict, List

from ecdsa.ellipticcurve import Point

from .crypto_utils import (
    CURVE_ORDER,
    hash_to_int,
    point_add,
    point_to_bytes,
    scalar_mult,
)


def sign(
    message: bytes,
    public_ring: List[Point],
    private_key: int,
    signer_index: int,
) -> Dict[str, object]:
    """Create a ring signature over *message* using the provided ring."""

    ring_size = len(public_ring)
    if ring_size < 2:
        raise ValueError("Ring signatures require at least two members")
    if not 0 <= signer_index < ring_size:
        raise ValueError("Signer index is out of bounds for the ring size")

    # Prepare storage
    c_values: List[int] = [0] * ring_size
    s_values: List[int] = [0] * ring_size

    from .crypto_utils import random_scalar

    nonce_scalar = random_scalar()
    k_point = scalar_mult(nonce_scalar)

    next_index = (signer_index + 1) % ring_size
    c_values[next_index] = hash_to_int(message, point_to_bytes(k_point))

    # Iterate through the ring, sampling random responses for non-signers.
    j = next_index
    while j != signer_index:
        s_values[j] = random_scalar()
        candidate = point_add(
            scalar_mult(s_values[j]),
            scalar_mult(c_values[j], public_ring[j]),
        )
        c_values[(j + 1) % ring_size] = hash_to_int(
            message, point_to_bytes(candidate)
        )
        j = (j + 1) % ring_size

    # Close the ring by solving for the signer's response.
    s_values[signer_index] = (
        (nonce_scalar - c_values[signer_index] * private_key) % CURVE_ORDER
    )

    return {
        "c0": c_values[0],
        "s": s_values,
    }


def verify(message: bytes, public_ring: List[Point], signature: Dict[str, object]) -> bool:
    """Verify a ring signature."""

    if not signature or "c0" not in signature or "s" not in signature:
        return False
    c = signature["c0"]
    s_values = signature["s"]
    if len(s_values) != len(public_ring):
        return False

    for point, s_value in zip(public_ring, s_values):
        candidate = point_add(scalar_mult(s_value), scalar_mult(c, point))
        c = hash_to_int(message, point_to_bytes(candidate))

    return c == signature["c0"]

