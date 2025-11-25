"""Range proof implementation using Disjunctive Chaum-Pedersen proofs."""

from __future__ import annotations

from typing import List, Tuple

from src.crypto_utils import (
    CURVE_ORDER,
    G,
    H,
    Point,
    hash_to_int,
    pedersen_commit,
    point_add,
    point_neg,
    point_to_bytes,
    random_scalar,
    scalar_mult,
)


def prove_range(
    value: int, bits: int = 64
) -> Tuple[List[Point], List[Tuple[int, int, int, int]], int]:
    """
    Generate a range proof for a value, proving it's in [0, 2^bits - 1].
    Uses a 1-out-of-2 Disjunctive Chaum-Pedersen proof for each bit.

    Returns:
        - bit_commitments: List of commitments to each bit.
        - proofs: List of 1-out-of-2 proofs for each bit commitment.
        - total_blinding: The blinding factor for the aggregate commitment.
    """
    if not (0 <= value < (1 << bits)):
        raise ValueError("Value must be non-negative and within the bit range")

    value_bits = [(value >> i) & 1 for i in range(bits)]
    bit_blindings = [random_scalar() for _ in range(bits)]

    bit_commitments = [
        pedersen_commit(bit, blinding)
        for bit, blinding in zip(value_bits, bit_blindings)
    ]

    proofs = [
        _prove_bit_commitment(bit, blinding)
        for bit, blinding in zip(value_bits, bit_blindings)
    ]

    total_blinding = sum(
        (1 << i) * bit_blindings[i] for i in range(bits)
    ) % CURVE_ORDER

    return bit_commitments, proofs, total_blinding


def verify_range(
    commitment: Point,
    bit_commitments: List[Point],
    proofs: List[Tuple[int, int, int, int]],
    bits: int = 64,
) -> bool:
    """
    Verify a range proof.
    """
    if len(bit_commitments) != bits or len(proofs) != bits:
        return False

    # 1. Verify that the sum of the weighted bit commitments equals the total commitment.
    reconstructed_commitment = scalar_mult(1 << 0, bit_commitments[0])
    for i in range(1, bits):
        term = scalar_mult(1 << i, bit_commitments[i])
        reconstructed_commitment = point_add(reconstructed_commitment, term)

    if commitment != reconstructed_commitment:
        return False

    # 2. Verify the 1-out-of-2 proof for each bit commitment.
    for i in range(bits):
        if not _verify_bit_commitment(bit_commitments[i], proofs[i]):
            return False

    return True


def _prove_bit_commitment(
    bit: int, blinding: int
) -> Tuple[int, int, int, int]:
    """
    Generates a 1-out-of-2 proof that a commitment C = rG + vH
    is a commitment to v=0 or v=1.
    """
    C = pedersen_commit(bit, blinding)
    P0 = C
    P1 = point_add(C, point_neg(H))

    if bit == 0:
        # Real proof for v=0
        k0 = random_scalar()
        L0 = scalar_mult(k0, G)

        # Fake proof for v=1
        s1 = random_scalar()
        c1 = random_scalar()
        L1 = point_add(scalar_mult(s1, G), point_neg(scalar_mult(c1, P1)))

        # Challenge
        e = hash_to_int(point_to_bytes(P0), point_to_bytes(P1), point_to_bytes(L0), point_to_bytes(L1))
        c0 = (e - c1) % CURVE_ORDER
        s0 = (k0 + c0 * blinding) % CURVE_ORDER
    elif bit == 1:
        # Real proof for v=1
        k1 = random_scalar()
        L1 = scalar_mult(k1, G)

        # Fake proof for v=0
        s0 = random_scalar()
        c0 = random_scalar()
        L0 = point_add(scalar_mult(s0, G), point_neg(scalar_mult(c0, P0)))

        # Challenge
        e = hash_to_int(point_to_bytes(P0), point_to_bytes(P1), point_to_bytes(L0), point_to_bytes(L1))
        c1 = (e - c0) % CURVE_ORDER
        s1 = (k1 + c1 * blinding) % CURVE_ORDER
    else:
        raise ValueError("Bit must be 0 or 1")

    return c0, s0, c1, s1


def _verify_bit_commitment(
    commitment: Point, proof: Tuple[int, int, int, int]
) -> bool:
    """
    Verifies a 1-out-of-2 proof for a bit commitment.
    """
    c0, s0, c1, s1 = proof
    P0 = commitment
    P1 = point_add(commitment, point_neg(H))

    L0_prime = point_add(scalar_mult(s0, G), point_neg(scalar_mult(c0, P0)))
    L1_prime = point_add(scalar_mult(s1, G), point_neg(scalar_mult(c1, P1)))

    e_prime = hash_to_int(point_to_bytes(P0), point_to_bytes(P1), point_to_bytes(L0_prime), point_to_bytes(L1_prime))

    return e_prime == (c0 + c1) % CURVE_ORDER
