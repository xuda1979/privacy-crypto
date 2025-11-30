"""Implementation of a Schnorr-style ring signature scheme."""

from __future__ import annotations

from typing import Dict, List, Union

from ecdsa.ellipticcurve import Point

from .crypto_utils import (
    CURVE_ORDER,
    hash_to_int,
    point_add,
    point_to_bytes,
    scalar_mult,
    random_scalar,
)


def sign(
    message: bytes,
    public_ring: List[Union[Point, List[Point]]],
    private_keys: Union[int, List[int]],
    signer_index: int,
) -> Dict[str, object]:
    """
    Create a ring signature over *message* using the provided ring.
    Supports both standard LSAG (single point per member) and Vector Ring Signatures (list of points per member).
    """

    ring_size = len(public_ring)
    if ring_size < 2:
        raise ValueError("Ring signatures require at least two members")
    if not 0 <= signer_index < ring_size:
        raise ValueError("Signer index is out of bounds for the ring size")

    # Detect if we are doing Vector Ring Signature
    is_vector = isinstance(public_ring[0], list)

    # Normalize inputs
    if not is_vector:
        # Standard LSAG: Treat as vector of size 1
        public_ring_vec = [[p] for p in public_ring]
        private_keys_vec = [private_keys]
    else:
        public_ring_vec = public_ring
        private_keys_vec = private_keys

    vector_len = len(public_ring_vec[0])

    # Validation
    if len(private_keys_vec) != vector_len:
        raise ValueError("Number of private keys must match vector length")
    for member in public_ring_vec:
        if len(member) != vector_len:
             raise ValueError("All ring members must have the same vector length")

    # Prepare storage
    c_values: List[int] = [0] * ring_size
    s_values: List[List[int]] = [[0] * vector_len for _ in range(ring_size)] # s is now a vector of scalars for each ring member... wait.
    # NO. In MLSAG/Vector, there is ONE 'c' per ring member, but MULTIPLE 's' values?
    # Actually, for standard MLSAG, we have one `c` rotating around.
    # But for each key in the vector, we need a corresponding `s`?
    # Let's review: c_{i+1} = H(m, L1, R1, ...) where L1 = s1*G + c*P1, R1 = s2*G + c*P2...
    # Yes. So we need `s` for EACH component of the vector.

    # Generate random nonces for the signer (one per vector component)
    alpha_scalars = [random_scalar() for _ in range(vector_len)]

    # Calculate initial challenge for next member
    # L_i = alpha_i * G
    L_points = [scalar_mult(alpha) for alpha in alpha_scalars]

    # Hash accumulation: H(m, L_points...)
    # We hash all L points
    hash_payload = message
    for p in L_points:
        hash_payload = hash_payload + point_to_bytes(p)

    next_index = (signer_index + 1) % ring_size
    c_values[next_index] = hash_to_int(hash_payload)

    # Iterate through the ring, sampling random responses for non-signers.
    j = next_index
    while j != signer_index:
        # For each component in the vector
        s_vec = []
        L_points_j = []
        for v_idx in range(vector_len):
            s_val = random_scalar()
            s_vec.append(s_val)
            # L = s*G + c*P
            candidate = point_add(
                scalar_mult(s_val),
                scalar_mult(c_values[j], public_ring_vec[j][v_idx]),
            )
            L_points_j.append(candidate)

        s_values[j] = s_vec

        # Calculate next c
        hash_payload = message
        for p in L_points_j:
            hash_payload = hash_payload + point_to_bytes(p)

        c_values[(j + 1) % ring_size] = hash_to_int(hash_payload)
        j = (j + 1) % ring_size

    # Close the ring by solving for the signer's response.
    # s = alpha - c * x
    s_signer = []
    for v_idx in range(vector_len):
        s_comp = (alpha_scalars[v_idx] - c_values[signer_index] * private_keys_vec[v_idx]) % CURVE_ORDER
        s_signer.append(s_comp)

    s_values[signer_index] = s_signer

    # Flatten s_values if not vector mode (backward compatibility)
    if not is_vector:
        s_return = [s[0] for s in s_values]
    else:
        s_return = s_values # List of Lists

    return {
        "c0": c_values[0],
        "s": s_return,
    }


def verify(
    message: bytes,
    public_ring: List[Union[Point, List[Point]]],
    signature: Dict[str, object]
) -> bool:
    """Verify a ring signature (supports vector)."""

    if not signature or "c0" not in signature or "s" not in signature:
        return False
    c = signature["c0"]
    s_values = signature["s"]

    if len(s_values) != len(public_ring):
        return False

    # Detect Vector Mode
    is_vector = isinstance(public_ring[0], list)

    if not is_vector:
         public_ring_vec = [[p] for p in public_ring]
         # s_values should be list of ints
         if isinstance(s_values[0], list): return False
         s_values_vec = [[s] for s in s_values]
    else:
         public_ring_vec = public_ring
         s_values_vec = s_values

    vector_len = len(public_ring_vec[0])

    for i in range(len(public_ring_vec)):
        ring_member_vec = public_ring_vec[i]
        s_vec = s_values_vec[i]

        if len(ring_member_vec) != vector_len or len(s_vec) != vector_len:
            return False

        L_points = []
        for v_idx in range(vector_len):
            # L = s*G + c*P
            candidate = point_add(
                scalar_mult(s_vec[v_idx]),
                scalar_mult(c, ring_member_vec[v_idx])
            )
            L_points.append(candidate)

        # Calculate next c
        hash_payload = message
        for p in L_points:
            hash_payload = hash_payload + point_to_bytes(p)

        c = hash_to_int(hash_payload)

    return c == signature["c0"]
