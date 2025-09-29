"""Utility primitives for elliptic-curve cryptography used in the project.

This module centralises the low level curve operations that power the
privacy-preserving transaction flow.  The implementation is intentionally
explicit to avoid relying on any non-deterministic serialisation behaviour
from third-party libraries.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, Tuple

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point


CURVE = SECP256k1
CURVE_ORDER = CURVE.order
CURVE_FIELD = CURVE.curve.p()
G = CURVE.generator


def random_scalar() -> int:
    """Return a cryptographically secure random scalar for the curve."""

    return secrets.randbelow(CURVE_ORDER - 1) + 1


def scalar_mult(scalar: int, point: Point = G) -> Point:
    """Multiply *point* by *scalar* on the curve."""

    return scalar * point


def point_add(p1: Point, p2: Point) -> Point:
    """Add two curve points."""

    return p1 + p2


def point_neg(point: Point) -> Point:
    """Return the additive inverse of *point*."""

    return Point(point.curve(), point.x(), (-point.y()) % CURVE_FIELD)


def int_to_bytes(value: int) -> bytes:
    """Encode a scalar value as a 32-byte big-endian sequence."""

    return value.to_bytes(32, "big")


def bytes_to_int(data: bytes) -> int:
    """Decode a big-endian byte sequence into an integer."""

    return int.from_bytes(data, "big")


def point_to_bytes(point: Point) -> bytes:
    """Return the compressed SEC1 representation of *point*."""

    prefix = b"\x02" if point.y() % 2 == 0 else b"\x03"
    return prefix + int_to_bytes(point.x())


def bytes_to_point(data: bytes) -> Point:
    """Decode a compressed SEC1 point representation."""

    if len(data) != 33:
        raise ValueError("Compressed points must be 33 bytes long")
    prefix = data[0]
    if prefix not in (2, 3):
        raise ValueError("Invalid compressed point prefix")
    x = bytes_to_int(data[1:])
    # y^2 = x^3 + 7 over the secp256k1 field
    rhs = (pow(x, 3, CURVE_FIELD) + 7) % CURVE_FIELD
    y = pow(rhs, (CURVE_FIELD + 1) // 4, CURVE_FIELD)
    if (y % 2 == 0 and prefix == 3) or (y % 2 == 1 and prefix == 2):
        y = (-y) % CURVE_FIELD
    return Point(CURVE.curve, x, y)


def hash_bytes(*chunks: Iterable[bytes]) -> bytes:
    """Hash the concatenation of *chunks* with SHA-256."""

    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(bytes(chunk))
    return digest.digest()


def hash_to_int(*chunks: Iterable[bytes]) -> int:
    """Map arbitrary bytes to a scalar in the curve order."""

    return bytes_to_int(hash_bytes(*chunks)) % CURVE_ORDER


def hash_to_point(label: bytes) -> Point:
    """Derive a secondary generator point deterministically from *label*."""

    counter = 0
    while True:
        candidate = hash_bytes(label, counter.to_bytes(4, "big"))
        x = bytes_to_int(candidate) % CURVE_FIELD
        rhs = (pow(x, 3, CURVE_FIELD) + 7) % CURVE_FIELD
        y = pow(rhs, (CURVE_FIELD + 1) // 4, CURVE_FIELD)
        if pow(y, 2, CURVE_FIELD) == rhs:
            if y % 2 == 1:
                y = (-y) % CURVE_FIELD
            return Point(CURVE.curve, x, y)
        counter += 1


H = hash_to_point(b"privacy-crypto-secondary-generator")


def generate_keypair() -> Tuple[int, Point]:
    """Generate a fresh private/public key pair."""

    private_key = random_scalar()
    public_key = scalar_mult(private_key, G)
    return private_key, public_key


def derive_shared_secret(private_scalar: int, public_point: Point) -> bytes:
    """Compute an ECDH shared secret as compressed point bytes."""

    shared_point = scalar_mult(private_scalar, public_point)
    return hash_bytes(point_to_bytes(shared_point))


def derive_stealth_address(
    recipient_view_public: Point,
    recipient_spend_public: Point,
) -> Tuple[int, Point, Point]:
    """Generate an ephemeral stealth address for the recipient."""

    ephemeral_scalar = random_scalar()
    ephemeral_public = scalar_mult(ephemeral_scalar, G)
    shared_point = scalar_mult(ephemeral_scalar, recipient_view_public)
    c = hash_to_int(point_to_bytes(shared_point))
    one_time_public = point_add(recipient_spend_public, scalar_mult(c, G))
    return ephemeral_scalar, ephemeral_public, one_time_public


def pedersen_commit(amount: int, blinding: int) -> Point:
    """Create a Pedersen commitment to *amount* using *blinding*."""

    return point_add(scalar_mult(blinding, G), scalar_mult(amount, H))


def prove_commitment(amount: int, blinding: int) -> Tuple[Point, int, int]:
    """Produce a Schnorr-style proof of knowledge for the commitment."""

    commitment = pedersen_commit(amount, blinding)
    r1 = random_scalar()
    r2 = random_scalar()
    t = point_add(scalar_mult(r1, G), scalar_mult(r2, H))
    challenge = hash_to_int(point_to_bytes(commitment), point_to_bytes(t))
    s1 = (r1 + challenge * blinding) % CURVE_ORDER
    s2 = (r2 + challenge * amount) % CURVE_ORDER
    return t, s1, s2


def verify_commitment(
    commitment: Point, t: Point, s1: int, s2: int
) -> bool:
    """Verify the Schnorr-style proof returned by :func:`prove_commitment`."""

    challenge = hash_to_int(point_to_bytes(commitment), point_to_bytes(t))
    left = point_add(scalar_mult(s1, G), scalar_mult(s2, H))
    right = point_add(t, scalar_mult(challenge, commitment))
    return left == right

