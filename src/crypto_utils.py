"""Utility primitives for elliptic-curve cryptography used in the project.

This module centralises the low level curve operations that power the
privacy-preserving transaction flow.  The implementation is intentionally
explicit to avoid relying on any non-deterministic serialisation behaviour
from third-party libraries.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Dict, Iterable, Tuple

from ecdsa import SECP256k1, rfc6979
from ecdsa.ellipticcurve import Point, PointJacobi
from pybip39 import Mnemonic, Seed


CURVE = SECP256k1
CURVE_ORDER = CURVE.order
CURVE_FIELD = CURVE.curve.p()
G = CURVE.generator


def random_scalar() -> int:
    """Return a cryptographically secure random scalar for the curve."""

    return secrets.randbelow(CURVE_ORDER - 1) + 1


def is_valid_scalar(value: int) -> bool:
    """Return ``True`` if *value* is a non-zero scalar within the curve order."""

    return isinstance(value, int) and 1 <= value < CURVE_ORDER


def _ensure_bytes(data: object) -> bytes:
    """Normalise *data* to a ``bytes`` instance."""

    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise TypeError("message must be bytes-like")


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


def generate_mnemonic() -> str:
    """Generate a 12-word mnemonic phrase."""
    return Mnemonic().phrase


def keys_from_mnemonic(mnemonic_phrase: str, passphrase: str = "") -> int:
    """Derive a private key from a mnemonic phrase."""
    seed = Seed(Mnemonic.from_phrase(mnemonic_phrase), passphrase)
    key = bytes_to_int(bytes(seed))
    return (key % (CURVE_ORDER - 1)) + 1


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


from src.rangeproof import prove_range, verify_range


def schnorr_sign(message: bytes, private_key: int) -> Tuple[Point, int]:
    """Return a deterministic Schnorr signature over *message*."""

    message_bytes = _ensure_bytes(message)
    if not is_valid_scalar(private_key):
        raise ValueError("private key must be a scalar in the curve order")

    message_hash = hashlib.sha256(message_bytes).digest()
    k = rfc6979.generate_k(CURVE_ORDER, private_key, hashlib.sha256, message_hash)
    r_point = scalar_mult(k, G)
    if hasattr(r_point, "to_affine"):
        r_point = r_point.to_affine()
    challenge = hash_to_int(point_to_bytes(r_point), message_bytes)
    s = (k + challenge * private_key) % CURVE_ORDER
    return r_point, s


def schnorr_verify(message: bytes, public_key: Point, signature: Tuple[Point, int]) -> bool:
    """Verify a Schnorr signature produced by :func:`schnorr_sign`."""

    try:
        message_bytes = _ensure_bytes(message)
    except TypeError:
        return False

    try:
        r_point, s_value = signature
    except (TypeError, ValueError):
        return False

    if not isinstance(r_point, (Point, PointJacobi)):
        return False

    if not is_valid_scalar(s_value):
        return False

    challenge = hash_to_int(point_to_bytes(r_point), message_bytes)
    left = scalar_mult(s_value, G)
    right = point_add(r_point, scalar_mult(challenge, public_key))
    return left == right


def encode_schnorr_signature(signature: Tuple[Point, int]) -> Dict[str, str]:
    """Encode a Schnorr signature as base64 strings for transport."""

    r_point, s_value = signature
    r_bytes = point_to_bytes(r_point)
    s_bytes = int_to_bytes(s_value)
    return {
        "R": base64.b64encode(r_bytes).decode("ascii"),
        "s": base64.b64encode(s_bytes).decode("ascii"),
    }


def decode_schnorr_signature(payload: Dict[str, str]) -> Tuple[Point, int]:
    """Decode the representation produced by :func:`encode_schnorr_signature`."""

    if not isinstance(payload, dict):
        raise TypeError("signature payload must be a mapping")

    try:
        r_encoded = payload["R"]
        s_encoded = payload["s"]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError("signature payload missing fields") from exc

    r_bytes = base64.b64decode(str(r_encoded).encode("ascii"))
    s_bytes = base64.b64decode(str(s_encoded).encode("ascii"))
    r_point = bytes_to_point(r_bytes)
    s_value = bytes_to_int(s_bytes)
    return r_point, s_value

