"""Wallet management utilities for the privacy crypto prototype."""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from typing import Dict, Tuple

from ecdsa.ellipticcurve import Point
from nacl import pwhash, secret, utils
from nacl.exceptions import CryptoError

from . import crypto_utils
from .utils.serialization import canonical_hash


@dataclass
class Wallet:
    """Represents a user wallet with separate view and spend keys."""

    view_private_key: int
    spend_private_key: int

    @classmethod
    def generate(cls) -> "Wallet":
        view_private, _ = crypto_utils.generate_keypair()
        spend_private, _ = crypto_utils.generate_keypair()
        return cls(view_private, spend_private)

    def save_to_file(self, filename: str, password: str) -> None:
        """Encrypt and save wallet keys to *filename* using *password*."""

        salt = utils.random(pwhash.argon2i.SALTBYTES)
        key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            password.encode("utf-8"),
            salt,
            opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
            memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
        )
        box = secret.SecretBox(key)

        payload = json.dumps(
            {"view": self.view_private_key, "spend": self.spend_private_key}
        ).encode("utf-8")

        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(payload, nonce)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": 1,
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "data": base64.b64encode(encrypted).decode("ascii"),
                },
                f,
            )

    @classmethod
    def load_from_file(cls, filename: str, password: str) -> "Wallet":
        """Load and decrypt wallet from *filename* using *password*."""

        if not os.path.exists(filename):
            raise ValueError("Wallet file not found")

        with open(filename, "r", encoding="utf-8") as f:
            blob = json.load(f)

        try:
            salt = base64.b64decode(blob["salt"])
            encrypted_data = base64.b64decode(blob["data"])
        except (KeyError, ValueError, binascii.Error) as exc:
            raise ValueError("Malformed wallet file") from exc

        key = pwhash.argon2i.kdf(
            secret.SecretBox.KEY_SIZE,
            password.encode("utf-8"),
            salt,
            opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
            memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
        )
        box = secret.SecretBox(key)

        try:
            plaintext = box.decrypt(encrypted_data)
            keys = json.loads(plaintext)
            return cls(keys["view"], keys["spend"])
        except (CryptoError, KeyError, ValueError) as exc:
            raise ValueError("Invalid password or corrupt wallet file") from exc

    @property
    def view_public_key(self) -> Point:
        return crypto_utils.scalar_mult(self.view_private_key)

    @property
    def spend_public_key(self) -> Point:
        return crypto_utils.scalar_mult(self.spend_private_key)

    def export_address(self) -> str:
        """Return a base64 encoded representation of the public address."""

        data = (
            crypto_utils.point_to_bytes(self.view_public_key)
            + crypto_utils.point_to_bytes(self.spend_public_key)
        )
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def import_address(address: str) -> Tuple[Point, Point]:
        """Parse *address* and return the embedded public keys."""

        decoded = base64.b64decode(address.encode("ascii"))
        if len(decoded) != 66:
            raise ValueError("Addresses must encode two compressed points")
        view_bytes = decoded[:33]
        spend_bytes = decoded[33:]
        view_point = crypto_utils.bytes_to_point(view_bytes)
        spend_point = crypto_utils.bytes_to_point(spend_bytes)
        return view_point, spend_point

    def key_image(self) -> Point:
        """Derive a key image to prevent double spending."""

        public_bytes = crypto_utils.point_to_bytes(self.spend_public_key)
        hashed_point = crypto_utils.hash_to_point(public_bytes)
        return crypto_utils.scalar_mult(self.spend_private_key, hashed_point)

    def create_shared_secret(self, ephemeral_public: Point) -> bytes:
        return crypto_utils.derive_shared_secret(self.view_private_key, ephemeral_public)

    def public_keys(self) -> Tuple[Point, Point]:
        return self.view_public_key, self.spend_public_key

    @staticmethod
    def _decode_point(value: str) -> Point:
        """Decode a base64 encoded curve point."""

        try:
            data = base64.b64decode(value.encode("ascii"))
        except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
            raise ValueError("Point payload is not valid base64") from exc
        return crypto_utils.bytes_to_point(data)

    def _shared_point_with(self, ephemeral_public: Point) -> Point:
        """Return the Diffie-Hellman shared point with *ephemeral_public*."""

        return crypto_utils.scalar_mult(self.view_private_key, ephemeral_public)

    def _stealth_point_from_shared(self, shared_point: Point) -> Point:
        """Derive the expected stealth public key from a shared point."""

        tweak = crypto_utils.hash_to_int(crypto_utils.point_to_bytes(shared_point))
        return crypto_utils.point_add(
            self.spend_public_key, crypto_utils.scalar_mult(tweak, crypto_utils.G)
        )

    def belongs_to_transaction(self, transaction: Dict[str, object]) -> bool:
        """Return ``True`` if *transaction* pays to this wallet."""

        try:
            ephemeral = self._decode_point(transaction["ephemeral_public_key"])
            stealth_target = self._decode_point(transaction["stealth_address"])
        except (KeyError, ValueError):
            return False

        shared_point = self._shared_point_with(ephemeral)
        expected = self._stealth_point_from_shared(shared_point)
        return expected == stealth_target

    def decrypt_transaction_amount(self, transaction: Dict[str, object]) -> int:
        """Return the plaintext amount embedded in *transaction* for this wallet."""

        if not self.belongs_to_transaction(transaction):
            raise ValueError("Transaction is not addressed to this wallet")

        ephemeral = self._decode_point(transaction["ephemeral_public_key"])
        shared_secret = crypto_utils.derive_shared_secret(
            self.view_private_key, ephemeral
        )
        box = secret.SecretBox(shared_secret)

        try:
            ciphertext = base64.b32decode(transaction["encrypted_amount"].encode("ascii"))
        except (KeyError, ValueError, TypeError) as exc:  # pragma: no cover - defensive
            raise ValueError("Invalid encrypted amount payload") from exc

        plaintext = box.decrypt(ciphertext)
        if len(plaintext) != 8:
            raise ValueError("Encrypted amount has unexpected length")
        return int.from_bytes(plaintext, "big")

    def derive_one_time_private_key(self, transaction: Dict[str, object]) -> int:
        """Return the private key corresponding to the transaction's stealth address."""

        if not self.belongs_to_transaction(transaction):
            raise ValueError("Transaction is not addressed to this wallet")

        ephemeral = self._decode_point(transaction["ephemeral_public_key"])
        shared_point = self._shared_point_with(ephemeral)
        tweak = crypto_utils.hash_to_int(crypto_utils.point_to_bytes(shared_point))
        return (tweak + self.spend_private_key) % crypto_utils.CURVE_ORDER


def verify_audit_bundle(bundle: Dict[str, object]) -> bool:
    """Verify a selective-disclosure proof generated for compliant auditing."""

    if not isinstance(bundle, dict):
        return False

    payload = bundle.get("payload")
    signature = bundle.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        return False

    try:
        amount = int(payload["amount"])
        commitment_b64 = payload["amount_commitment"]
        blinding_b64 = payload["amount_blinding"]
        view_key_b64 = payload["view_public_key"]
        timestamp = payload["timestamp"]
        _ = payload.get("tx_id")
        _ = payload.get("stealth_address")
        sig_r_b64 = signature["R"]
        sig_s_b64 = signature["s"]
    except (KeyError, TypeError, ValueError):
        return False

    if not isinstance(timestamp, (int, float)) and timestamp is not None:
        return False

    try:
        commitment_bytes = base64.b64decode(str(commitment_b64).encode("ascii"))
        blinding_bytes = base64.b64decode(str(blinding_b64).encode("ascii"))
        view_bytes = base64.b64decode(str(view_key_b64).encode("ascii"))
        r_bytes = base64.b64decode(str(sig_r_b64).encode("ascii"))
        s_bytes = base64.b64decode(str(sig_s_b64).encode("ascii"))
    except (binascii.Error, ValueError):
        return False

    try:
        commitment_point = crypto_utils.bytes_to_point(commitment_bytes)
        view_point = crypto_utils.bytes_to_point(view_bytes)
        r_point = crypto_utils.bytes_to_point(r_bytes)
    except ValueError:
        return False

    blinding = crypto_utils.bytes_to_int(blinding_bytes)
    s_value = crypto_utils.bytes_to_int(s_bytes)

    expected_commitment = crypto_utils.pedersen_commit(amount, blinding)
    if expected_commitment != commitment_point:
        return False

    message_hash = canonical_hash(payload)
    return crypto_utils.schnorr_verify(message_hash, view_point, (r_point, s_value))


__all__ = ["Wallet", "verify_audit_bundle"]

