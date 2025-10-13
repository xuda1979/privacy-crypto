"""Wallet management utilities for the privacy crypto prototype."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Dict, Tuple

from ecdsa.ellipticcurve import Point
from nacl import secret

from . import crypto_utils


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
            ciphertext = base64.b64decode(transaction["encrypted_amount"].encode("ascii"))
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

