"""Wallet management utilities for the privacy crypto prototype."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Tuple

from ecdsa.ellipticcurve import Point

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

    def key_image(self) -> Point:
        """Derive a key image to prevent double spending."""

        public_bytes = crypto_utils.point_to_bytes(self.spend_public_key)
        hashed_point = crypto_utils.hash_to_point(public_bytes)
        return crypto_utils.scalar_mult(self.spend_private_key, hashed_point)

    def create_shared_secret(self, ephemeral_public: Point) -> bytes:
        return crypto_utils.derive_shared_secret(self.view_private_key, ephemeral_public)

    def public_keys(self) -> Tuple[Point, Point]:
        return self.view_public_key, self.spend_public_key

