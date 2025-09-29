"""High-level transaction construction helpers for the privacy crypto demo."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from nacl import secret, utils

from . import crypto_utils, ring_signature
from .wallet import Wallet


def _encode_point(point) -> str:
    return base64.b64encode(crypto_utils.point_to_bytes(point)).decode("ascii")


def _encode_scalar(value: int) -> str:
    return base64.b64encode(crypto_utils.int_to_bytes(value)).decode("ascii")


def _transaction_message(payload: Dict[str, object]) -> bytes:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return crypto_utils.hash_bytes(serialized.encode("utf-8"))


@dataclass
class Transaction:
    """Representation of a privacy-preserving transaction."""

    ring_public_keys: List[str]
    key_image: str
    stealth_address: str
    ephemeral_public_key: str
    encrypted_amount: str
    amount_commitment: str
    commitment_proof: Dict[str, str]
    ring_signature: Dict[str, object]
    timestamp: float = field(default_factory=time.time)
    memo: str | None = None

    def to_dict(self) -> Dict[str, object]:
        payload = {
            "ring_public_keys": self.ring_public_keys,
            "key_image": self.key_image,
            "stealth_address": self.stealth_address,
            "ephemeral_public_key": self.ephemeral_public_key,
            "encrypted_amount": self.encrypted_amount,
            "amount_commitment": self.amount_commitment,
            "commitment_proof": self.commitment_proof,
            "ring_signature": self.ring_signature,
            "timestamp": self.timestamp,
        }
        if self.memo is not None:
            payload["memo"] = self.memo
        payload["tx_id"] = self.compute_tx_id()
        return payload

    def compute_tx_id(self) -> str:
        message = _transaction_message(
            {
                "ring_public_keys": self.ring_public_keys,
                "key_image": self.key_image,
                "stealth_address": self.stealth_address,
                "ephemeral_public_key": self.ephemeral_public_key,
                "encrypted_amount": self.encrypted_amount,
                "amount_commitment": self.amount_commitment,
                "commitment_proof": self.commitment_proof,
                "timestamp": self.timestamp,
                "memo": self.memo,
            }
        )
        return crypto_utils.hash_bytes(message).hex()


def create_transaction(
    sender: Wallet,
    recipient: Wallet,
    amount: int,
    ring_members: Sequence[Wallet],
    memo: str | None = None,
) -> Transaction:
    """Construct a private transaction from *sender* to *recipient*."""

    if amount <= 0:
        raise ValueError("Amount must be positive")

    # Build the ring of public keys (spend keys) and locate the signer index.
    ring_list = list(ring_members)
    ring_points = [member.spend_public_key for member in ring_list]
    try:
        signer_index = ring_list.index(sender)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("Sender must be part of the ring members") from exc

    ring_serialized = [_encode_point(point) for point in ring_points]

    # Create the stealth address for the recipient.
    ephemeral_scalar, ephemeral_public, stealth_public = crypto_utils.derive_stealth_address(
        recipient.view_public_key, recipient.spend_public_key
    )

    shared_secret = crypto_utils.derive_shared_secret(
        ephemeral_scalar, recipient.view_public_key
    )
    box = secret.SecretBox(shared_secret)
    encrypted_amount = box.encrypt(amount.to_bytes(8, "big"), utils.random(secret.SecretBox.NONCE_SIZE))

    # Pedersen commitment for the confidential amount.
    blinding = crypto_utils.random_scalar()
    commitment = crypto_utils.pedersen_commit(amount, blinding)
    proof_point, s1, s2 = crypto_utils.prove_commitment(amount, blinding)

    commitment_dict = {
        "commitment": _encode_point(commitment),
        "t": _encode_point(proof_point),
        "s1": _encode_scalar(s1),
        "s2": _encode_scalar(s2),
    }

    key_image = _encode_point(sender.key_image())

    message_payload = {
        "ring_public_keys": ring_serialized,
        "key_image": key_image,
        "stealth_address": _encode_point(stealth_public),
        "ephemeral_public_key": _encode_point(ephemeral_public),
        "amount_commitment": commitment_dict,
        "memo": memo,
    }
    message = _transaction_message(message_payload)

    ring_signature_payload = ring_signature.sign(message, ring_points, sender.spend_private_key, signer_index)

    tx = Transaction(
        ring_public_keys=ring_serialized,
        key_image=key_image,
        stealth_address=_encode_point(stealth_public),
        ephemeral_public_key=_encode_point(ephemeral_public),
        encrypted_amount=base64.b64encode(encrypted_amount).decode("ascii"),
        amount_commitment=commitment_dict["commitment"],
        commitment_proof=commitment_dict,
        ring_signature=ring_signature_payload,
        memo=memo,
    )
    return tx


def main() -> None:  # pragma: no cover - demonstration helper
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy_1 = Wallet.generate()
    decoy_2 = Wallet.generate()
    ring = [sender, decoy_1, decoy_2]
    transaction = create_transaction(sender, recipient, amount=25, ring_members=ring, memo="demo")
    print(json.dumps(transaction.to_dict(), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()

