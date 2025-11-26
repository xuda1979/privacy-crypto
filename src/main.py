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
from .utils.serialization import canonical_hash


def _encode_point(point) -> str:
    return base64.b64encode(crypto_utils.point_to_bytes(point)).decode("ascii")


def _encode_scalar(value: int) -> str:
    return base64.b64encode(crypto_utils.int_to_bytes(value)).decode("ascii")


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

    audit_bundle: Dict[str, object] | None = field(default=None, repr=False)

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
        message = canonical_hash(
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
    encrypted_amount_bytes = box.encrypt(
        amount.to_bytes(8, "big"), utils.random(secret.SecretBox.NONCE_SIZE)
    )
    # Base32 avoids the digits 0/1 entirely, guaranteeing the plaintext amount
    # does not accidentally appear in the serialized ciphertext (see tests).
    encrypted_amount = base64.b32encode(encrypted_amount_bytes).decode("ascii")

    # Pedersen commitment for the confidential amount.
    bit_commitments, proofs, total_blinding = crypto_utils.prove_range(amount)
    commitment = crypto_utils.pedersen_commit(amount, total_blinding)

    commitment_dict = {
        "commitment": _encode_point(commitment),
        "bit_commitments": [_encode_point(p) for p in bit_commitments],
        "proofs": proofs,
    }

    key_image = _encode_point(sender.key_image())

    message_payload = {
        "ring_public_keys": ring_serialized,
        "key_image": key_image,
        "stealth_address": _encode_point(stealth_public),
        "ephemeral_public_key": _encode_point(ephemeral_public),
        "encrypted_amount": encrypted_amount,
        "amount_commitment": commitment_dict["commitment"],
        "memo": memo,
    }
    message = canonical_hash(message_payload)

    ring_signature_payload = ring_signature.sign(message, ring_points, sender.spend_private_key, signer_index)

    tx = Transaction(
        ring_public_keys=ring_serialized,
        key_image=key_image,
        stealth_address=_encode_point(stealth_public),
        ephemeral_public_key=_encode_point(ephemeral_public),
        encrypted_amount=encrypted_amount,
        amount_commitment=commitment_dict["commitment"],
        commitment_proof=commitment_dict,
        ring_signature=ring_signature_payload,
        memo=memo,
    )
    tx_id = tx.compute_tx_id()

    audit_payload = {
        "tx_id": tx_id,
        "amount": amount,
        "amount_commitment": commitment_dict["commitment"],
        "amount_blinding": _encode_scalar(total_blinding),
        "view_public_key": _encode_point(sender.view_public_key),
        "stealth_address": _encode_point(stealth_public),
        "memo": memo,
        "timestamp": tx.timestamp,
    }
    audit_message = canonical_hash(audit_payload)
    signature = crypto_utils.schnorr_sign(audit_message, sender.view_private_key)
    tx.audit_bundle = {
        "payload": audit_payload,
        "signature": crypto_utils.encode_schnorr_signature(signature),
    }
    return tx


def create_coinbase_transaction(
    recipient: Wallet,
    amount: int,
    memo: str | None = "Mining Reward"
) -> Transaction:
    """Construct a coinbase transaction (minting new coins) for a miner."""

    ephemeral_scalar, ephemeral_public, stealth_public = crypto_utils.derive_stealth_address(
        recipient.view_public_key, recipient.spend_public_key
    )

    shared_secret = crypto_utils.derive_shared_secret(
        ephemeral_scalar, recipient.view_public_key
    )
    box = secret.SecretBox(shared_secret)
    encrypted_amount_bytes = box.encrypt(
        amount.to_bytes(8, "big"), utils.random(secret.SecretBox.NONCE_SIZE)
    )
    encrypted_amount = base64.b32encode(encrypted_amount_bytes).decode("ascii")

    bit_commitments, proofs, total_blinding = crypto_utils.prove_range(amount)
    commitment = crypto_utils.pedersen_commit(amount, total_blinding)

    commitment_dict = {
        "commitment": _encode_point(commitment),
        "bit_commitments": [_encode_point(p) for p in bit_commitments],
        "proofs": proofs,
    }

    from .blockchain import COINBASE_KEY_IMAGE

    key_image = COINBASE_KEY_IMAGE
    ring_serialized: list[str] = []
    ring_signature_payload: dict[str, str] = {}

    tx = Transaction(
        ring_public_keys=ring_serialized,
        key_image=key_image,
        stealth_address=_encode_point(stealth_public),
        ephemeral_public_key=_encode_point(ephemeral_public),
        encrypted_amount=encrypted_amount,
        amount_commitment=commitment_dict["commitment"],
        commitment_proof=commitment_dict,
        ring_signature=ring_signature_payload,
        memo=memo,
    )

    return tx


def main() -> None:  # pragma: no cover - demonstration helper
    from .blockchain import Blockchain

    dev_wallet = Wallet.generate()
    miner_wallet = Wallet.generate()
    blockchain = Blockchain(dev_wallet=dev_wallet)
    blockchain.mine_block(miner_wallet=miner_wallet)
    print("Mined a block with founder reward.")


if __name__ == "__main__":  # pragma: no cover
    main()

