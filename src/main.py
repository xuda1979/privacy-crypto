"""High-level transaction construction helpers for the privacy crypto demo."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Optional

from nacl import secret, utils

from . import crypto_utils, ring_signature
from .wallet import Wallet
from .utils.serialization import canonical_hash


def _encode_point(point) -> str:
    return base64.b64encode(crypto_utils.point_to_bytes(point)).decode("ascii")


def _encode_scalar(value: int) -> str:
    return base64.b64encode(crypto_utils.int_to_bytes(value)).decode("ascii")

@dataclass
class TransactionInput:
    """Represents a single input to a transaction."""
    amount: int
    key_image: str
    ring_public_keys: List[str]
    ring_signature: Dict[str, object]

@dataclass
class TransactionOutput:
    """Represents a single output from a transaction."""
    address: str # Stealth address
    amount: int
    ephemeral_public_key: str
    encrypted_amount: Optional[str] = None # kept for potential future use or backward compatibility
    amount_commitment: str = ""
    commitment_proof: Dict[str, str] = field(default_factory=dict)

@dataclass
class Transaction:
    """Representation of a privacy-preserving transaction."""

    # We support only 1 input currently for simplicity in ring signature handling
    inputs: List[Dict[str, object]]
    outputs: List[Dict[str, object]]
    fee: int
    timestamp: float = field(default_factory=time.time)
    memo: str | None = None
    tx_id: str = ""

    audit_bundle: Dict[str, object] | None = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, object]:
        payload = {
            "inputs": self.inputs,
            "outputs": self.outputs,
            "fee": self.fee,
            "timestamp": self.timestamp,
        }
        if self.memo is not None:
            payload["memo"] = self.memo

        # Calculate ID if missing
        if not self.tx_id:
            self.tx_id = self.compute_tx_id()

        payload["tx_id"] = self.tx_id
        return payload

    def compute_tx_id(self) -> str:
        # Canonical hash of the transaction content
        payload = {
            "inputs": self.inputs,
            "outputs": self.outputs,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "memo": self.memo,
        }
        return crypto_utils.hash_bytes(canonical_hash(payload)).hex()


def create_transaction(
    sender_wallet: Wallet,
    recipient_wallet: Wallet,
    amount: int,
    ring_members: Sequence[Dict[str, object]], # List of UTXOs (dicts with 'amount', 'stealth_public_key')
    input_utxo: Dict[str, object], # The specific UTXO being spent
    fee: int = 0,
    memo: str | None = None,
) -> Transaction:
    """Construct a private transaction from *sender* to *recipient*.
    """

    if amount <= 0:
        raise ValueError("Amount must be positive")

    # 1. Validate Input
    if input_utxo['amount'] < amount + fee:
        raise ValueError(f"Insufficient funds in selected UTXO. Have {input_utxo['amount']}, need {amount + fee}")

    change_amount = input_utxo['amount'] - amount - fee

    # 2. Recover One-Time Private Key for the Input
    try:
        ephemeral_public_str = input_utxo['ephemeral_public_key']
        ephemeral_public_point = crypto_utils.bytes_to_point(base64.b64decode(ephemeral_public_str))
    except (KeyError, ValueError):
        raise ValueError("Input UTXO missing valid ephemeral_public_key")

    shared_secret_point = crypto_utils.scalar_mult(sender_wallet.view_private_key, ephemeral_public_point)
    shared_secret = crypto_utils.hash_to_int(crypto_utils.point_to_bytes(shared_secret_point))

    one_time_private_key = (shared_secret + sender_wallet.spend_private_key) % crypto_utils.CURVE_ORDER

    one_time_public_point = crypto_utils.scalar_mult(one_time_private_key)
    stealth_address_point = crypto_utils.bytes_to_point(base64.b64decode(input_utxo['stealth_public_key']))

    if crypto_utils.point_to_bytes(one_time_public_point) != crypto_utils.point_to_bytes(stealth_address_point):
         raise ValueError("Derived private key does not match UTXO stealth address. Not your UTXO?")

    # 3. Build Ring
    for member in ring_members:
        if member['amount'] != input_utxo['amount']:
            raise ValueError("All ring members must have the same amount as the input")

    ring_points = []
    for member in ring_members:
        pt = crypto_utils.bytes_to_point(base64.b64decode(member['stealth_public_key']))
        ring_points.append(pt)

    ring_serialized = [_encode_point(p) for p in ring_points]

    try:
        signer_index = [m['stealth_public_key'] for m in ring_members].index(input_utxo['stealth_public_key'])
    except ValueError:
        raise ValueError("Input UTXO must be in ring members")

    # 4. Create Outputs
    tx_outputs = []

    # Destination Output
    dest_ephemeral_scalar, dest_ephemeral_public, dest_stealth_public = crypto_utils.derive_stealth_address(
        recipient_wallet.view_public_key, recipient_wallet.spend_public_key
    )

    dest_commitment = crypto_utils.pedersen_commit(amount, 0)

    dest_output = {
        "address": _encode_point(dest_stealth_public),
        "amount": amount,
        "ephemeral_public_key": _encode_point(dest_ephemeral_public),
        "amount_commitment": _encode_point(dest_commitment),
    }
    tx_outputs.append(dest_output)

    # Change Output (if any)
    if change_amount > 0:
        change_ephemeral_scalar, change_ephemeral_public, change_stealth_public = crypto_utils.derive_stealth_address(
            sender_wallet.view_public_key, sender_wallet.spend_public_key
        )
        change_commitment = crypto_utils.pedersen_commit(change_amount, 0)

        change_output = {
            "address": _encode_point(change_stealth_public),
            "amount": change_amount,
            "ephemeral_public_key": _encode_point(change_ephemeral_public),
            "amount_commitment": _encode_point(change_commitment),
        }
        tx_outputs.append(change_output)

    # 5. Sign Input
    key_image_point = crypto_utils.generate_key_image(one_time_private_key, one_time_public_point)
    key_image = _encode_point(key_image_point)

    sig_message_payload = {
        "ring_public_keys": ring_serialized,
        "key_image": key_image,
        "input_amount": input_utxo['amount'],
        "outputs": tx_outputs,
        "fee": fee,
        "memo": memo,
    }
    message = canonical_hash(sig_message_payload)

    ring_signature_payload = ring_signature.sign(message, ring_points, one_time_private_key, signer_index)

    input_data = {
        "amount": input_utxo['amount'],
        "key_image": key_image,
        "ring_public_keys": ring_serialized,
        "ring_signature": ring_signature_payload
    }

    tx = Transaction(
        inputs=[input_data],
        outputs=tx_outputs,
        fee=fee,
        memo=memo
    )
    tx_id = tx.compute_tx_id()

    # 6. Create Audit Bundle (Optional but requested for API test compatibility)
    # We sign the destination amount info.
    # Note: Original code used `encrypted_amount` etc.
    # We use explicit amount.

    audit_payload = {
        "tx_id": tx_id,
        "amount": amount,
        "amount_commitment": dest_output["amount_commitment"],
        "amount_blinding": _encode_scalar(0), # Explicit amount -> blinding 0
        "view_public_key": _encode_point(sender_wallet.view_public_key),
        "stealth_address": dest_output["address"], # Destination address?
        "memo": memo,
        "timestamp": tx.timestamp,
    }
    audit_message = canonical_hash(audit_payload)
    # Sender signs with VIEW key to prove they authorized/viewed it?
    signature = crypto_utils.schnorr_sign(audit_message, sender_wallet.view_private_key)
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
    """Construct a coinbase transaction."""

    ephemeral_scalar, ephemeral_public, stealth_public = crypto_utils.derive_stealth_address(
        recipient.view_public_key, recipient.spend_public_key
    )

    commitment = crypto_utils.pedersen_commit(amount, 0)

    output = {
        "address": _encode_point(stealth_public),
        "amount": amount,
        "ephemeral_public_key": _encode_point(ephemeral_public),
        "amount_commitment": _encode_point(commitment),
    }

    from .blockchain import COINBASE_KEY_IMAGE

    input_data = {
        "amount": 0,
        "key_image": COINBASE_KEY_IMAGE,
        "ring_public_keys": [],
        "ring_signature": {}
    }

    return Transaction(
        inputs=[input_data],
        outputs=[output],
        fee=0,
        memo=memo
    )

def main() -> None:  # pragma: no cover - demonstration helper
    pass

if __name__ == "__main__":  # pragma: no cover
    main()
