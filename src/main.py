"""High-level transaction construction helpers for the privacy crypto demo."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Optional

from nacl import secret, utils

from . import crypto_utils, ring_signature, rangeproof
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
    encrypted_data: Optional[str] = None # Encrypted {amount, blinding}

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

    # 1. Validate Input (Local Wallet Check)
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

    # 3. Create Pseudo Commitment for Input
    # Try to recover input blinding factor if available
    b_real = 0
    if 'blinding_factor' in input_utxo:
        b_real = input_utxo['blinding_factor']

    b_pseudo = crypto_utils.random_scalar()
    pseudo_commitment = crypto_utils.pedersen_commit(input_utxo['amount'], b_pseudo)

    # 4. Create Outputs with Commitments and Range Proofs
    tx_outputs = []

    # We need Sum(b_inputs) == Sum(b_outputs) + b_fee
    # b_pseudo - (b_dest + b_change) = 0 => b_pseudo = b_dest + b_change

    b_dest = crypto_utils.random_scalar()
    b_change = (b_pseudo - b_dest) % crypto_utils.CURVE_ORDER

    # Destination Output
    dest_ephemeral_scalar, dest_ephemeral_public, dest_stealth_public = crypto_utils.derive_stealth_address(
        recipient_wallet.view_public_key, recipient_wallet.spend_public_key
    )

    # Range Proof for Destination
    dest_bits = 64
    d_bit_comms, d_proofs, d_total_blinding = rangeproof.prove_range(amount, dest_bits)

    # Use the total blinding from proof as b_dest to ensure proof validity
    b_dest = d_total_blinding
    dest_commitment = crypto_utils.pedersen_commit(amount, b_dest)

    dest_proof_data = {
        "bit_commitments": [_encode_point(p) for p in d_bit_comms],
        "proofs": d_proofs
    }

    # Encrypt amount and blinding for recipient
    dest_shared_secret = crypto_utils.derive_shared_secret(dest_ephemeral_scalar, recipient_wallet.view_public_key)
    dest_payload = json.dumps({"amount": amount, "blinding": b_dest}).encode("utf-8")
    dest_encrypted = crypto_utils.encrypt_data(dest_payload, dest_shared_secret)

    dest_output = {
        "address": _encode_point(dest_stealth_public),
        "amount": 0, # HIDDEN
        "ephemeral_public_key": _encode_point(dest_ephemeral_public),
        "amount_commitment": _encode_point(dest_commitment),
        "commitment_proof": dest_proof_data,
        "encrypted_data": base64.b64encode(dest_encrypted).decode("ascii")
    }
    tx_outputs.append(dest_output)

    # Change Output (if any)
    if change_amount > 0:
        change_ephemeral_scalar, change_ephemeral_public, change_stealth_public = crypto_utils.derive_stealth_address(
            sender_wallet.view_public_key, sender_wallet.spend_public_key
        )

        # Range Proof for Change
        change_bits = 64
        c_bit_comms, c_proofs, c_total_blinding = rangeproof.prove_range(change_amount, change_bits)
        b_change_generated = c_total_blinding

        change_commitment = crypto_utils.pedersen_commit(change_amount, b_change_generated)

        change_proof_data = {
            "bit_commitments": [_encode_point(p) for p in c_bit_comms],
            "proofs": c_proofs
        }

        # Encrypt for self (change)
        change_shared_secret = crypto_utils.derive_shared_secret(change_ephemeral_scalar, sender_wallet.view_public_key)
        change_payload = json.dumps({"amount": change_amount, "blinding": b_change_generated}).encode("utf-8")
        change_encrypted = crypto_utils.encrypt_data(change_payload, change_shared_secret)

        change_output = {
            "address": _encode_point(change_stealth_public),
            "amount": 0, # HIDDEN
            "ephemeral_public_key": _encode_point(change_ephemeral_public),
            "amount_commitment": _encode_point(change_commitment),
            "commitment_proof": change_proof_data,
            "encrypted_data": base64.b64encode(change_encrypted).decode("ascii")
        }
        tx_outputs.append(change_output)

        # Adjust b_pseudo
        b_pseudo = (b_dest + b_change_generated) % crypto_utils.CURVE_ORDER
        pseudo_commitment = crypto_utils.pedersen_commit(input_utxo['amount'], b_pseudo)
    else:
        # No change
        b_pseudo = b_dest
        pseudo_commitment = crypto_utils.pedersen_commit(input_utxo['amount'], b_pseudo)


    # 5. Build Ring Vector and Sign Input
    try:
        signer_index = [m['stealth_public_key'] for m in ring_members].index(input_utxo['stealth_public_key'])
    except ValueError:
        raise ValueError("Input UTXO must be in ring members")

    ring_vector = []

    for member in ring_members:
        p_stealth = crypto_utils.bytes_to_point(base64.b64decode(member['stealth_public_key']))

        if 'amount_commitment' in member and member['amount_commitment']:
            c_member = crypto_utils.bytes_to_point(base64.b64decode(member['amount_commitment']))
        else:
            # Fallback for legacy outputs
            c_member = crypto_utils.pedersen_commit(member['amount'], 0)

        c_diff = crypto_utils.point_add(c_member, crypto_utils.point_neg(pseudo_commitment))
        ring_vector.append([p_stealth, c_diff])

    # Key 1: Commitment Difference Key (b_real - b_pseudo)
    priv_diff = (b_real - b_pseudo) % crypto_utils.CURVE_ORDER

    private_keys = [one_time_private_key, priv_diff]

    # Sign
    key_image_point = crypto_utils.generate_key_image(one_time_private_key, one_time_public_point)
    key_image = _encode_point(key_image_point)

    ring_serialized = [m['stealth_public_key'] for m in ring_members]

    sig_message_payload = {
        "ring_public_keys": ring_serialized,
        "key_image": key_image,
        "pseudo_commitment": _encode_point(pseudo_commitment),
        "outputs": tx_outputs,
        "fee": fee,
        "memo": memo,
    }
    message = canonical_hash(sig_message_payload)
    ring_signature_payload = ring_signature.sign(message, ring_vector, private_keys, signer_index)


    input_data = {
        "amount": input_utxo['amount'], # Kept for backward compat but not used for balance check
        "key_image": key_image,
        "ring_public_keys": ring_serialized,
        "pseudo_commitment": _encode_point(pseudo_commitment),
        "ring_signature": ring_signature_payload
    }

    tx = Transaction(
        inputs=[input_data],
        outputs=tx_outputs,
        fee=fee,
        memo=memo
    )
    tx_id = tx.compute_tx_id()

    # 6. Audit Bundle
    # We encrypt a separate audit blob or assume standard audit bundle sufficient.
    # Standard audit bundle signs explicit fields.
    # Since we hid amount, audit bundle logic might need update if it relied on explicit amount in payload.
    # But `Wallet.verify_audit_bundle` takes a bundle (dict).
    # We can put the amount there. It's a selective disclosure proof.

    audit_payload = {
        "tx_id": tx_id,
        "amount": amount,
        "amount_commitment": dest_output["amount_commitment"],
        "amount_blinding": _encode_scalar(b_dest),
        "view_public_key": _encode_point(sender_wallet.view_public_key),
        "stealth_address": dest_output["address"],
        "memo": memo,
        "timestamp": tx.timestamp,
    }
    audit_message = canonical_hash(audit_payload)
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

    # Coinbase uses 0 blinding for transparency/supply check
    commitment = crypto_utils.pedersen_commit(amount, 0)

    output = {
        "address": _encode_point(stealth_public),
        "amount": amount, # Coinbase amount is explicit
        "ephemeral_public_key": _encode_point(ephemeral_public),
        "amount_commitment": _encode_point(commitment),
        # Coinbase technically needs range proof too if we enforce it globally,
        # but usually we trust coinbase or check explicit amount.
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
