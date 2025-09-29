"""Blockchain primitives with proof-of-work and transaction validation."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Dict, List

from . import crypto_utils, ring_signature


def compute_hash(block: "Block") -> str:
    """Compute the SHA-256 hash of a block's immutable fields."""

    block_dict = {
        "index": block.index,
        "timestamp": block.timestamp,
        "transactions": block.transactions,
        "previous_hash": block.previous_hash,
        "nonce": block.nonce,
    }
    serialized = json.dumps(block_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: float
    transactions: List[Dict[str, object]]
    previous_hash: str
    nonce: int = 0
    hash: str = ""


def _decode_point(value: str):
    return crypto_utils.bytes_to_point(base64.b64decode(value))


def _decode_scalar(value: str) -> int:
    return crypto_utils.bytes_to_int(base64.b64decode(value))


class Blockchain:
    """Proof-of-work blockchain with privacy-aware transaction validation."""

    difficulty: int = 4

    def __init__(self) -> None:
        self.chain: List[Block] = [self._create_genesis_block()]
        self.pending_transactions: List[Dict[str, object]] = []
        self.spent_key_images: set[str] = set()
        self.seen_transactions: set[str] = set()

    def _create_genesis_block(self) -> Block:
        block = Block(index=0, timestamp=time.time(), transactions=[], previous_hash="0" * 64)
        block = self._mine_block(block)
        return block

    def _mine_block(self, block: Block) -> Block:
        while True:
            block.hash = compute_hash(block)
            if block.hash.startswith("0" * self.difficulty):
                return block
            block.nonce += 1

    def add_transaction(self, transaction: Dict[str, object]) -> None:
        if not self.validate_transaction(transaction):
            raise ValueError("Invalid transaction")
        tx_id = transaction.get("tx_id")
        if tx_id in self.seen_transactions:
            raise ValueError("Duplicate transaction")
        if transaction["key_image"] in self.spent_key_images:
            raise ValueError("Double spend detected")
        self.pending_transactions.append(transaction)
        self.seen_transactions.add(tx_id)

    def validate_transaction(self, transaction: Dict[str, object]) -> bool:
        required_fields = {
            "ring_public_keys",
            "key_image",
            "stealth_address",
            "ephemeral_public_key",
            "encrypted_amount",
            "amount_commitment",
            "commitment_proof",
            "ring_signature",
            "timestamp",
        }
        if not required_fields.issubset(transaction):
            return False

        try:
            commitment_proof = transaction["commitment_proof"]
            commitment_point = _decode_point(commitment_proof["commitment"])
            proof_point = _decode_point(commitment_proof["t"])
            s1 = _decode_scalar(commitment_proof["s1"])
            s2 = _decode_scalar(commitment_proof["s2"])
        except (KeyError, ValueError):
            return False

        if transaction.get("amount_commitment") != commitment_proof.get("commitment"):
            return False

        if not crypto_utils.verify_commitment(commitment_point, proof_point, s1, s2):
            return False

        try:
            ring_points = [_decode_point(item) for item in transaction["ring_public_keys"]]
        except ValueError:
            return False

        message_payload = {
            "ring_public_keys": transaction["ring_public_keys"],
            "key_image": transaction["key_image"],
            "stealth_address": transaction["stealth_address"],
            "ephemeral_public_key": transaction["ephemeral_public_key"],
            "amount_commitment": transaction["commitment_proof"],
            "memo": transaction.get("memo"),
        }
        serialized = json.dumps(message_payload, sort_keys=True, separators=(",", ":"))
        message = crypto_utils.hash_bytes(serialized.encode("utf-8"))

        try:
            signature = transaction["ring_signature"]
        except KeyError:
            return False

        try:
            if not ring_signature.verify(message, ring_points, signature):
                return False
        except (KeyError, TypeError):
            return False

        # Key images must be valid curve points
        try:
            _decode_point(transaction["key_image"])
        except ValueError:
            return False

        return True

    def mine_block(self) -> Block:
        if not self.pending_transactions:
            raise ValueError("No pending transactions to mine")

        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.chain[-1].hash,
        )
        new_block = self._mine_block(new_block)
        if not self._validate_block(new_block, self.chain[-1]):
            raise ValueError("New block failed validation")
        self.chain.append(new_block)
        for transaction in new_block.transactions:
            self.spent_key_images.add(transaction["key_image"])
        self.pending_transactions = []
        return new_block

    def _validate_block(self, block: Block, previous_block: Block) -> bool:
        if block.previous_hash != previous_block.hash:
            return False
        if compute_hash(block) != block.hash:
            return False
        if not block.hash.startswith("0" * self.difficulty):
            return False
        for transaction in block.transactions:
            if not self.validate_transaction(transaction):
                return False
        return True

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            if not self._validate_block(self.chain[i], self.chain[i - 1]):
                return False
        return True

