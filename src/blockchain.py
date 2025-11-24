"""Blockchain primitives with proof-of-work and transaction validation."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import os
from dataclasses import asdict, dataclass
from typing import Dict, List

from . import crypto_utils, ring_signature
from .main import create_coinbase_transaction
from .wallet import Wallet
from .utils.serialization import canonical_hash
from .utils.merkle import compute_merkle_root


TOTAL_SUPPLY = 21_000_000
PREMINE_PERCENT = 0.15
BLOCK_REWARD = 10
COINBASE_KEY_IMAGE = "00" * 33

TARGET_BLOCK_TIME = 60
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
MAX_BLOCK_TXS = 50
DB_FILE = "blockchain_data.json"

def compute_hash(block: "Block") -> str:
    """Compute the SHA-256 hash of a block's immutable fields."""

    block_dict = {
        "index": block.index,
        "timestamp": block.timestamp,
        "merkle_root": block.merkle_root,
        "previous_hash": block.previous_hash,
        "nonce": block.nonce,
    }
    # Hash only the block header, not the full transaction bodies
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
    merkle_root: str = ""

    def __post_init__(self):
        if not self.merkle_root:
            self.merkle_root = compute_merkle_root(self.transactions)


def _decode_point(value: str):
    data = base64.b64decode(value)
    return crypto_utils.bytes_to_point(data)


def _decode_scalar(value: str) -> int:
    return crypto_utils.bytes_to_int(base64.b64decode(value))


def _normalised_transaction_payload(transaction: Dict[str, object]) -> Dict[str, object]:
    """Return the canonical payload committed to by signatures/tx-id."""

    return {
        "ring_public_keys": transaction["ring_public_keys"],
        "key_image": transaction["key_image"],
        "stealth_address": transaction["stealth_address"],
        "ephemeral_public_key": transaction["ephemeral_public_key"],
        "encrypted_amount": transaction["encrypted_amount"],
        "amount_commitment": transaction["amount_commitment"],
        "commitment_proof": transaction["commitment_proof"],
        "timestamp": transaction["timestamp"],
        "memo": transaction.get("memo"),
    }


class Blockchain:
    """Proof-of-work blockchain with privacy-aware transaction validation."""

    difficulty: int = 2

    def __init__(self, dev_wallet: Wallet | None = None) -> None:
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, object]] = []
        self.spent_key_images: set[str] = set()
        self.seen_transactions: set[str] = set()

        if os.path.exists(DB_FILE):
            self._load_chain()
        else:
            self.chain = [self._create_genesis_block(dev_wallet)]
            self._save_chain()

    def _create_genesis_block(self, dev_wallet: Wallet | None) -> Block:
        transactions = []
        if dev_wallet:
            premine_amount = int(TOTAL_SUPPLY * PREMINE_PERCENT)
            tx = create_coinbase_transaction(dev_wallet, premine_amount, memo="Genesis Pre-mine")
            transactions.append(tx.to_dict())

        block = Block(index=0, timestamp=time.time(), transactions=transactions, previous_hash="0" * 64)
        block = self._mine_block(block)
        return block

    def _adjust_difficulty(self) -> None:
        if len(self.chain) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0:
            return

        start_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
        end_block = self.chain[-1]

        time_taken = end_block.timestamp - start_block.timestamp
        expected_time = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL

        if time_taken < expected_time / 2:
            self.difficulty += 1
            print(f"[consensus] Mining too fast. Increased difficulty to {self.difficulty}")
        elif time_taken > expected_time * 2:
            self.difficulty = max(1, self.difficulty - 1)
            print(f"[consensus] Mining too slow. Decreased difficulty to {self.difficulty}")

    def _save_chain(self) -> None:
        with open(DB_FILE, "w") as f:
            data = [asdict(b) for b in self.chain]
            json.dump(data, f, indent=2)

    def _load_chain(self) -> None:
        print(f"[storage] Loading blockchain from {DB_FILE}...")
        with open(DB_FILE, "r") as f:
            data = json.load(f)
            self.chain = [Block(**item) for item in data]
            for block in self.chain:
                for tx in block.transactions:
                    if tx.get("key_image") and tx["key_image"] != COINBASE_KEY_IMAGE:
                        self.spent_key_images.add(tx["key_image"])
                        self.seen_transactions.add(tx.get("tx_id"))
            self._adjust_difficulty()

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

        is_coinbase = transaction["key_image"] == COINBASE_KEY_IMAGE

        if is_coinbase:
            if len(transaction["ring_public_keys"]) != 0:
                return False
            if transaction.get("ring_signature") not in ({}, None):
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

            try:
                _decode_point(transaction["amount_commitment"])
            except (TypeError, ValueError):
                return False

            if not crypto_utils.verify_commitment(commitment_point, proof_point, s1, s2):
                return False

            try:
                base64.b32decode(transaction["encrypted_amount"], casefold=True)
            except (TypeError, ValueError):
                return False

            try:
                timestamp = float(transaction["timestamp"])
            except (TypeError, ValueError):
                return False
            now = time.time()
            if timestamp > now + 2 * 60 * 60:
                return False
            if timestamp < now - 7 * 24 * 60 * 60:
                return False

            return True

        if not isinstance(transaction.get("ring_public_keys"), list):
            return False
        if len(transaction["ring_public_keys"]) < 2:
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

        try:
            _decode_point(transaction["amount_commitment"])
        except (TypeError, ValueError):
            return False

        if not crypto_utils.verify_commitment(commitment_point, proof_point, s1, s2):
            return False

        try:
            ring_points = [_decode_point(item) for item in transaction["ring_public_keys"]]
        except ValueError:
            return False

        # Do not allow duplicate public keys in the ring to avoid trivial deanonymisation
        if len({crypto_utils.point_to_bytes(point) for point in ring_points}) != len(ring_points):
            return False

        message_payload = {
            "ring_public_keys": transaction["ring_public_keys"],
            "key_image": transaction["key_image"],
            "stealth_address": transaction["stealth_address"],
            "ephemeral_public_key": transaction["ephemeral_public_key"],
            "encrypted_amount": transaction["encrypted_amount"],
            "amount_commitment": transaction["amount_commitment"],
            "memo": transaction.get("memo"),
        }
        message = canonical_hash(message_payload)

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

        # Validate stealth/ephemeral keys are well-formed points
        try:
            _decode_point(transaction["stealth_address"])
            _decode_point(transaction["ephemeral_public_key"])
        except ValueError:
            return False

        # Ensure the encrypted payload is valid base32
        try:
            base64.b32decode(transaction["encrypted_amount"], casefold=True)
        except (TypeError, ValueError):
            return False

        # Prevent excessively skewed timestamps (potential time-warp attacks)
        try:
            timestamp = float(transaction["timestamp"])
        except (TypeError, ValueError):
            return False
        now = time.time()
        if timestamp > now + 2 * 60 * 60:
            return False
        if timestamp < now - 7 * 24 * 60 * 60:
            return False

        # When a transaction id is present ensure it commits to the canonical payload
        tx_id = transaction.get("tx_id")
        if tx_id is not None:
            if not isinstance(tx_id, str):
                return False
            expected = crypto_utils.hash_bytes(canonical_hash(_normalised_transaction_payload(transaction))).hex()
            if tx_id != expected:
                return False

        return True

    def mine_block(self, miner_wallet: Wallet = None) -> Block:
        max_txs = MAX_BLOCK_TXS - 1
        transactions_to_mine = self.pending_transactions[:max_txs]

        if miner_wallet:
            coinbase_tx = create_coinbase_transaction(miner_wallet, amount=BLOCK_REWARD)
            transactions_to_mine.insert(0, coinbase_tx.to_dict())

        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=transactions_to_mine,
            previous_hash=self.chain[-1].hash,
        )
        # Block post-init will compute the merkle_root
        new_block = self._mine_block(new_block)
        if not self._validate_block(new_block, self.chain[-1]):
            raise ValueError("New block failed validation")
        self.chain.append(new_block)
        for transaction in new_block.transactions:
            if transaction["key_image"] != COINBASE_KEY_IMAGE:
                self.spent_key_images.add(transaction["key_image"])

        self.pending_transactions = self.pending_transactions[max_txs:]
        self._adjust_difficulty()
        self._save_chain()

        return new_block

    def _validate_block(self, block: Block, previous_block: Block) -> bool:
        if block.previous_hash != previous_block.hash:
            return False
        calculated_root = compute_merkle_root(block.transactions)
        if block.merkle_root != calculated_root:
            return False
        if compute_hash(block) != block.hash:
            return False
        if not block.hash.startswith("0" * self.difficulty):
            return False
        if block.timestamp <= previous_block.timestamp:
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

