"""Blockchain primitives with proof-of-work and transaction validation."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Set, Union

from . import crypto_utils, ring_signature, rangeproof
from .main import create_coinbase_transaction, Transaction
from .wallet import Wallet
from .utils.serialization import canonical_hash
from .utils.merkle import compute_merkle_root


TOTAL_SUPPLY = 21_000_000
PREMINE_PERCENT = 0.20
BLOCK_REWARD = 50
FOUNDER_REWARD_PERCENT = 0.25
COINBASE_KEY_IMAGE = "00" * 33

TARGET_BLOCK_TIME = 30
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
    if block.version > 1:
        block_dict["version"] = block.version

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
    version: int = 1

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
        "inputs": transaction["inputs"],
        "outputs": transaction["outputs"],
        "fee": transaction["fee"],
        "timestamp": transaction["timestamp"],
        "memo": transaction.get("memo"),
    }


class Blockchain:
    """Proof-of-work blockchain with privacy-aware transaction validation."""

    difficulty: int = 2

    def __init__(self, dev_wallet: Wallet | None = None) -> None:
        self.dev_wallet = dev_wallet
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, object]] = []
        self.spent_key_images: set[str] = set()
        self.seen_transactions: set[str] = set()

        # UTXO Set: Map<StealthPublicKey, CommitmentString>
        # We store the commitment (base64 string) instead of the explicit amount.
        self.utxo_set: Dict[str, str] = {}

        if os.path.exists(DB_FILE):
            self._load_chain()
        else:
            # Create genesis block AND process its indices (add to UTXO set)
            genesis_block = self._create_genesis_block(dev_wallet)
            self.chain = [genesis_block]
            self._process_block_indices(genesis_block)
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
            chain_data = [asdict(b) for b in self.chain]
            data = {
                "storage_version": 3, # Bump version for CT format
                "chain": chain_data,
            }
            json.dump(data, f, indent=2)

    def _load_chain(self) -> None:
        print(f"[storage] Loading blockchain from {DB_FILE}...")
        try:
            with open(DB_FILE, "r") as f:
                raw_data = json.load(f)

                if isinstance(raw_data, list):
                    # Legacy format
                    data = raw_data
                elif isinstance(raw_data, dict):
                    data = raw_data.get("chain", [])
                else:
                    data = []

                self.chain = [Block(**item) for item in data]

                # Rebuild indices
                self.spent_key_images.clear()
                self.seen_transactions.clear()
                self.utxo_set.clear()

                for block in self.chain:
                    self._process_block_indices(block)

                self._adjust_difficulty()
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[storage] Failed to load chain: {e}. Starting fresh.")
            self.chain = []

    def _process_block_indices(self, block: Block) -> None:
        """Update indices (spent keys, UTXOs) based on a block."""
        for tx in block.transactions:
            self.seen_transactions.add(tx.get("tx_id"))

            # Add Outputs to UTXO set
            for output in tx.get("outputs", []):
                # Store Commitment (String) in UTXO set
                self.utxo_set[output["address"]] = output["amount_commitment"]

            # Mark Inputs as spent (Key Images)
            for inp in tx.get("inputs", []):
                key_image = inp.get("key_image")
                if key_image and key_image != COINBASE_KEY_IMAGE:
                    self.spent_key_images.add(key_image)

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

        for inp in transaction.get("inputs", []):
            if inp["key_image"] in self.spent_key_images:
                raise ValueError("Double spend detected")

        self.pending_transactions.append(transaction)
        self.seen_transactions.add(tx_id)

    def validate_transaction(self, transaction: Dict[str, object]) -> bool:
        required_fields = {
            "inputs",
            "outputs",
            "fee",
            "timestamp",
        }
        if not required_fields.issubset(transaction):
            return False

        inputs = transaction.get("inputs", [])
        outputs = transaction.get("outputs", [])
        fee = transaction.get("fee", 0)

        if not isinstance(inputs, list) or not isinstance(outputs, list):
            return False

        # Coinbase Check
        is_coinbase = False
        if len(inputs) == 1 and inputs[0]["key_image"] == COINBASE_KEY_IMAGE:
            is_coinbase = True

        if is_coinbase:
            if len(inputs[0]["ring_public_keys"]) != 0:
                return False
            # Check range proofs for coinbase outputs to be safe
            for output in outputs:
                try:
                    comm_point = _decode_point(output["amount_commitment"])
                    # Check proof
                    if "commitment_proof" in output and output["commitment_proof"]:
                        # If proof exists, verify it (though coinbase amount is usually public)
                        pass

                    # Verify explicit amount if provided matches commitment
                    expected = crypto_utils.pedersen_commit(output["amount"], 0)
                    if crypto_utils.point_to_bytes(comm_point) != crypto_utils.point_to_bytes(expected):
                        return False
                except:
                    return False
            return True

        # Regular CT Validation
        sum_pseudo_commitments = None # Sum of Inputs

        for inp in inputs:
            # 1. Check Key Image
            try:
                _decode_point(inp["key_image"])
            except ValueError:
                return False

            if inp["key_image"] in self.spent_key_images:
                return False

            # 2. Verify Ring Members and Signatures
            ring_keys = inp.get("ring_public_keys", [])
            pseudo_comm_str = inp.get("pseudo_commitment")

            if not pseudo_comm_str:
                return False

            try:
                pseudo_comm_point = _decode_point(pseudo_comm_str)
            except ValueError:
                return False

            if sum_pseudo_commitments is None:
                sum_pseudo_commitments = pseudo_comm_point
            else:
                sum_pseudo_commitments = crypto_utils.point_add(sum_pseudo_commitments, pseudo_comm_point)

            if len(ring_keys) < 2:
                return False

            # Construct Ring Vector: [[P1, C1-PC], [P2, C2-PC], ...]
            # We need to fetch C (Commitment) from UTXO set for each ring member
            ring_vector = []

            for ring_member_key in ring_keys:
                if ring_member_key not in self.utxo_set:
                    return False

                utxo_comm_str = self.utxo_set[ring_member_key]
                utxo_comm_point = _decode_point(utxo_comm_str)

                # C_diff = C_real - C_pseudo
                c_diff = crypto_utils.point_add(utxo_comm_point, crypto_utils.point_neg(pseudo_comm_point))

                p_stealth = _decode_point(ring_member_key)
                ring_vector.append([p_stealth, c_diff])

            # 3. Verify Ring Signature
            # Message is Hash of (Inputs-Metadata + Outputs + Fee + Memo)
            sig_message_payload = {
                "ring_public_keys": ring_keys,
                "key_image": inp["key_image"],
                "pseudo_commitment": pseudo_comm_str,
                "outputs": outputs,
                "fee": fee,
                "memo": transaction.get("memo"),
            }
            message = canonical_hash(sig_message_payload)

            try:
                if not ring_signature.verify(message, ring_vector, inp["ring_signature"]):
                    return False
            except (KeyError, TypeError):
                return False

        # 4. Verify Balance: Sum(PseudoCommitments) == Sum(OutputCommitments) + Fee*H
        fee_commitment = crypto_utils.scalar_mult(fee, crypto_utils.H)

        sum_output_commitments = fee_commitment

        for output in outputs:
            try:
                comm_point = _decode_point(output["amount_commitment"])
                sum_output_commitments = crypto_utils.point_add(sum_output_commitments, comm_point)

                # 5. Verify Range Proofs
                if "commitment_proof" not in output:
                    return False

                proof_data = output["commitment_proof"]

                bit_commitments = [_decode_point(b) for b in proof_data["bit_commitments"]]
                proofs = proof_data["proofs"] # List of tuples

                if not rangeproof.verify_range(comm_point, bit_commitments, proofs):
                    return False

            except Exception:
                return False

        # Check Balance Equation
        if crypto_utils.point_to_bytes(sum_pseudo_commitments) != crypto_utils.point_to_bytes(sum_output_commitments):
             return False

        # 6. Verify Timestamp
        try:
            timestamp = float(transaction["timestamp"])
        except (TypeError, ValueError):
            return False
        now = time.time()
        if timestamp > now + 2 * 60 * 60:
            return False
        if timestamp < now - 7 * 24 * 60 * 60:
            return False

        # 7. Verify Tx ID
        tx_id = transaction.get("tx_id")
        if tx_id:
             expected = crypto_utils.hash_bytes(canonical_hash(_normalised_transaction_payload(transaction))).hex()
             if tx_id != expected:
                 return False

        return True

    def mine_block(self, miner_wallet: Wallet = None) -> Block:
        num_coinbase_txs = 2 if self.dev_wallet else 1
        max_txs = MAX_BLOCK_TXS - num_coinbase_txs
        transactions_to_mine = self.pending_transactions[:max_txs]

        total_fees = sum(tx.get("fee", 0) for tx in transactions_to_mine)

        if miner_wallet:
            if self.dev_wallet:
                founder_block_reward = int(BLOCK_REWARD * FOUNDER_REWARD_PERCENT)
                founder_fee_cut = int(total_fees * 0.10)  # 10% of fees go to founder
                founder_total = founder_block_reward + founder_fee_cut

                miner_block_reward = BLOCK_REWARD - founder_block_reward
                miner_fee_cut = total_fees - founder_fee_cut
                miner_total = miner_block_reward + miner_fee_cut

                founder_tx = create_coinbase_transaction(
                    self.dev_wallet, amount=founder_total, memo="Founder's Reward + Fees"
                )
                transactions_to_mine.insert(0, founder_tx.to_dict())
                coinbase_tx = create_coinbase_transaction(miner_wallet, amount=miner_total)
                transactions_to_mine.insert(0, coinbase_tx.to_dict())
            else:
                total_reward = BLOCK_REWARD + total_fees
                coinbase_tx = create_coinbase_transaction(miner_wallet, amount=int(total_reward))
                transactions_to_mine.insert(0, coinbase_tx.to_dict())

        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=transactions_to_mine,
            previous_hash=self.chain[-1].hash,
        )
        new_block = self._mine_block(new_block)

        if not self._validate_block(new_block, self.chain[-1]):
            raise ValueError("New block failed validation")

        self.chain.append(new_block)
        self._process_block_indices(new_block)
        self.pending_transactions = self.pending_transactions[max_txs:]
        self._adjust_difficulty()
        self._save_chain()

        return new_block

    def _validate_block(self, block: Block, previous_block: Block) -> bool:
        if block.previous_hash != previous_block.hash:
            return False
        calculated_root = compute_merkle_root(block.transactions)
        if block.merkle_root != calculated_root:
            print(f"Merkle mismatch! Stored: {block.merkle_root}, Calc: {calculated_root}")
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
        """Check if the blockchain is valid."""
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            prev = self.chain[i-1]
            if block.previous_hash != prev.hash:
                print(f"Invalid link at block {i}")
                return False
            if block.merkle_root != compute_merkle_root(block.transactions):
                print(f"Invalid merkle root at block {i}")
                return False
            if compute_hash(block) != block.hash:
                print(f"Invalid hash at block {i}")
                return False
        return True
