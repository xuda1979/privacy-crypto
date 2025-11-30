"""Helpers for reconstructing wallet activity from blockchain data."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import json
from typing import Dict, Iterable, List

from . import crypto_utils
from .blockchain import Block, Blockchain
from .wallet import Wallet


def _safe_timestamp(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _decode_point(value: str):
    try:
        data = base64.b64decode(value.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid point encoding") from exc
    return crypto_utils.bytes_to_point(data)


@dataclass
class DetectedOutput:
    """Incoming transfer discovered while scanning the ledger."""

    tx_id: str
    amount: int
    memo: str | None
    timestamp: float
    block_index: int | None
    amount_commitment: str
    one_time_private_key: int # To spend it later


@dataclass
class OutgoingTransfer:
    """Outgoing spend initiated by this wallet."""

    tx_id: str
    memo: str | None
    timestamp: float
    block_index: int | None
    ring_size: int
    amount: int # Amount spent (input amount)


@dataclass
class WalletScanner:
    """Incrementally scan blocks and pending transactions for a wallet."""

    wallet: Wallet
    received_outputs: List[DetectedOutput] = field(default_factory=list)
    outgoing_transactions: List[OutgoingTransfer] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._seen_tx_ids: set[str] = set()
        # Outgoing detection is harder with one-time keys.
        # We need to check if ANY input key image belongs to us.
        # Key Image I = x * Hp(P).
        # To check if I is ours, we need to know x (one-time private key).
        # This requires us to have tracked our received outputs and their private keys.
        self.known_key_images: Dict[str, int] = {} # KeyImage -> Amount

    def precompute_key_images(self, outputs: List[DetectedOutput]):
        """Derive key images for all known outputs to detect spends."""
        for out in outputs:
            # We need the ephemeral public key to reconstruct P?
            # Actually, `out` contains `one_time_private_key`.
            # P = xG.
            # I = x * Hp(P).
            x = out.one_time_private_key
            P = crypto_utils.scalar_mult(x, crypto_utils.G)
            I = crypto_utils.generate_key_image(x, P)
            I_str = base64.b64encode(crypto_utils.point_to_bytes(I)).decode("ascii")
            self.known_key_images[I_str] = out.amount

    def scan_transaction(self, transaction: Dict[str, object], *, block_index: int | None = None) -> None:
        tx_id = transaction.get("tx_id")
        if isinstance(tx_id, str) and tx_id in self._seen_tx_ids:
            return

        # Scan for Incoming Outputs
        detected_incoming = False
        for output in transaction.get("outputs", []):
            if self.wallet.belongs_to_output(output):
                # We can calculate one-time private key now
                # belongs_to_output does the check but doesn't return the key.
                # Logic duplicated from Wallet...
                ephemeral = self.wallet._decode_point(output["ephemeral_public_key"])
                shared_point = self.wallet._shared_point_with(ephemeral)
                tweak = crypto_utils.hash_to_int(crypto_utils.point_to_bytes(shared_point))
                one_time_private = (tweak + self.wallet.spend_private_key) % crypto_utils.CURVE_ORDER

                amount = output["amount"] # Public now (0 if confidential)

                # Decrypt if confidential
                if amount == 0 and "encrypted_data" in output and output["encrypted_data"]:
                    try:
                        shared_secret = self.wallet.create_shared_secret(ephemeral)
                        encrypted_bytes = base64.b64decode(output["encrypted_data"])
                        decrypted_bytes = crypto_utils.decrypt_data(encrypted_bytes, shared_secret)
                        data = json.loads(decrypted_bytes.decode("utf-8"))
                        amount = data.get("amount", amount)
                    except Exception:
                        pass # Keep as 0

                record = DetectedOutput(
                    tx_id=tx_id or "",
                    amount=amount,
                    memo=transaction.get("memo"),
                    timestamp=_safe_timestamp(transaction.get("timestamp", 0.0)),
                    block_index=block_index,
                    amount_commitment=output.get("amount_commitment", ""),
                    one_time_private_key=one_time_private,
                )
                self.received_outputs.append(record)
                detected_incoming = True

                # Precompute key image for this new output so we can detect if it's spent later
                P = crypto_utils.scalar_mult(one_time_private, crypto_utils.G)
                I = crypto_utils.generate_key_image(one_time_private, P)
                I_str = base64.b64encode(crypto_utils.point_to_bytes(I)).decode("ascii")
                self.known_key_images[I_str] = amount

        if detected_incoming and isinstance(tx_id, str):
            self._seen_tx_ids.add(tx_id)

        # Scan for Outgoing Inputs (Spends)
        detected_outgoing = False
        for inp in transaction.get("inputs", []):
            key_image = inp.get("key_image")
            if key_image in self.known_key_images:
                # We spent this!
                ring_size = len(inp.get("ring_public_keys", []))
                amount = self.known_key_images[key_image]

                record = OutgoingTransfer(
                    tx_id=tx_id or "",
                    memo=transaction.get("memo"),
                    timestamp=_safe_timestamp(transaction.get("timestamp", 0.0)),
                    block_index=block_index,
                    ring_size=ring_size,
                    amount=amount
                )
                self.outgoing_transactions.append(record)
                detected_outgoing = True

        if detected_outgoing and isinstance(tx_id, str):
            self._seen_tx_ids.add(tx_id)


    def scan_transactions(self, transactions: Iterable[Dict[str, object]], *, block_index: int | None = None) -> None:
        for transaction in transactions:
            self.scan_transaction(transaction, block_index=block_index)

    def scan_block(self, block: Block) -> None:
        self.scan_transactions(block.transactions, block_index=block.index)

    def scan_chain(self, blockchain: Blockchain) -> None:
        for block in blockchain.chain:
            self.scan_block(block)

    def scan_pending(self, pending_transactions: Iterable[Dict[str, object]]) -> None:
        self.scan_transactions(pending_transactions, block_index=None)

    @property
    def total_received(self) -> int:
        return sum(record.amount for record in self.received_outputs)

    def summary(self) -> Dict[str, object]:
        return {
            "total_received": self.total_received,
            "incoming": [record.__dict__ for record in self.received_outputs],
            "outgoing": [record.__dict__ for record in self.outgoing_transactions],
        }


__all__ = [
    "DetectedOutput",
    "OutgoingTransfer",
    "WalletScanner",
]
