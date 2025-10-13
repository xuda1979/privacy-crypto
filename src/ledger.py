"""Helpers for reconstructing wallet activity from blockchain data."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
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
    one_time_private_key: int


@dataclass
class OutgoingTransfer:
    """Outgoing spend initiated by this wallet."""

    tx_id: str
    memo: str | None
    timestamp: float
    block_index: int | None
    ring_size: int


@dataclass
class WalletScanner:
    """Incrementally scan blocks and pending transactions for a wallet."""

    wallet: Wallet
    received_outputs: List[DetectedOutput] = field(default_factory=list)
    outgoing_transactions: List[OutgoingTransfer] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._seen_tx_ids: set[str] = set()
        self._wallet_key_image = self.wallet.key_image()

    def scan_transaction(self, transaction: Dict[str, object], *, block_index: int | None = None) -> None:
        tx_id = transaction.get("tx_id")
        if isinstance(tx_id, str) and tx_id in self._seen_tx_ids:
            return

        if self.wallet.belongs_to_transaction(transaction):
            amount = self.wallet.decrypt_transaction_amount(transaction)
            one_time_private = self.wallet.derive_one_time_private_key(transaction)
            commitment = transaction.get("amount_commitment")
            commitment_str = commitment if isinstance(commitment, str) else ""
            record = DetectedOutput(
                tx_id=tx_id or "",
                amount=amount,
                memo=transaction.get("memo"),
                timestamp=_safe_timestamp(transaction.get("timestamp", 0.0)),
                block_index=block_index,
                amount_commitment=commitment_str,
                one_time_private_key=one_time_private,
            )
            self.received_outputs.append(record)
            if isinstance(tx_id, str):
                self._seen_tx_ids.add(tx_id)
            return

        try:
            key_image_value = transaction["key_image"]
            if not isinstance(key_image_value, str):
                return
            key_image_point = _decode_point(key_image_value)
        except (KeyError, ValueError):
            return

        if key_image_point == self._wallet_key_image:
            ring_public_keys = transaction.get("ring_public_keys")
            ring_size = len(ring_public_keys) if isinstance(ring_public_keys, list) else 0
            record = OutgoingTransfer(
                tx_id=tx_id or "",
                memo=transaction.get("memo"),
                timestamp=_safe_timestamp(transaction.get("timestamp", 0.0)),
                block_index=block_index,
                ring_size=ring_size,
            )
            self.outgoing_transactions.append(record)
            if isinstance(tx_id, str):
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
