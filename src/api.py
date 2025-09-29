"""FastAPI application exposing the privacy crypto demo over HTTP."""

from __future__ import annotations

import random
import uuid
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .blockchain import Blockchain
from .main import create_transaction
from .wallet import Wallet

app = FastAPI(title="Privacy Crypto Demo", version="1.0.0")

_blockchain = Blockchain()
_wallet_store: Dict[str, Wallet] = {}
_rng = random.SystemRandom()


class WalletSummary(BaseModel):
    wallet_id: str
    address: str


class WalletResponse(WalletSummary):
    view_private_key: str
    spend_private_key: str


class TransactionRequest(BaseModel):
    sender_wallet_id: str
    recipient_wallet_id: str
    amount: int = Field(gt=0, description="Amount of coins to transfer")
    ring_size: int = Field(default=3, ge=2, description="Number of members in the ring")
    memo: str | None = Field(default=None, max_length=280)


class TransactionResponse(BaseModel):
    tx_id: str
    pending_transactions: int


class PendingResponse(BaseModel):
    pending: List[Dict[str, Any]]


class MineResponse(BaseModel):
    block_index: int
    hash: str
    transactions: List[Dict[str, Any]]


def _format_wallet(wallet_id: str, wallet: Wallet) -> WalletSummary:
    return WalletSummary(wallet_id=wallet_id, address=wallet.export_address())


@app.post("/wallets", response_model=WalletResponse)
def create_wallet() -> WalletResponse:
    """Generate a new wallet and return its credentials."""

    wallet = Wallet.generate()
    wallet_id = uuid.uuid4().hex
    _wallet_store[wallet_id] = wallet
    return WalletResponse(
        wallet_id=wallet_id,
        address=wallet.export_address(),
        view_private_key=f"{wallet.view_private_key:x}",
        spend_private_key=f"{wallet.spend_private_key:x}",
    )


@app.get("/wallets", response_model=List[WalletSummary])
def list_wallets() -> List[WalletSummary]:
    """Return the registered wallets without exposing private keys."""

    return [_format_wallet(wallet_id, wallet) for wallet_id, wallet in _wallet_store.items()]


@app.get("/pending", response_model=PendingResponse)
def pending_transactions() -> PendingResponse:
    """Return the list of transactions waiting to be mined."""

    return PendingResponse(pending=_blockchain.pending_transactions)


@app.post("/transactions", response_model=TransactionResponse)
def submit_transaction(payload: TransactionRequest) -> TransactionResponse:
    """Create and queue a privacy-preserving transaction for mining."""

    try:
        sender = _wallet_store[payload.sender_wallet_id]
    except KeyError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Sender wallet not found") from exc
    try:
        recipient = _wallet_store[payload.recipient_wallet_id]
    except KeyError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Recipient wallet not found") from exc

    available_decoys = [wallet for wid, wallet in _wallet_store.items() if wid != payload.sender_wallet_id]
    if len(available_decoys) < payload.ring_size - 1:
        raise HTTPException(status_code=400, detail="Not enough wallets to assemble the requested ring size")

    decoys = _rng.sample(available_decoys, payload.ring_size - 1)
    ring_members = decoys + [sender]
    _rng.shuffle(ring_members)

    transaction = create_transaction(sender, recipient, payload.amount, ring_members, memo=payload.memo)
    tx_dict = transaction.to_dict()

    try:
        _blockchain.add_transaction(tx_dict)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return TransactionResponse(tx_id=tx_dict["tx_id"], pending_transactions=len(_blockchain.pending_transactions))


@app.post("/mine", response_model=MineResponse)
def mine_block() -> MineResponse:
    """Mine the current pending transactions into a new block."""

    try:
        block = _blockchain.mine_block()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return MineResponse(block_index=block.index, hash=block.hash, transactions=block.transactions)


@app.get("/chain")
def get_chain() -> Dict[str, Any]:
    """Return the blockchain with metadata useful for monitoring."""

    chain = [
        {
            "index": block.index,
            "timestamp": block.timestamp,
            "transactions": block.transactions,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "hash": block.hash,
        }
        for block in _blockchain.chain
    ]
    return {"length": len(chain), "chain": chain, "valid": _blockchain.is_chain_valid()}


def reset_state() -> None:
    """Reset the in-memory state. Intended for tests."""

    _wallet_store.clear()
    global _blockchain
    _blockchain = Blockchain()


__all__ = ["app", "reset_state"]

