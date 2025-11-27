"""FastAPI application exposing the privacy crypto demo over HTTP."""

from __future__ import annotations

import random
import uuid
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .blockchain import Blockchain
from .dex import Dex, PRIVACY_COIN_SYMBOL
from .main import create_transaction
from .wallet import Wallet

app = FastAPI(title="Privacy Crypto Demo", version="1.0.0")

_wallet_store: Dict[str, Wallet] = {}
_rng = random.SystemRandom()
_dex = Dex()

# Initialize Blockchain with a Dev Wallet for the pre-mine
print("--- GENESIS INITIALIZATION ---")
_dev_wallet, _ = Wallet.generate()
print("DEV WALLET (15% PRE-MINE) KEYS:")
print(f"  View Private:  {_dev_wallet.view_private_key}")
print(f"  Spend Private: {_dev_wallet.spend_private_key}")
print(f"  Address:       {_dev_wallet.export_address()}")
print("------------------------------")
_blockchain = Blockchain(dev_wallet=_dev_wallet)


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
    audit_bundle: Dict[str, Any]


class PendingResponse(BaseModel):
    pending: List[Dict[str, Any]]


class MineResponse(BaseModel):
    block_index: int
    hash: str
    transactions: List[Dict[str, Any]]


class DexPoolCreateRequest(BaseModel):
    other_asset: str = Field(min_length=2, max_length=16)
    privacy_amount: int = Field(gt=0)
    other_amount: int = Field(gt=0)
    fee_bps: int = Field(default=30, ge=0, lt=10_000)


class DexPoolResponse(BaseModel):
    pool_id: str
    other_asset: str
    privacy_reserve: int
    other_reserve: int
    fee_bps: int
    total_shares: int


class DexLiquidityRequest(BaseModel):
    provider_id: str = Field(min_length=1, max_length=64)
    privacy_amount: int = Field(gt=0)
    other_amount: int = Field(gt=0)


class DexLiquidityResponse(BaseModel):
    minted_shares: int
    total_shares: int


class DexWithdrawRequest(BaseModel):
    provider_id: str = Field(min_length=1, max_length=64)
    share_amount: int = Field(gt=0)


class DexWithdrawResponse(BaseModel):
    privacy_withdrawn: int
    other_withdrawn: int
    total_shares: int


class DexSwapRequest(BaseModel):
    pool_id: str
    input_asset: str
    input_amount: int = Field(gt=0)
    min_output_amount: int | None = Field(default=None, ge=0)


class DexSwapResponse(BaseModel):
    pool_id: str
    input_asset: str
    output_asset: str
    input_amount: int
    output_amount: int
    fee_bps: int


class DexQuoteRequest(BaseModel):
    pool_id: str
    input_asset: str
    input_amount: int = Field(gt=0)


def _format_wallet(wallet_id: str, wallet: Wallet) -> WalletSummary:
    return WalletSummary(wallet_id=wallet_id, address=wallet.export_address())


@app.post("/wallets", response_model=WalletResponse)
def create_wallet() -> WalletResponse:
    """Generate a new wallet and return its credentials."""

    wallet, _ = Wallet.generate()
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

    audit_bundle = transaction.audit_bundle or {}
    return TransactionResponse(
        tx_id=tx_dict["tx_id"],
        pending_transactions=len(_blockchain.pending_transactions),
        audit_bundle=audit_bundle,
    )


@app.post("/mine", response_model=MineResponse)
def mine_block() -> MineResponse:
    """Mine the current pending transactions into a new block."""

    # In a real node, the miner uses their own wallet.
    # For this demo, we use a 'miner' wallet stored locally or generate one.
    miner_id = "miner_wallet"
    if miner_id not in _wallet_store:
        _wallet_store[miner_id], _ = Wallet.generate()

    miner_wallet = _wallet_store[miner_id]

    try:
        # Mine block and credit reward to the miner_wallet
        block = _blockchain.mine_block(miner_wallet=miner_wallet)
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
    import os
    if os.path.exists("blockchain_data.json"):
        os.remove("blockchain_data.json")
    _dev_wallet, _ = Wallet.generate()
    _blockchain = Blockchain(dev_wallet=_dev_wallet)
    global _dex
    _dex = Dex()


__all__ = ["app", "reset_state"]


@app.post("/dex/pools", response_model=DexPoolResponse)
def create_dex_pool(payload: DexPoolCreateRequest) -> DexPoolResponse:
    try:
        pool = _dex.create_pool(
            payload.other_asset,
            payload.privacy_amount,
            payload.other_amount,
            fee_bps=payload.fee_bps,
            provider_id="api",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DexPoolResponse(**pool.as_dict())


@app.get("/dex/pools", response_model=List[DexPoolResponse])
def list_dex_pools() -> List[DexPoolResponse]:
    return [DexPoolResponse(**pool) for pool in _dex.list_pools()]


@app.post("/dex/pools/{pool_id}/liquidity", response_model=DexLiquidityResponse)
def add_liquidity(pool_id: str, payload: DexLiquidityRequest) -> DexLiquidityResponse:
    try:
        result = _dex.provide_liquidity(
            pool_id,
            payload.provider_id,
            payload.privacy_amount,
            payload.other_amount,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DexLiquidityResponse(**result)


@app.post("/dex/pools/{pool_id}/withdraw", response_model=DexWithdrawResponse)
def withdraw_liquidity(pool_id: str, payload: DexWithdrawRequest) -> DexWithdrawResponse:
    try:
        result = _dex.withdraw_liquidity(pool_id, payload.provider_id, payload.share_amount)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DexWithdrawResponse(**result)


@app.post("/dex/swap", response_model=DexSwapResponse)
def swap_assets(payload: DexSwapRequest) -> DexSwapResponse:
    min_output = payload.min_output_amount
    try:
        result = _dex.execute_swap(
            payload.pool_id,
            payload.input_asset,
            payload.input_amount,
            min_output_amount=min_output,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DexSwapResponse(**result)


@app.post("/dex/quote", response_model=DexSwapResponse)
def quote_swap(payload: DexQuoteRequest) -> DexSwapResponse:
    try:
        result = _dex.quote_swap(payload.pool_id, payload.input_asset, payload.input_amount)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DexSwapResponse(**result)

