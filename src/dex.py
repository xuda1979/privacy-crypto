"""Simple constant-product DEX primitives for swapping the privacy coin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


PRIVACY_COIN_SYMBOL = "PRV"


@dataclass
class LiquidityPool:
    """Constant-product liquidity pool between the privacy coin and another asset."""

    pool_id: str
    other_asset: str
    fee_bps: int = 30
    privacy_reserve: int = 0
    other_reserve: int = 0
    total_shares: int = 0
    provider_shares: Dict[str, int] = field(default_factory=dict)

    def _validate_positive(self, *values: int) -> None:
        if any(value <= 0 for value in values):
            raise ValueError("Amounts must be positive integers")

    def add_liquidity(self, provider_id: str, privacy_amount: int, other_amount: int) -> int:
        """Add liquidity while maintaining the reserve ratio."""

        self._validate_positive(privacy_amount, other_amount)
        if provider_id == "":
            raise ValueError("Provider id cannot be empty")
        if self.total_shares == 0:
            minted = privacy_amount
        else:
            if privacy_amount * self.other_reserve != other_amount * self.privacy_reserve:
                raise ValueError("Liquidity must preserve current pool ratio")
            minted = (privacy_amount * self.total_shares) // self.privacy_reserve
            if minted <= 0:
                raise ValueError("Provided liquidity is too small for the current pool size")

        self.privacy_reserve += privacy_amount
        self.other_reserve += other_amount
        self.total_shares += minted
        self.provider_shares[provider_id] = self.provider_shares.get(provider_id, 0) + minted
        return minted

    def remove_liquidity(self, provider_id: str, share_amount: int) -> tuple[int, int]:
        """Remove liquidity proportionally to the provider share."""

        self._validate_positive(share_amount)
        provider_share = self.provider_shares.get(provider_id, 0)
        if share_amount > provider_share:
            raise ValueError("Insufficient share balance")
        if share_amount > self.total_shares:
            raise ValueError("Share amount exceeds pool supply")

        privacy_withdrawn = (share_amount * self.privacy_reserve) // self.total_shares
        other_withdrawn = (share_amount * self.other_reserve) // self.total_shares
        if privacy_withdrawn == 0 or other_withdrawn == 0:
            raise ValueError("Withdrawal too small for current reserves")

        self.privacy_reserve -= privacy_withdrawn
        self.other_reserve -= other_withdrawn
        self.total_shares -= share_amount
        remaining = provider_share - share_amount
        if remaining:
            self.provider_shares[provider_id] = remaining
        else:
            self.provider_shares.pop(provider_id, None)
        return privacy_withdrawn, other_withdrawn

    def _amount_out(self, input_amount: int, input_reserve: int, output_reserve: int) -> int:
        if self.fee_bps < 0 or self.fee_bps >= 10_000:
            raise ValueError("Invalid fee configuration")
        fee_multiplier = 10_000 - self.fee_bps
        amount_in_with_fee = input_amount * fee_multiplier
        numerator = amount_in_with_fee * output_reserve
        denominator = input_reserve * 10_000 + amount_in_with_fee
        if denominator == 0:
            raise ValueError("Pool reserves are empty")
        amount_out = numerator // denominator
        if amount_out <= 0:
            raise ValueError("Input amount too small")
        return amount_out

    def quote(self, input_asset: str, input_amount: int) -> Dict[str, int | str]:
        """Return the swap quote without mutating reserves."""

        self._validate_positive(input_amount)
        if input_asset == PRIVACY_COIN_SYMBOL:
            if self.privacy_reserve == 0 or self.other_reserve == 0:
                raise ValueError("Pool is empty")
            amount_out = self._amount_out(input_amount, self.privacy_reserve, self.other_reserve)
            output_asset = self.other_asset
        elif input_asset == self.other_asset:
            if self.privacy_reserve == 0 or self.other_reserve == 0:
                raise ValueError("Pool is empty")
            amount_out = self._amount_out(input_amount, self.other_reserve, self.privacy_reserve)
            output_asset = PRIVACY_COIN_SYMBOL
        else:
            raise ValueError("Asset not supported by this pool")
        return {
            "pool_id": self.pool_id,
            "input_asset": input_asset,
            "output_asset": output_asset,
            "input_amount": input_amount,
            "output_amount": amount_out,
            "fee_bps": self.fee_bps,
        }

    def swap(self, input_asset: str, input_amount: int, min_output_amount: int | None = None) -> Dict[str, int | str]:
        """Execute a swap and mutate reserves if the quote matches expectations."""

        quote = self.quote(input_asset, input_amount)
        output_amount = quote["output_amount"]
        if min_output_amount is not None and output_amount < min_output_amount:
            raise ValueError("Slippage exceeds limit")

        if input_asset == PRIVACY_COIN_SYMBOL:
            self.privacy_reserve += input_amount
            self.other_reserve -= output_amount
        else:
            self.other_reserve += input_amount
            self.privacy_reserve -= output_amount
        return quote

    def as_dict(self) -> Dict[str, int | str]:
        return {
            "pool_id": self.pool_id,
            "other_asset": self.other_asset,
            "privacy_reserve": self.privacy_reserve,
            "other_reserve": self.other_reserve,
            "fee_bps": self.fee_bps,
            "total_shares": self.total_shares,
        }


class Dex:
    """In-memory registry of liquidity pools supporting swaps."""

    def __init__(self) -> None:
        self.pools: Dict[str, LiquidityPool] = {}

    def _normalise_asset(self, asset: str) -> str:
        cleaned = asset.strip().upper()
        if not cleaned:
            raise ValueError("Asset symbol cannot be empty")
        return cleaned

    def create_pool(
        self,
        other_asset: str,
        privacy_amount: int,
        other_amount: int,
        *,
        fee_bps: int = 30,
        provider_id: str = "protocol",
    ) -> LiquidityPool:
        asset = self._normalise_asset(other_asset)
        if asset == PRIVACY_COIN_SYMBOL:
            raise ValueError("Counter asset must differ from the privacy coin")
        pool_id = f"{PRIVACY_COIN_SYMBOL}-{asset}"
        if pool_id in self.pools:
            raise ValueError("Pool already exists for this asset")
        if fee_bps < 0 or fee_bps >= 10_000:
            raise ValueError("Fee must be between 0 and 9999 bps")
        pool = LiquidityPool(pool_id=pool_id, other_asset=asset, fee_bps=fee_bps)
        pool.add_liquidity(provider_id, privacy_amount, other_amount)
        self.pools[pool_id] = pool
        return pool

    def list_pools(self) -> List[Dict[str, int | str]]:
        return [pool.as_dict() for pool in self.pools.values()]

    def get_pool(self, pool_id: str) -> LiquidityPool:
        try:
            return self.pools[pool_id]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError("Pool not found") from exc

    def provide_liquidity(
        self, pool_id: str, provider_id: str, privacy_amount: int, other_amount: int
    ) -> Dict[str, int]:
        pool = self.get_pool(pool_id)
        minted = pool.add_liquidity(provider_id, privacy_amount, other_amount)
        return {"minted_shares": minted, "total_shares": pool.total_shares}

    def withdraw_liquidity(self, pool_id: str, provider_id: str, share_amount: int) -> Dict[str, int]:
        pool = self.get_pool(pool_id)
        privacy_amount, other_amount = pool.remove_liquidity(provider_id, share_amount)
        return {
            "privacy_withdrawn": privacy_amount,
            "other_withdrawn": other_amount,
            "total_shares": pool.total_shares,
        }

    def quote_swap(self, pool_id: str, input_asset: str, input_amount: int) -> Dict[str, int | str]:
        pool = self.get_pool(pool_id)
        asset = self._normalise_asset(input_asset)
        return pool.quote(asset, input_amount)

    def execute_swap(
        self,
        pool_id: str,
        input_asset: str,
        input_amount: int,
        *,
        min_output_amount: int | None = None,
    ) -> Dict[str, int | str]:
        pool = self.get_pool(pool_id)
        asset = self._normalise_asset(input_asset)
        return pool.swap(asset, input_amount, min_output_amount)


__all__ = ["Dex", "LiquidityPool", "PRIVACY_COIN_SYMBOL"]

