import pytest

from src.dex import Dex, PRIVACY_COIN_SYMBOL


def test_pool_creation_and_liquidity_flow():
    dex = Dex()
    pool = dex.create_pool("eth", 1_000_000, 500_000, fee_bps=25, provider_id="bootstrap")
    assert pool.privacy_reserve == 1_000_000
    assert pool.other_reserve == 500_000
    assert pool.fee_bps == 25

    minted = dex.provide_liquidity(pool.pool_id, "lp-1", 200_000, 100_000)
    assert minted["minted_shares"] > 0

    withdraw = dex.withdraw_liquidity(pool.pool_id, "lp-1", minted["minted_shares"])
    assert withdraw["privacy_withdrawn"] == 200_000
    assert withdraw["other_withdrawn"] == 100_000


def test_swap_and_quote():
    dex = Dex()
    pool = dex.create_pool("usdc", 2_000_000, 2_000_000)
    quote = dex.quote_swap(pool.pool_id, PRIVACY_COIN_SYMBOL, 100_000)
    assert quote["output_amount"] > 0

    swap = dex.execute_swap(pool.pool_id, PRIVACY_COIN_SYMBOL, 100_000)
    assert swap["output_amount"] == quote["output_amount"]
    assert pool.privacy_reserve > 2_000_000
    assert pool.other_reserve < 2_000_000


def test_ratio_enforced_on_liquidity():
    dex = Dex()
    pool = dex.create_pool("btc", 1_000_000, 100_000)
    with pytest.raises(ValueError):
        dex.provide_liquidity(pool.pool_id, "lp", 100, 50)
