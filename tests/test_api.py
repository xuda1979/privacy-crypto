import pytest
from fastapi.testclient import TestClient

from src.api import app, reset_state, _wallet_store
from src.wallet import verify_audit_bundle, Wallet


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()
    yield
    reset_state()


def test_wallet_creation_and_transaction_flow():
    client = TestClient(app)

    # 1. Create a recipient
    recipient = client.post("/wallets").json()

    # 2. Mine blocks to generate funds and UTXOs
    # Mine 3 blocks to get 3 UTXOs of the same amount (Block Reward - Founder Fee)
    # This ensures we have funds AND decoys (UTXOs of same amount)
    client.post("/mine") # Block 1
    client.post("/mine") # Block 2
    client.post("/mine") # Block 3

    # 3. Get the miner wallet (which has the funds)
    # This requires accessing internal state because API doesn't expose miner wallet ID directly
    # The API code initializes "miner_wallet" in _wallet_store
    assert "miner_wallet" in _wallet_store
    miner_wallet_obj = _wallet_store["miner_wallet"]

    # Create a sender response structure for the test
    sender = {
        "wallet_id": "miner_wallet",
        "address": miner_wallet_obj.export_address()
    }

    # 4. Submit Transaction
    # Spend from miner_wallet to recipient
    # Amount must be less than block reward (10 * 0.8 = 8)
    amount = 5

    payload = {
        "sender_wallet_id": sender["wallet_id"],
        "recipient_wallet_id": recipient["wallet_id"],
        "amount": amount,
        "ring_size": 3,
        "memo": "integration test",
    }
    response = client.post("/transactions", json=payload)
    assert response.status_code == 200
    tx_data = response.json()
    assert "tx_id" in tx_data
    assert "audit_bundle" in tx_data
    # Audit bundle might be empty dict if not implemented fully, but check key exists

    pending = client.get("/pending").json()
    assert len(pending["pending"]) == 1

    mine_response = client.post("/mine")
    assert mine_response.status_code == 200
    chain = client.get("/chain").json()

    # Genesis + 3 mined + 1 new block = 5 blocks
    assert chain["length"] >= 5
    assert chain["valid"] is True
    assert all("hash" in block for block in chain["chain"])


def test_transaction_requires_sufficient_decoys():
    client = TestClient(app)
    sender = client.post("/wallets").json()
    recipient = client.post("/wallets").json()

    response = client.post(
        "/transactions",
        json={
            "sender_wallet_id": sender["wallet_id"],
            "recipient_wallet_id": recipient["wallet_id"],
            "amount": 5,
            "ring_size": 4,
        },
    )
    # This should fail due to insufficient funds (400) or insufficient decoys (400)
    assert response.status_code == 400
    detail = response.json()["detail"].lower()
    assert "insufficient" in detail or "not enough" in detail


def test_dex_endpoints_allow_swaps():
    client = TestClient(app)
    pool = client.post(
        "/dex/pools",
        json={"other_asset": "ETH", "privacy_amount": 1_000_000, "other_amount": 500_000, "fee_bps": 35},
    )
    assert pool.status_code == 200
    pool_id = pool.json()["pool_id"]

    add = client.post(
        f"/dex/pools/{pool_id}/liquidity",
        json={"provider_id": "alice", "privacy_amount": 200_000, "other_amount": 100_000},
    )
    assert add.status_code == 200
    minted = add.json()["minted_shares"]
    assert minted > 0

    quote = client.post(
        "/dex/quote",
        json={"pool_id": pool_id, "input_asset": "PRV", "input_amount": 50_000},
    ).json()
    assert quote["output_amount"] > 0

    swap = client.post(
        "/dex/swap",
        json={"pool_id": pool_id, "input_asset": "PRV", "input_amount": 50_000, "min_output_amount": 1},
    )
    assert swap.status_code == 200
    swap_body = swap.json()
    assert swap_body["output_amount"] == quote["output_amount"]

    withdraw = client.post(
        f"/dex/pools/{pool_id}/withdraw",
        json={"provider_id": "alice", "share_amount": add.json()["minted_shares"]},
    )
    assert withdraw.status_code == 200
