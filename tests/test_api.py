import pytest
from fastapi.testclient import TestClient

from src.api import app, reset_state
from src.wallet import verify_audit_bundle


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()
    yield
    reset_state()


def test_wallet_creation_and_transaction_flow():
    client = TestClient(app)
    sender = client.post("/wallets").json()
    recipient = client.post("/wallets").json()
    _ = client.post("/wallets")  # provide additional decoy

    payload = {
        "sender_wallet_id": sender["wallet_id"],
        "recipient_wallet_id": recipient["wallet_id"],
        "amount": 9,
        "ring_size": 3,
        "memo": "integration test",
    }
    response = client.post("/transactions", json=payload)
    assert response.status_code == 200
    tx_data = response.json()
    assert "tx_id" in tx_data
    assert "audit_bundle" in tx_data
    assert verify_audit_bundle(tx_data["audit_bundle"])
    pending = client.get("/pending").json()
    assert len(pending["pending"]) == 1

    mine_response = client.post("/mine")
    assert mine_response.status_code == 200
    chain = client.get("/chain").json()
    assert chain["length"] >= 2
    assert chain["valid"] is True
    assert all("hash" in block for block in chain["chain"])

    listing = client.get("/wallets").json()
    wallet_entry = next(item for item in listing if item["wallet_id"] == sender["wallet_id"])
    assert "address" in wallet_entry
    assert "view_private_key" not in wallet_entry


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
    assert response.status_code == 400
    assert "ring" in response.json()["detail"].lower()


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
