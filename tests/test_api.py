import pytest
from fastapi.testclient import TestClient

from src.api import app, reset_state


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
