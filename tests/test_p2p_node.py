import pytest
from fastapi.testclient import TestClient

from src.p2p.node import app, reset_state


@pytest.fixture(autouse=True)
def clean_state():
    reset_state()
    yield
    reset_state()


def test_submit_transaction_updates_mempool():
    tx = {
        "version": 1,
        "inputs": [],
        "outputs": [{"address": "addr1", "amount": 5}],
        "fee": 2,
    }
    with TestClient(app) as client:
        response = client.post("/p2p/submit", json={"tx": tx})
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["tx_id"]

        status = client.get("/p2p/peers")
        assert status.status_code == 200
        payload = status.json()
        assert payload["mempool_size"] == 1
        assert payload["seen_tx"] == 1


def test_submit_requires_tx_object():
    with TestClient(app) as client:
        response = client.post("/p2p/submit", json={"foo": "bar"})
        assert response.status_code == 400
        assert "tx must be an object" in response.json()["error"]
