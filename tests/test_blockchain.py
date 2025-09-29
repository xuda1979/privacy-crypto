import pytest

from src.blockchain import Blockchain, compute_hash
from src.main import create_transaction
from src.wallet import Wallet


def test_genesis_block_pow():
    blockchain = Blockchain()
    genesis = blockchain.chain[0]
    assert genesis.hash.startswith("0" * blockchain.difficulty)
    assert compute_hash(genesis) == genesis.hash


def test_transaction_creation_and_validation():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()
    ring = [sender, decoy]
    tx = create_transaction(sender, recipient, amount=10, ring_members=ring)
    tx_dict = tx.to_dict()

    blockchain = Blockchain()
    assert blockchain.validate_transaction(tx_dict)
    assert str(10).encode() not in tx_dict["encrypted_amount"].encode()
    blockchain.add_transaction(tx_dict)
    mined_block = blockchain.mine_block()
    assert tx_dict in mined_block.transactions


def test_double_spend_detection():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()
    ring = [sender, decoy]

    tx = create_transaction(sender, recipient, amount=5, ring_members=ring)
    tx_dict = tx.to_dict()

    blockchain = Blockchain()
    blockchain.add_transaction(tx_dict)
    blockchain.mine_block()

    with pytest.raises(ValueError):
        blockchain.add_transaction(tx_dict)


def test_tampered_transaction_rejected():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()
    ring = [sender, decoy]

    tx = create_transaction(sender, recipient, amount=7, ring_members=ring)
    tx_dict = tx.to_dict()
    tx_dict["ring_public_keys"][0] = tx_dict["ring_public_keys"][0][::-1]

    blockchain = Blockchain()
    assert not blockchain.validate_transaction(tx_dict)
    with pytest.raises(ValueError):
        blockchain.add_transaction(tx_dict)


def test_chain_validation_catches_tampering():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()
    ring = [sender, decoy]

    tx = create_transaction(sender, recipient, amount=3, ring_members=ring)
    blockchain = Blockchain()
    blockchain.add_transaction(tx.to_dict())
    blockchain.mine_block()

    blockchain.chain[1].transactions[0]["memo"] = "tampered"
    assert not blockchain.is_chain_valid()

