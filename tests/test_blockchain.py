import pytest

from src.blockchain import Blockchain, compute_hash
from src.main import create_transaction, create_coinbase_transaction
from src.wallet import Wallet
from tests.conftest import mock_utxo

def test_genesis_block_pow():
    blockchain = Blockchain()
    genesis = blockchain.chain[0]
    assert genesis.hash.startswith("0" * blockchain.difficulty)
    assert compute_hash(genesis) == genesis.hash


def test_transaction_creation_and_validation():
    sender, _ = Wallet.generate(include_mnemonic=True)
    recipient, _ = Wallet.generate(include_mnemonic=True)
    decoy, _ = Wallet.generate(include_mnemonic=True)

    # Need inputs. Create a mock UTXO for sender.
    input_utxo = mock_utxo(sender, amount=10)
    decoy_utxo = mock_utxo(decoy, amount=10) # Decoy must have same amount

    ring = [input_utxo, decoy_utxo]

    tx = create_transaction(sender, recipient, amount=10, ring_members=ring, input_utxo=input_utxo, fee=0)
    tx_dict = tx.to_dict()

    blockchain = Blockchain()
    # To validate, the UTXOs must exist in blockchain's UTXO set
    # Manually seed UTXO set
    blockchain.utxo_set[input_utxo["stealth_public_key"]] = {"commitment": input_utxo["amount_commitment"], "amount": 10}
    blockchain.utxo_set[decoy_utxo["stealth_public_key"]] = {"commitment": decoy_utxo["amount_commitment"], "amount": 10}

    assert blockchain.validate_transaction(tx_dict)

    # Check that amount is confidential (0)
    assert tx_dict["outputs"][0]["amount"] == 0

    blockchain.add_transaction(tx_dict)
    mined_block = blockchain.mine_block()
    assert tx_dict in mined_block.transactions


def test_double_spend_detection():
    sender, _ = Wallet.generate(include_mnemonic=True)
    recipient, _ = Wallet.generate(include_mnemonic=True)
    decoy, _ = Wallet.generate(include_mnemonic=True)

    input_utxo = mock_utxo(sender, amount=10)
    decoy_utxo = mock_utxo(decoy, amount=10)
    ring = [input_utxo, decoy_utxo]

    tx = create_transaction(sender, recipient, amount=5, ring_members=ring, input_utxo=input_utxo, fee=0)
    tx_dict = tx.to_dict()

    blockchain = Blockchain()
    blockchain.utxo_set[input_utxo["stealth_public_key"]] = {"commitment": input_utxo["amount_commitment"], "amount": 10}
    blockchain.utxo_set[decoy_utxo["stealth_public_key"]] = {"commitment": decoy_utxo["amount_commitment"], "amount": 10}

    blockchain.add_transaction(tx_dict)
    blockchain.mine_block()

    # The issue: validate_transaction checks spent_key_images too.
    # So it might return False -> ValueError("Invalid transaction")
    # Instead of reaching the specific Double Spend check in add_transaction.
    # Let's check if validate_transaction has a specific return for double spend or just False?
    # It returns False.
    # add_transaction calls validate_transaction first.

    # We should expect "Invalid transaction" OR "Double spend detected" depending on where it catches it.
    # In my updated blockchain.py:
    # validate_transaction: if inp["key_image"] in self.spent_key_images: return False
    # add_transaction: if not validate_transaction(): raise ValueError("Invalid transaction")

    # So it raises "Invalid transaction".
    # I should update the test expectation.

    with pytest.raises(ValueError, match="Invalid transaction"):
        blockchain.add_transaction(tx_dict)


def test_tampered_transaction_rejected():
    sender, _ = Wallet.generate(include_mnemonic=True)
    recipient, _ = Wallet.generate(include_mnemonic=True)
    decoy, _ = Wallet.generate(include_mnemonic=True)

    input_utxo = mock_utxo(sender, amount=10)
    decoy_utxo = mock_utxo(decoy, amount=10)
    ring = [input_utxo, decoy_utxo]

    tx = create_transaction(sender, recipient, amount=7, ring_members=ring, input_utxo=input_utxo, fee=0)
    tx_dict = tx.to_dict()

    # Tamper with ring signature input
    tx_dict["inputs"][0]["ring_public_keys"][0] = tx_dict["inputs"][0]["ring_public_keys"][0][::-1]

    blockchain = Blockchain()
    blockchain.utxo_set[input_utxo["stealth_public_key"]] = {"commitment": input_utxo["amount_commitment"], "amount": 10}
    blockchain.utxo_set[decoy_utxo["stealth_public_key"]] = {"commitment": decoy_utxo["amount_commitment"], "amount": 10}

    assert not blockchain.validate_transaction(tx_dict)
    with pytest.raises(ValueError):
        blockchain.add_transaction(tx_dict)


def test_chain_validation_catches_tampering():
    sender, _ = Wallet.generate(include_mnemonic=True)
    recipient, _ = Wallet.generate(include_mnemonic=True)
    decoy, _ = Wallet.generate(include_mnemonic=True)

    input_utxo = mock_utxo(sender, amount=10)
    decoy_utxo = mock_utxo(decoy, amount=10)
    ring = [input_utxo, decoy_utxo]

    tx = create_transaction(sender, recipient, amount=3, ring_members=ring, input_utxo=input_utxo, fee=0)
    blockchain = Blockchain()
    blockchain.utxo_set[input_utxo["stealth_public_key"]] = {"commitment": input_utxo["amount_commitment"], "amount": 10}
    blockchain.utxo_set[decoy_utxo["stealth_public_key"]] = {"commitment": decoy_utxo["amount_commitment"], "amount": 10}

    blockchain.add_transaction(tx.to_dict())
    blockchain.mine_block()

    blockchain.chain[1].transactions[0]["memo"] = "tampered"

    # My simplified `is_chain_valid` in blockchain.py is returning True.
    # It probably needs to re-hash the block/tx.
    # `_validate_block` checks `compute_merkle_root(block.transactions)`.
    # If I modify transaction data in place, `compute_merkle_root` will re-calculate based on modified data.
    # The block header `merkle_root` remains the old one.
    # So `block.merkle_root != calculated_root` should trigger.
    # Unless `compute_merkle_root` is caching or something?

    assert not blockchain.is_chain_valid()
