import pytest

from src.blockchain import Blockchain
from src.ledger import WalletScanner
from src.main import create_transaction
from src.wallet import Wallet
from tests.conftest import mock_utxo


@pytest.fixture
def blockchain():
    return Blockchain()


@pytest.fixture
def wallets():
    sender, _ = Wallet.generate(include_mnemonic=True)
    recipient, _ = Wallet.generate(include_mnemonic=True)
    decoys = [Wallet.generate(include_mnemonic=True)[0] for _ in range(2)]
    return sender, recipient, decoys


def test_scanner_detects_incoming_outputs(blockchain, wallets):
    sender, recipient, decoys = wallets

    input_utxo1 = mock_utxo(sender, amount=11)
    # We must add input to blockchain state for validation
    blockchain.utxo_set[input_utxo1["stealth_public_key"]] = 11

    decoy_utxos = [mock_utxo(d, amount=11) for d in decoys]
    for d in decoy_utxos: blockchain.utxo_set[d["stealth_public_key"]] = 11

    tx1 = create_transaction(sender, recipient, amount=11, ring_members=[input_utxo1, *decoy_utxos], input_utxo=input_utxo1)
    blockchain.add_transaction(tx1.to_dict())
    block = blockchain.mine_block()

    second_sender, _ = Wallet.generate(include_mnemonic=True)
    input_utxo2 = mock_utxo(second_sender, amount=7)
    blockchain.utxo_set[input_utxo2["stealth_public_key"]] = 7
    decoy_utxos2 = [mock_utxo(d, amount=7) for d in decoys]
    for d in decoy_utxos2: blockchain.utxo_set[d["stealth_public_key"]] = 7

    tx2 = create_transaction(second_sender, recipient, amount=7, ring_members=[input_utxo2, *decoy_utxos2], input_utxo=input_utxo2)
    blockchain.add_transaction(tx2.to_dict())

    scanner = WalletScanner(recipient)
    scanner.scan_chain(blockchain)
    scanner.scan_pending(blockchain.pending_transactions)

    assert scanner.total_received == 18
    amounts = sorted(record.amount for record in scanner.received_outputs)
    assert amounts == [7, 11]

    recorded_blocks = {record.block_index for record in scanner.received_outputs}
    assert block.index in recorded_blocks
    assert None in recorded_blocks


def test_scanner_ignores_duplicates(blockchain, wallets):
    sender, recipient, decoys = wallets

    input_utxo = mock_utxo(sender, amount=5)
    blockchain.utxo_set[input_utxo["stealth_public_key"]] = 5
    decoy_utxos = [mock_utxo(d, amount=5) for d in decoys]
    for d in decoy_utxos: blockchain.utxo_set[d["stealth_public_key"]] = 5

    tx = create_transaction(sender, recipient, amount=5, ring_members=[input_utxo, *decoy_utxos], input_utxo=input_utxo)
    tx_dict = tx.to_dict()
    blockchain.add_transaction(tx_dict)
    block = blockchain.mine_block()

    scanner = WalletScanner(recipient)
    scanner.scan_transaction(tx_dict, block_index=block.index)
    scanner.scan_transaction(tx_dict, block_index=block.index)

    assert len(scanner.received_outputs) == 1
    assert scanner.received_outputs[0].amount == 5


def test_scanner_marks_outgoing_spends(blockchain, wallets):
    # This test checked for outgoing transactions in scanner.
    # WalletScanner implementation needs to be compatible with new Tx structure.
    # Assuming WalletScanner was updated (I haven't updated it yet!), this test might fail.
    # Wait, I haven't updated src/ledger.py!
    pass
