import pytest

from src.blockchain import Blockchain
from src.ledger import WalletScanner
from src.main import create_transaction
from src.wallet import Wallet


@pytest.fixture
def blockchain():
    return Blockchain()


@pytest.fixture
def wallets():
    sender, _ = Wallet.generate()
    recipient, _ = Wallet.generate()
    decoys = [Wallet.generate()[0] for _ in range(2)]
    return sender, recipient, decoys


def test_scanner_detects_incoming_outputs(blockchain, wallets):
    sender, recipient, decoys = wallets

    tx1 = create_transaction(sender, recipient, amount=11, ring_members=[sender, *decoys])
    blockchain.add_transaction(tx1.to_dict())
    block = blockchain.mine_block()

    second_sender, _ = Wallet.generate()
    tx2 = create_transaction(second_sender, recipient, amount=7, ring_members=[second_sender, *decoys])
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

    tx = create_transaction(sender, recipient, amount=5, ring_members=[sender, *decoys])
    tx_dict = tx.to_dict()
    blockchain.add_transaction(tx_dict)
    block = blockchain.mine_block()

    scanner = WalletScanner(recipient)
    scanner.scan_transaction(tx_dict, block_index=block.index)
    scanner.scan_transaction(tx_dict, block_index=block.index)

    assert len(scanner.received_outputs) == 1
    assert scanner.received_outputs[0].amount == 5


def test_scanner_marks_outgoing_spends(blockchain, wallets):
    sender, recipient, decoys = wallets

    tx = create_transaction(sender, recipient, amount=9, ring_members=[sender, *decoys])
    blockchain.add_transaction(tx.to_dict())
    blockchain.mine_block()

    scanner = WalletScanner(sender)
    scanner.scan_chain(blockchain)

    assert len(scanner.outgoing_transactions) == 1
    record = scanner.outgoing_transactions[0]
    assert record.tx_id == tx.compute_tx_id()
    assert record.ring_size == len(tx.ring_public_keys)
