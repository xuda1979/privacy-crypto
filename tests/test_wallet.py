import base64

import copy

import pytest

from src import crypto_utils
from src.main import create_transaction
from src.wallet import Wallet, verify_audit_bundle


def test_wallet_address_roundtrip():
    wallet = Wallet.generate()
    address = wallet.export_address()
    view_key, spend_key = Wallet.import_address(address)
    assert view_key == wallet.view_public_key
    assert spend_key == wallet.spend_public_key


def test_key_image_consistency():
    wallet = Wallet.generate()
    assert wallet.key_image() == wallet.key_image()
    other = Wallet.generate()
    assert wallet.key_image() != other.key_image()


def test_shared_secret_symmetry():
    alice = Wallet.generate()
    bob = Wallet.generate()
    secret_ab = alice.create_shared_secret(bob.view_public_key)
    secret_ba = bob.create_shared_secret(alice.view_public_key)
    assert secret_ab == secret_ba


def test_public_keys_tuple_matches_properties():
    wallet = Wallet.generate()
    view, spend = wallet.public_keys()
    assert view == wallet.view_public_key
    assert spend == wallet.spend_public_key


@pytest.mark.parametrize("invalid", ["", "Zm9v", "a" * 8])
def test_import_address_rejects_invalid_payloads(invalid):
    with pytest.raises(ValueError):
        Wallet.import_address(invalid)


def test_recipient_can_detect_and_decrypt_transaction():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()

    tx = create_transaction(sender, recipient, amount=42, ring_members=[sender, decoy])
    tx_dict = tx.to_dict()

    assert recipient.belongs_to_transaction(tx_dict)
    assert not decoy.belongs_to_transaction(tx_dict)

    amount = recipient.decrypt_transaction_amount(tx_dict)
    assert amount == 42

    one_time_private = recipient.derive_one_time_private_key(tx_dict)
    stealth_bytes = base64.b64decode(tx_dict["stealth_address"].encode("ascii"))
    stealth_point = crypto_utils.bytes_to_point(stealth_bytes)
    assert crypto_utils.scalar_mult(one_time_private) == stealth_point


def test_decrypt_fails_for_non_recipient():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    outsider = Wallet.generate()

    tx = create_transaction(sender, recipient, amount=7, ring_members=[sender, outsider])
    tx_dict = tx.to_dict()

    with pytest.raises(ValueError):
        outsider.decrypt_transaction_amount(tx_dict)

    with pytest.raises(ValueError):
        outsider.derive_one_time_private_key(tx_dict)


def test_audit_bundle_verification_roundtrip():
    sender = Wallet.generate()
    recipient = Wallet.generate()
    decoy = Wallet.generate()

    tx = create_transaction(sender, recipient, amount=55, ring_members=[sender, decoy])
    bundle = tx.audit_bundle
    assert bundle is not None
    assert verify_audit_bundle(bundle)

    tampered = copy.deepcopy(bundle)
    tampered["payload"]["amount"] = 99
    assert not verify_audit_bundle(tampered)
