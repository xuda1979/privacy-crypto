import pytest

from src.wallet import Wallet


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
