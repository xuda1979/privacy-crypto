import pytest

from src import crypto_utils, ring_signature
from src.wallet import Wallet


def test_ring_signature_sign_and_verify():
    wallets = [Wallet.generate(include_mnemonic=True)[0] for _ in range(3)]
    ring = [wallet.spend_public_key for wallet in wallets]
    message = b"ring signature message"
    signature = ring_signature.sign(message, ring, wallets[1].spend_private_key, 1)
    assert ring_signature.verify(message, ring, signature)


def test_ring_signature_rejects_tampering():
    wallets = [Wallet.generate(include_mnemonic=True)[0] for _ in range(3)]
    ring = [wallet.spend_public_key for wallet in wallets]
    message = b"tamper"
    signature = ring_signature.sign(message, ring, wallets[0].spend_private_key, 0)
    signature["s"][1] = (signature["s"][1] + 1) % crypto_utils.CURVE_ORDER
    assert not ring_signature.verify(message, ring, signature)


def test_ring_signature_requires_multiple_members():
    wallet, _ = Wallet.generate(include_mnemonic=True)
    with pytest.raises(ValueError):
        ring_signature.sign(b"msg", [wallet.spend_public_key], wallet.spend_private_key, 0)


@pytest.mark.parametrize("index", [-1, 5])
def test_ring_signature_validates_signer_index(index):
    wallets = [Wallet.generate(include_mnemonic=True)[0] for _ in range(3)]
    ring = [wallet.spend_public_key for wallet in wallets]
    with pytest.raises(ValueError):
        ring_signature.sign(b"msg", ring, wallets[0].spend_private_key, index)
