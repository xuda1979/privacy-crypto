import pytest

from src import crypto_utils


def test_point_roundtrip_serialisation():
    _, point = crypto_utils.generate_keypair()
    encoded = crypto_utils.point_to_bytes(point)
    decoded = crypto_utils.bytes_to_point(encoded)
    assert decoded == point


def test_hash_to_point_is_deterministic():
    label = b"privacy-demo"
    point1 = crypto_utils.hash_to_point(label)
    point2 = crypto_utils.hash_to_point(label)
    assert point1 == point2


def test_pedersen_commitment_proof_verifies():
    amount = 42
    blinding = crypto_utils.random_scalar()
    commitment = crypto_utils.pedersen_commit(amount, blinding)
    proof_point, s1, s2 = crypto_utils.prove_commitment(amount, blinding)
    assert crypto_utils.verify_commitment(commitment, proof_point, s1, s2)
    tampered = (s1 + 1) % crypto_utils.CURVE_ORDER
    assert not crypto_utils.verify_commitment(commitment, proof_point, tampered, s2)


def test_schnorr_signature_roundtrip():
    private_key, public_key = crypto_utils.generate_keypair()
    message = b"audit-bundle-test"
    signature = crypto_utils.schnorr_sign(message, private_key)
    assert crypto_utils.schnorr_verify(message, public_key, signature)
    altered = (signature[0], (signature[1] + 1) % crypto_utils.CURVE_ORDER)
    assert not crypto_utils.schnorr_verify(message, public_key, altered)


def test_schnorr_sign_is_deterministic():
    private_key, public_key = crypto_utils.generate_keypair()
    message = b"deterministic-schnorr"
    signature1 = crypto_utils.schnorr_sign(message, private_key)
    signature2 = crypto_utils.schnorr_sign(message, private_key)
    assert signature1 == signature2
    assert crypto_utils.schnorr_verify(message, public_key, signature1)


def test_schnorr_sign_validates_inputs():
    private_key, _ = crypto_utils.generate_keypair()
    with pytest.raises(TypeError):
        crypto_utils.schnorr_sign("not-bytes", private_key)
    with pytest.raises(ValueError):
        crypto_utils.schnorr_sign(b"msg", 0)


def test_schnorr_verify_rejects_invalid_inputs():
    private_key, public_key = crypto_utils.generate_keypair()
    message = b"invalid-checks"
    signature = crypto_utils.schnorr_sign(message, private_key)
    assert not crypto_utils.schnorr_verify("bad", public_key, signature)
    out_of_range = (signature[0], crypto_utils.CURVE_ORDER)
    assert not crypto_utils.schnorr_verify(message, public_key, out_of_range)
