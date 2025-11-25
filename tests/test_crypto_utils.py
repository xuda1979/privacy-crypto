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


def test_schnorr_signature_roundtrip():
    private_key, public_key = crypto_utils.generate_keypair()
    message = b"audit-bundle-test"
    signature = crypto_utils.schnorr_sign(message, private_key)
    assert crypto_utils.schnorr_verify(message, public_key, signature)


def test_prove_and_verify_range_valid():
    """Test that a valid range proof is accepted."""
    value = 12345
    bit_commitments, proofs, total_blinding = crypto_utils.prove_range(value)
    commitment = crypto_utils.pedersen_commit(value, total_blinding)
    assert crypto_utils.verify_range(commitment, bit_commitments, proofs)


def test_verify_range_invalid_commitment():
    """Test that an invalid range proof with a bad commitment is rejected."""
    value = 12345
    bit_commitments, proofs, total_blinding = crypto_utils.prove_range(value)
    bad_commitment = crypto_utils.pedersen_commit(value + 1, total_blinding)
    assert not crypto_utils.verify_range(bad_commitment, bit_commitments, proofs)


def test_verify_range_invalid_proof():
    """Test that an invalid range proof with a bad proof is rejected."""
    value = 12345
    bit_commitments, proofs, total_blinding = crypto_utils.prove_range(value)
    commitment = crypto_utils.pedersen_commit(value, total_blinding)

    # Invalidate one of the proofs
    c0, s0, c1, s1 = proofs[0]
    bad_proofs = [(c0, s0 + 1, c1, s1)] + proofs[1:]

    assert not crypto_utils.verify_range(commitment, bit_commitments, bad_proofs)


def test_prove_range_negative_value():
    """Test that proving a negative value raises an error."""
    import pytest
    with pytest.raises(ValueError):
        crypto_utils.prove_range(-1)


def test_prove_range_out_of_range():
    """Test that proving a value outside the bit range raises an error."""
    import pytest
    with pytest.raises(ValueError):
        crypto_utils.prove_range(2**64)


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
