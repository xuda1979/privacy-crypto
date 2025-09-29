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
