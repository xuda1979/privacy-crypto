import unittest
from src import crypto_utils, ring_signature

class TestVectorRing(unittest.TestCase):
    def test_vector_signature(self):
        # 1. Setup Keys
        priv1, pub1 = crypto_utils.generate_keypair()
        priv2, pub2 = crypto_utils.generate_keypair()

        # Vector Keys (Simulating [SpendKey, CommitmentDiff])
        priv1_b, pub1_b = crypto_utils.generate_keypair()
        priv2_b, pub2_b = crypto_utils.generate_keypair()

        # Ring: Member 0 (Me), Member 1 (Other)
        ring_member_0 = [pub1, pub1_b]
        ring_member_1 = [pub2, pub2_b]
        public_ring = [ring_member_0, ring_member_1]

        private_keys = [priv1, priv1_b]
        signer_index = 0

        message = b"Test Message"

        # 2. Sign
        sig = ring_signature.sign(message, public_ring, private_keys, signer_index)

        # 3. Verify
        self.assertTrue(ring_signature.verify(message, public_ring, sig))

        # 4. Verify with wrong message
        self.assertFalse(ring_signature.verify(b"Wrong", public_ring, sig))

        # 5. Verify standard signature compatibility
        standard_ring = [pub1, pub2]
        standard_sig = ring_signature.sign(message, standard_ring, priv1, 0)
        self.assertTrue(ring_signature.verify(message, standard_ring, standard_sig))

if __name__ == '__main__':
    unittest.main()
