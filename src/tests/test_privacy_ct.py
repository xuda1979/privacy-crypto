import unittest
import base64
import os
from src import crypto_utils, ring_signature, rangeproof
from src.blockchain import Blockchain, Block, DB_FILE
from src.wallet import Wallet
from src.main import create_transaction, create_coinbase_transaction, Transaction

class TestPrivacyCT(unittest.TestCase):
    def setUp(self):
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()
        self.blockchain = Blockchain(dev_wallet=self.alice)

    def tearDown(self):
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

    def test_spend_received_ct_funds(self):
        # 1. Alice sends to Bob (Genesis -> CT)
        alice_utxos = self.alice.scan_blockchain(self.blockchain)
        utxo = alice_utxos[0]

        # Fake Ring Member
        utxo_amount = utxo['amount']
        fake_key, fake_pub = crypto_utils.generate_keypair()
        fake_stealth = base64.b64encode(crypto_utils.point_to_bytes(fake_pub)).decode('ascii')
        fake_comm = base64.b64encode(crypto_utils.point_to_bytes(crypto_utils.pedersen_commit(utxo_amount, 0))).decode("ascii")
        self.blockchain.utxo_set[fake_stealth] = fake_comm

        ring_members = [
            utxo,
            {"stealth_public_key": fake_stealth, "amount": utxo_amount, "amount_commitment": fake_comm}
        ]

        tx1 = create_transaction(self.alice, self.bob, 1000, ring_members, utxo, fee=1)
        self.blockchain.add_transaction(tx1.to_dict())
        self.blockchain.mine_block(miner_wallet=self.alice)

        # 2. Bob recovers funds (CT -> CT)
        bob_utxos = self.bob.scan_blockchain(self.blockchain)
        self.assertTrue(len(bob_utxos) > 0)
        bob_utxo = bob_utxos[0]

        self.assertEqual(bob_utxo['amount'], 1000)
        self.assertNotEqual(bob_utxo['blinding_factor'], 0, "Blinding factor should be recovered and non-zero")

        # 3. Bob spends funds back to Alice
        fake_key2, fake_pub2 = crypto_utils.generate_keypair()
        fake_stealth2 = base64.b64encode(crypto_utils.point_to_bytes(fake_pub2)).decode('ascii')

        # Decoy commitment with random blinding
        fake_blinding = crypto_utils.random_scalar()
        fake_comm2 = base64.b64encode(crypto_utils.point_to_bytes(crypto_utils.pedersen_commit(1000, fake_blinding))).decode("ascii")
        self.blockchain.utxo_set[fake_stealth2] = fake_comm2

        ring_members_bob = [
            bob_utxo,
            {"stealth_public_key": fake_stealth2, "amount": 1000, "amount_commitment": fake_comm2}
        ]

        tx2 = create_transaction(self.bob, self.alice, 500, ring_members_bob, bob_utxo, fee=1)

        self.blockchain.add_transaction(tx2.to_dict())
        self.blockchain.mine_block(miner_wallet=self.alice)

        # 4. Verify Alice received 500
        alice_new_utxos = self.alice.scan_blockchain(self.blockchain)

        found_500 = False
        for u in alice_new_utxos:
            if u['amount'] == 500:
                found_500 = True
                break
        self.assertTrue(found_500, "Alice did not receive 500 from Bob")

if __name__ == '__main__':
    unittest.main()
