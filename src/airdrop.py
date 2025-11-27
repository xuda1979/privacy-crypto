"""A utility for airdropping tokens to a list of recipients."""

import argparse
import json
from typing import List

from .blockchain import Blockchain
from .main import create_transaction
from .wallet import Wallet


def main():
    parser = argparse.ArgumentParser(description="Airdrop tokens to a list of recipients.")
    parser.add_argument("sender_wallet_file", help="Path to the sender's wallet file.")
    parser.add_argument("password", help="Password for the sender's wallet.")
    parser.add_argument("recipients_file", help="Path to a JSON file containing a list of recipient addresses.")
    parser.add_argument("amount", type=int, help="Amount of tokens to send to each recipient.")
    parser.add_argument("--memo", help="Memo to include with the transaction.")

    args = parser.parse_args()

    try:
        sender_wallet = Wallet.load_from_file(args.sender_wallet_file, args.password)
    except ValueError as e:
        print(f"Error loading wallet: {e}")
        return

    with open(args.recipients_file, "r") as f:
        recipient_addresses: List[str] = json.load(f)

    blockchain = Blockchain()

    print(f"Airdropping {args.amount} tokens to {len(recipient_addresses)} recipients...")

    for i, address in enumerate(recipient_addresses):
        try:
            view_public_key, spend_public_key = Wallet.import_address(address)

            # We need a dummy wallet object for the recipient to create a transaction
            class DummyRecipientWallet:
                def __init__(self, view_pk, spend_pk):
                    self.view_public_key = view_pk
                    self.spend_public_key = spend_pk

            recipient_wallet = DummyRecipientWallet(view_public_key, spend_public_key)

            # Generate decoy wallets to create a valid ring for the transaction.
            # Using unique members is required to pass validation.
            decoy1, _ = Wallet.generate()
            decoy2, _ = Wallet.generate()
            ring_members = [sender_wallet, decoy1, decoy2]

            tx = create_transaction(
                sender=sender_wallet,
                recipient=recipient_wallet,
                amount=args.amount,
                ring_members=ring_members,
                memo=args.memo,
            )
            blockchain.add_transaction(tx.to_dict())
            print(f"({i+1}/{len(recipient_addresses)}) Created transaction for {address}")
        except Exception as e:
            print(f"Error creating transaction for {address}: {e}")

    print("Airdrop transactions created and added to the pending pool.")
    print("Mine a block to confirm the transactions.")


if __name__ == "__main__":
    main()
