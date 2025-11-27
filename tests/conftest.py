from src.wallet import Wallet
from src.main import create_transaction, create_coinbase_transaction
from src.blockchain import COINBASE_KEY_IMAGE
import base64
from src import crypto_utils

def mock_utxo(wallet: Wallet, amount: int = 10):
    """Helper to create a valid UTXO for testing."""
    # We need a valid ephemeral key and stealth address that corresponds to the wallet
    ephemeral_scalar, ephemeral_public, stealth_public = crypto_utils.derive_stealth_address(
        wallet.view_public_key, wallet.spend_public_key
    )

    return {
        "stealth_public_key": base64.b64encode(crypto_utils.point_to_bytes(stealth_public)).decode("ascii"),
        "amount": amount,
        "ephemeral_public_key": base64.b64encode(crypto_utils.point_to_bytes(ephemeral_public)).decode("ascii"),
        # For testing input validation, we might need key_image_if_spent but create_transaction doesn't require it in input_utxo arg
    }
