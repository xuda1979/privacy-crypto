import json
import os
import time
from dataclasses import asdict

import pytest

from src.blockchain import Blockchain, Block, DB_FILE

def test_migration_legacy_to_new(tmp_path):
    # Setup: Create a legacy blockchain file (list of blocks)
    # We use a temporary directory for DB_FILE to avoid messing with real data

    # We need to monkeypatch DB_FILE in the module or change working directory
    # Changing working directory is safer for file operations if DB_FILE is relative

    original_cwd = os.getcwd()
    os.chdir(tmp_path)

    try:
        # Create a mock legacy chain
        legacy_chain = [
            {
                "index": 0,
                "timestamp": time.time(),
                "transactions": [],
                "previous_hash": "0" * 64,
                "nonce": 0,
                "hash": "mock_hash_0",
                "merkle_root": "mock_root_0"
                # Note: No "version" field
            },
            {
                "index": 1,
                "timestamp": time.time(),
                "transactions": [],
                "previous_hash": "mock_hash_0",
                "nonce": 123,
                "hash": "mock_hash_1",
                "merkle_root": "mock_root_1"
            }
        ]

        with open(DB_FILE, "w") as f:
            json.dump(legacy_chain, f)

        # Initialize Blockchain, which should load the legacy chain
        # We pass dev_wallet=None to avoid creating a genesis block if file exists
        blockchain = Blockchain()

        # Verify loaded chain
        assert len(blockchain.chain) == 2
        assert blockchain.chain[0].hash == "mock_hash_0"
        assert blockchain.chain[1].index == 1

        # Verify version default was applied
        assert blockchain.chain[0].version == 1
        assert blockchain.chain[1].version == 1

        # Save the chain (trigger migration to new format)
        blockchain._save_chain()

        # Read the file and verify it's now a dict with version
        with open(DB_FILE, "r") as f:
            saved_data = json.load(f)

        assert isinstance(saved_data, dict)
        assert saved_data["storage_version"] == 1
        assert "chain" in saved_data
        assert len(saved_data["chain"]) == 2
        assert saved_data["chain"][0]["hash"] == "mock_hash_0"
        assert saved_data["chain"][0]["version"] == 1

    finally:
        os.chdir(original_cwd)

def test_load_new_format(tmp_path):
    original_cwd = os.getcwd()
    os.chdir(tmp_path)

    try:
        # Create a new format chain
        new_format_data = {
            "storage_version": 1,
            "chain": [
                 {
                    "index": 0,
                    "timestamp": time.time(),
                    "transactions": [],
                    "previous_hash": "0" * 64,
                    "nonce": 0,
                    "hash": "mock_hash_0",
                    "merkle_root": "mock_root_0",
                    "version": 1
                }
            ]
        }

        with open(DB_FILE, "w") as f:
            json.dump(new_format_data, f)

        blockchain = Blockchain()

        assert len(blockchain.chain) == 1
        assert blockchain.chain[0].hash == "mock_hash_0"

    finally:
        os.chdir(original_cwd)
