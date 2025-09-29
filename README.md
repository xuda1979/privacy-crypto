# privacy-crypto
Prototype code and documentation for a privacy-focused cryptocurrency project.

## Features

- Proof-of-work blockchain with deterministic hashing and validation of block
  ancestry.
- Privacy-preserving transactions featuring stealth addresses, Pedersen
  commitments, encrypted amounts and ring signatures with key image based
  double-spend protection.
- Wallet utilities that maintain separate view/spend keys and support
  generation of one-time addresses.

## Development

### Requirements

Install the Python dependencies in your environment:

```bash
pip install -r requirements.txt
```

The project currently relies on [`ecdsa`](https://pypi.org/project/ecdsa/) and
[`PyNaCl`](https://pypi.org/project/PyNaCl/) for the underlying cryptographic
operations.

### Tests

Run the unit test suite with:

```bash
pytest
```

The genesis block is mined with a low difficulty to keep tests fast.
