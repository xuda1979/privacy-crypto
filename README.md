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

### Running the HTTP API

An HTTP API backed by [FastAPI](https://fastapi.tiangolo.com/) exposes the
blockchain, wallet management helpers and transaction submission endpoints. To
start the service locally run:

```bash
./scripts/deploy.sh
```

By default the server listens on `0.0.0.0:8000`. Override the `HOST` and `PORT`
environment variables if you need to bind to a different interface or port
number. The generated OpenAPI schema and interactive Swagger UI are available
at `http://<host>:<port>/docs` once the server is running.

The API supports the following workflow:

1. `POST /wallets` to create a new wallet. The response includes a `wallet_id`
   used to reference the wallet in future calls alongside the exported public
   address.
2. `GET /wallets` to enumerate known wallets without exposing private keys.
3. `POST /transactions` to create a ring-signature protected transaction from
   one wallet to another. The `ring_size` parameter determines how many decoy
   wallets participate in the ring.
4. `POST /mine` to mine pending transactions into a new block.
5. `GET /chain` and `GET /pending` to inspect chain state and queued
   transactions.
