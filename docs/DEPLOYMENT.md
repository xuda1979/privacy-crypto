# Deployment Guide

## 1) Local development

```bash
pip install -r requirements.txt
./scripts/run_node.sh        # API on :8000
./scripts/run_p2p.sh         # P2P on :9000
```

Set environment variables as needed:

* `HOST`, `PORT` — API bind (default `0.0.0.0:8000`)
* `P2P_HOST`, `P2P_PORT` — P2P bind (default `0.0.0.0:9000`)
* `PEERS` — comma separated WebSocket URLs to bootstrap peers, e.g.
  `ws://peer1:9000,ws://peer2:9000`
* `MIN_FEE_RATE` — minimal mempool fee rate (integer; default `0`)

## 2) Docker single node

```bash
docker build -t privacy-crypto .
docker run --rm -p 8000:8000 -p 9000:9000 privacy-crypto
```

## 3) Docker Compose multi-node (devnet)

```bash
docker compose up --build --scale p2p=3
```

Visit:
* API docs: `http://localhost:8000/docs`
* P2P status: `http://localhost:9000/p2p/peers`

### Submit a transaction through the P2P relay

```bash
curl -X POST http://localhost:9000/p2p/submit \
  -H 'content-type: application/json' \
  -d '{"tx": { "version":1, "inputs":[...], "outputs":[...], "fee": 1000 }}'
```

### Tear down

```bash
docker compose down -v
```
