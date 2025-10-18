#!/usr/bin/env bash
set -euo pipefail

# Build and launch a small local multi-node network using Docker Compose.
# Requires Docker Engine + docker compose plugin.

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-privacycrypto}"
export TAG="${TAG:-latest}"

echo "[devnet] building containers..."
docker compose build

echo "[devnet] starting 1 API + 3 P2P nodes..."
docker compose up -d --scale p2p=3

echo "[devnet] logs (follow) -> Ctrl+C to stop"
docker compose logs -f --tail=50

# To tear down:
#   docker compose down -v
