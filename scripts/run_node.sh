#!/usr/bin/env bash
# Quick-start helper to run a privacy-crypto node locally.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Error: could not find Python interpreter '$PYTHON_BIN' in PATH." >&2
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating virtual environment in $VENV_DIR" >&2
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip >/dev/null
if [[ -f "$ROOT_DIR/requirements.txt" ]]; then
  python -m pip install -r "$ROOT_DIR/requirements.txt"
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

cd "$ROOT_DIR"

echo "Starting privacy-crypto node on $HOST:$PORT" >&2
exec uvicorn src.api:app --host "$HOST" --port "$PORT"
