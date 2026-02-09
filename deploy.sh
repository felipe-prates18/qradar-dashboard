#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-9030}"
HOST="${HOST:-0.0.0.0}"
VENV_DIR="${VENV_DIR:-${APP_DIR}/.venv}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but was not found in PATH." >&2
  exit 1
fi

if [[ ! -f "$APP_DIR/users.db" ]]; then
  if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "users.db not found and sqlite3 is unavailable to create one." >&2
    exit 1
  fi
  echo "users.db not found; creating an empty database at $APP_DIR/users.db"
  sqlite3 "$APP_DIR/users.db" "VACUUM;"
fi

if [[ ! -f "$APP_DIR/app/config.json" ]]; then
  echo "config.json not found at $APP_DIR/app/config.json" >&2
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating virtual environment at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

pip install --upgrade pip >/dev/null
pip install -r "$APP_DIR/requirements.txt"

echo "Starting QRadar Monitoring App on ${HOST}:${PORT}..."
exec uvicorn app.main:app \
  --host "$HOST" \
  --port "$PORT" \
  --log-config "$APP_DIR/logging.ini"
