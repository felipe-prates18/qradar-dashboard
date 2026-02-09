#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PORT="$(python3 - <<'PY'
import json
from pathlib import Path

cfg = Path('app/config.json')
try:
    data = json.loads(cfg.read_text())
    print(data.get('server', {}).get('port', 9050))
except Exception:
    print(9050)
PY
)"
PORT="${PORT:-${DEFAULT_PORT}}"
HOST="${HOST:-0.0.0.0}"
VENV_DIR="${VENV_DIR:-${APP_DIR}/.venv}"
LOG_DIR="${LOG_DIR:-${APP_DIR}/logs}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/deploy.log}"
PID_FILE="${PID_FILE:-${APP_DIR}/.uvicorn.pid}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-90}"

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

mkdir -p "$LOG_DIR"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(cat "$PID_FILE")"
  if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
    echo "Application is already running (PID $existing_pid)."
    echo "URL: http://${HOST}:${PORT}"
    echo "Logs: $LOG_FILE"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

echo "Starting QRadar Monitoring App on ${HOST}:${PORT}..."
nohup uvicorn app.main:app \
  --host "$HOST" \
  --port "$PORT" \
  --log-config "$APP_DIR/logging.ini" \
  >>"$LOG_FILE" 2>&1 &

pid="$!"
echo "$pid" > "$PID_FILE"

deploy_failed=0
for ((elapsed=0; elapsed<STARTUP_TIMEOUT; elapsed++)); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    deploy_failed=1
    break
  fi

  if grep -q "Application startup complete" "$LOG_FILE"; then
    break
  fi

  sleep 1
done

if [[ "$deploy_failed" -eq 1 ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
  echo "Deploy failed: uvicorn process terminated unexpectedly." >&2
  echo "Last log lines:" >&2
  tail -n 30 "$LOG_FILE" >&2 || true
  rm -f "$PID_FILE"
  exit 1
fi

if ! grep -q "Application startup complete" "$LOG_FILE"; then
  echo "Deploy timed out after ${STARTUP_TIMEOUT}s waiting for startup confirmation." >&2
  echo "Process is still running (PID $pid). Check logs: $LOG_FILE" >&2
  exit 1
fi

echo "Deploy concluído com sucesso."
echo "PID: $pid"
echo "URL: http://${HOST}:${PORT}"
echo "Logs: $LOG_FILE"
