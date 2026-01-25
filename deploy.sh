#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8000}"
COMPOSE_FILE="${COMPOSE_FILE:-${APP_DIR}/docker-compose.yml}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required but was not found in PATH." >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker-compose)
else
  echo "Docker Compose is required but was not found." >&2
  exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "Compose file not found: $COMPOSE_FILE" >&2
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

echo "Building and starting containers with Docker Compose..."
PORT="$PORT" "${DOCKER_COMPOSE[@]}" -f "$COMPOSE_FILE" up -d --build

echo "Deployment complete. The service should now be running on port ${PORT}."
