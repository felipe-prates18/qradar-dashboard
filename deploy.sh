#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

SERVICE="qradar-dashboard"
IMAGE_TAG="${IMAGE_TAG:-qradar-dashboard:latest}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-90}"
HOST_UVICORN_PID_FILE="${APP_DIR}/.uvicorn.pid"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required but was not found in PATH." >&2
    exit 1
  fi
}

require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "'docker compose' plugin is required but was not found." >&2
  exit 1
fi

# Deploys antigos rodavam o uvicorn direto no host via nohup, deixando o PID
# aqui. Se ainda estiver vivo, encerra para não competir com a porta do host.
if [[ -f "$HOST_UVICORN_PID_FILE" ]]; then
  existing_pid="$(cat "$HOST_UVICORN_PID_FILE" 2>/dev/null || true)"
  if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
    echo "Parando processo uvicorn herdado rodando direto no host (PID $existing_pid)..."
    kill "$existing_pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 10); do
      kill -0 "$existing_pid" >/dev/null 2>&1 || break
      sleep 1
    done
    kill -9 "$existing_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$HOST_UVICORN_PID_FILE"
fi

if [[ ! -f "$APP_DIR/app/config.json" ]]; then
  echo "config.json not found at $APP_DIR/app/config.json" >&2
  exit 1
fi

# users.db e alerts_state.json são bind-mounts de arquivo único no
# docker-compose.yml. Se não existirem no host, o Docker cria um diretório
# no lugar e o container quebra ao tentar abri-los como arquivo.
if [[ ! -f "$APP_DIR/users.db" ]]; then
  require_cmd sqlite3
  echo "users.db not found; creating an empty database at $APP_DIR/users.db"
  sqlite3 "$APP_DIR/users.db" "VACUUM;"
fi

if [[ ! -f "$APP_DIR/alerts_state.json" ]]; then
  echo "alerts_state.json not found; creating an empty state file at $APP_DIR/alerts_state.json"
  echo '{}' > "$APP_DIR/alerts_state.json"
fi

echo "Construindo imagem ${IMAGE_TAG}..."
docker build -t "$IMAGE_TAG" "$APP_DIR"

echo "Subindo container via docker compose..."
docker compose up -d --force-recreate "$SERVICE"

echo "Aguardando aplicação inicializar..."
deploy_failed=0
for ((elapsed = 0; elapsed < STARTUP_TIMEOUT; elapsed++)); do
  state="$(docker inspect -f '{{.State.Status}}' "$SERVICE" 2>/dev/null || echo "unknown")"
  if [[ "$state" != "running" ]]; then
    deploy_failed=1
    break
  fi

  if docker compose logs --no-color "$SERVICE" 2>&1 | grep -q "Application startup complete"; then
    break
  fi

  sleep 1
done

if [[ "$deploy_failed" -eq 1 ]]; then
  echo "Deploy failed: o container '$SERVICE' terminou inesperadamente." >&2
  echo "Últimas linhas do log:" >&2
  docker compose logs --no-color --tail 30 "$SERVICE" >&2 || true
  exit 1
fi

if ! docker compose logs --no-color "$SERVICE" 2>&1 | grep -q "Application startup complete"; then
  echo "Deploy timed out após ${STARTUP_TIMEOUT}s esperando confirmação de startup." >&2
  echo "O container ainda está rodando (PID gerenciado pelo Docker)." >&2
  echo "Verifique os logs: docker compose logs -f $SERVICE" >&2
  exit 1
fi

url="$(docker compose port "$SERVICE" 9030 2>/dev/null || true)"
echo "Deploy concluído com sucesso."
echo "URL: http://${url:-localhost:9000}"
echo "Logs: docker compose logs -f $SERVICE"
