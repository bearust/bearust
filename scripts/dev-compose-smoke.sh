#!/usr/bin/env bash
set -euo pipefail

# Fresh, isolated verification for the contributor-facing Docker development
# stack. It uses alternate host ports so a locally running service on 8081 does
# not have to be stopped, and removes only its own Compose project/volumes.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="bearust-dev-smoke-${RANDOM}"
export BEARUST_PORT=18080
export BEARUST_CONTROL_PORT=18081
export BEARUST_FRONTEND_PORT=18583
compose=(docker compose -p "$project" -f "$root_dir/docker-compose.dev.yml")

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_healthy() {
  local container_id status
  container_id="$("${compose[@]}" ps -q bearust)"
  for _ in $(seq 1 90); do
    status="$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)"
    if test "$status" = healthy; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" ps
  "${compose[@]}" logs bearust frontend || true
  return 1
}

wait_http_200() {
  local url code
  url="$1"
  for _ in $(seq 1 60); do
    code="$(curl --silent --output /dev/null --write-out '%{http_code}' "$url" || true)"
    if test "$code" = 200; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" ps
  "${compose[@]}" logs frontend || true
  return 1
}

echo "[dev-smoke] starting a fresh Compose project"
"${compose[@]}" up --build -d
wait_healthy

echo "[dev-smoke] backend control API"
test "$(curl --silent --show-error --write-out '%{http_code}' --output /tmp/bearust-dev-smoke-status.json http://127.0.0.1:18081/api/setup/status)" = 200
grep -q '"initialized":false' /tmp/bearust-dev-smoke-status.json

echo "[dev-smoke] frontend and Vite API proxy"
wait_http_200 http://127.0.0.1:18583/
test "$(curl --silent --show-error --write-out '%{http_code}' --output /tmp/bearust-dev-smoke-proxy.json http://127.0.0.1:18583/api/setup/status)" = 200
grep -q '"initialized":false' /tmp/bearust-dev-smoke-proxy.json

rm -f /tmp/bearust-dev-smoke-status.json /tmp/bearust-dev-smoke-proxy.json
echo "Development Compose smoke checks passed"
