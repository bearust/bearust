#!/usr/bin/env bash
set -euo pipefail
docker compose up -d --build
trap 'docker compose down --remove-orphans' EXIT
container_id="$(docker compose ps -q bearust)"
for _ in $(seq 1 30); do
  if test "$(docker inspect --format '{{.State.Health.Status}}' "$container_id")" = "healthy"; then exit 0; fi
  sleep 1
done
docker compose logs bearust
exit 1
