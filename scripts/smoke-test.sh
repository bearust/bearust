#!/usr/bin/env bash
set -euo pipefail

# Compose smoke coverage for both Phase 1 plaintext compatibility and Phase 2
# native TLS. The script deliberately uses temporary config/certificate files
# so it never modifies checked-in configuration or secrets.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
project="bearust-smoke-${RANDOM}"
compose=(docker compose -p "$project" -f "$root_dir/docker-compose.yml")
cleanup() {
  "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/data" "$tmp_dir/tls"
chmod 0777 "$tmp_dir/data"

cat >"$tmp_dir/base.toml" <<'TOML'
[server]
bind = "0.0.0.0:8080"
graceful_shutdown_seconds = 1

[health]
interval_seconds = 1
timeout_seconds = 1
healthy_threshold = 1
unhealthy_threshold = 1

[[upstream_pools]]
name = "api"
algorithm = "round_robin"

[[upstream_pools.backends]]
address = "127.0.0.1:9"
health_check = "tcp"
health_path = ""

[[routes]]
name = "api"
host = "api.example.com"
path_prefix = "/"
upstream_pool = "api"
TOML

wait_healthy() {
  local container_id
  container_id="$("${compose[@]}" ps -q bearust)"
  for _ in $(seq 1 45); do
    if test "$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)" = healthy; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" logs bearust
  return 1
}

fetch_cert_fingerprint() {
  openssl s_client -connect 127.0.0.1:8080 -servername localhost </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 \
    | sed 's/^sha256 Fingerprint=//; s/://g'
}

echo "[smoke] building production image"
"${compose[@]}" build bearust

echo "[smoke] plaintext compatibility"
cp "$tmp_dir/base.toml" "$tmp_dir/plain.toml"
BEARUST_CONFIG="$tmp_dir/plain.toml" BEARUST_DATA="$tmp_dir/data" BEARUST_TLS="$tmp_dir/tls" \
  "${compose[@]}" up -d bearust
wait_healthy
plain_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  -H 'Host: api.example.com' http://127.0.0.1:8080/)"
test "$plain_status" = 503
"${compose[@]}" down --remove-orphans

echo "[smoke] generating an ephemeral self-signed certificate"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -keyout "$tmp_dir/tls/key.pem" -out "$tmp_dir/tls/cert.pem" \
  >/dev/null 2>&1
chmod 0600 "$tmp_dir/tls/key.pem"
cat "$tmp_dir/base.toml" >"$tmp_dir/tls.toml"
cat >>"$tmp_dir/tls.toml" <<TOML

[server.tls]
cert_path = "/etc/bearust/tls/cert.pem"
key_path = "/etc/bearust/tls/key.pem"
TOML

echo "[smoke] invalid certificate is rejected at startup"
cp "$tmp_dir/tls.toml" "$tmp_dir/invalid.toml"
sed -i 's#cert.pem#missing.pem#' "$tmp_dir/invalid.toml"
if BEARUST_CONFIG="$tmp_dir/invalid.toml" BEARUST_DATA="$tmp_dir/data" BEARUST_TLS="$tmp_dir/tls" \
    "${compose[@]}" run --rm --no-deps bearust >/dev/null 2>&1; then
  echo "invalid TLS material unexpectedly started" >&2
  exit 1
fi

echo "[smoke] HTTPS listener and certificate reload"
BEARUST_CONFIG="$tmp_dir/tls.toml" BEARUST_DATA="$tmp_dir/data" BEARUST_TLS="$tmp_dir/tls" \
  "${compose[@]}" up -d bearust
wait_healthy
tls_status="$(curl --silent --show-error --insecure --output /dev/null --write-out '%{http_code}' \
  -H 'Host: api.example.com' https://127.0.0.1:8080/)"
test "$tls_status" = 503
before="$(fetch_cert_fingerprint)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost-reloaded' -keyout "$tmp_dir/tls/key-new.pem" -out "$tmp_dir/tls/cert-new.pem" \
  >/dev/null 2>&1
chmod 0600 "$tmp_dir/tls/key-new.pem"
mv "$tmp_dir/tls/cert-new.pem" "$tmp_dir/tls/cert.pem"
mv "$tmp_dir/tls/key-new.pem" "$tmp_dir/tls/key.pem"
docker compose -p "$project" -f "$root_dir/docker-compose.yml" kill -s HUP bearust
after=""
for _ in $(seq 1 30); do
  after="$(fetch_cert_fingerprint || true)"
  test -n "$after" && test "$after" != "$before" && break
  sleep 1
done
test -n "$after" && test "$after" != "$before"

echo "[smoke] production image identity and secret-leak check"
image="${project}-bearust"
test "$(docker run --rm --entrypoint id "$image")" = 'uid=10001(bearust) gid=10001(bearust) groups=10001(bearust)'
logs="$("${compose[@]}" logs bearust 2>&1)"
if grep -Eqi 'PRIVATE KEY|BEGIN .*KEY|localhost-reloaded' <<<"$logs"; then
  echo "TLS secret material appeared in logs" >&2
  exit 1
fi

echo "Phase 2 TLS smoke checks passed"
