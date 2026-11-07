# Deployment and operations

The production image runs as UID/GID 10001, drops all capabilities, enables
`no-new-privileges`, and uses a read-only root filesystem. The TOML config is
mounted read-only; `/data` and `/etc/bearust/tls` are persistent named Docker
volumes initialized with the correct ownership for UID 10001. `/tmp` and
`/run/bearust` are tmpfs. Ports follow the Nginx Proxy Manager layout:

| Host port | Container port | Purpose |
| --- | --- | --- |
| `${BEARUST_HTTP_PORT:-80}` | 8080 | HTTP (redirects TLS hosts to HTTPS; serves ACME HTTP-01) |
| `${BEARUST_HTTPS_PORT:-443}` | 8443 | HTTPS with per-host certificates (SNI) |
| `127.0.0.1:${BEARUST_CONTROL_PORT:-81}` | 8081 | Dashboard and control API |

The process inside the container still runs unprivileged on 8080/8443/8081;
Docker publishes the privileged host ports. The dashboard is loopback-only
by default — reach it with an SSH tunnel (`ssh -L 81:127.0.0.1:81 server`) or
set `BEARUST_CONTROL_HOST=0.0.0.0` only behind a firewall or VPN.

The default production deployment is intentionally one command:

```bash
docker compose up -d --build
```

It uses the local image tag `bearust:local`. Bearust does not use Docker
Hub; official images are published to the GitHub Container Registry at
`ghcr.io/bearust/bearust` by the `Publish` workflow on every push to `main`
(`:latest` plus `:sha-<commit>`) and on every `v*` tag (`:vX.Y.Z` and
`:X.Y`). No manual build or push step is needed for releases.

To deploy from a prebuilt image instead of building locally, set
`BEARUST_IMAGE` and pull before starting:

```bash
echo 'BEARUST_IMAGE=ghcr.io/bearust/bearust:latest' >> .env
docker compose pull
docker compose up -d
```

While the package is private, each host must authenticate once with a token
that has the `read:packages` scope:

```bash
echo "$CR_PAT" | docker login ghcr.io -u <github-username> --password-stdin
```

Pin production deployments to an immutable tag (`:vX.Y.Z` or
`:sha-<commit>`) rather than `:latest`, and roll back by changing
`BEARUST_IMAGE` to the previous tag and re-running `docker compose up -d`.

For a custom certificate, copy the PEM chain and private key into the
`bearust-tls` volume and reference them from `[server.tls]`. Keep private keys
mode `0600`; never put key contents or ACME tokens in configuration, logs, or
issue reports. The certificate store persists active metadata below `/data`
and activates new material atomically, preserving the previous active
certificate when validation or issuance fails.

Let's Encrypt HTTP-01 requires public port 80 and every requested hostname resolving to the proxy. DNS-01 is required for wildcard names or deployments without port 80; the Cloudflare API token should be scoped to the target zone with only `Zone:DNS:Edit` and `Zone:Zone:Read`. Renewal runs asynchronously outside request handling once a certificate enters its renewal window, with bounded retries and last-known-good fallback. See [docs/acme.md](docs/acme.md) for the staging-first rollout and recovery procedure.

ACME credentials are accepted only by the authenticated certificate API and are stored in `/data/secrets` with mode `0700` (individual files `0600`). They are never returned by API responses or written to JSON logs. Keep `/data` private and back it up using filesystem permissions that preserve these modes.

The command is `bearust serve --config /etc/bearust/bearust.toml --json-logs`. The PID file defaults to `./bearust.pid` relative to `/run/bearust`; send `SIGHUP` (`docker compose kill -s HUP bearust`) after atomically replacing the mounted config. Shutdown is graceful: listeners stop accepting new work and in-flight requests drain.

## Managed nodes (API tokens and desired state)

A managing control plane such as Bearust Cloud drives a node through two
endpoints instead of a browser session:

- **API tokens.** An administrator with `system.settings.manage` creates one
  from a signed-in session (`POST /api/api-tokens` with
  `{"name": "bearust-cloud", "scope": "write"}`); the `brt_…` secret is
  returned once and only its hash is stored. Send it as
  `Authorization: Bearer brt_…`. A token acts as the administrator who created
  it, narrowed by scope: `read` allows only safe methods, `write` also allows
  configuration changes. No token can reach `/api/api-tokens`, `/api/users`,
  `/api/roles`, `/api/setup`, `/api/auth`, `/api/sso`, or change plugins.
  Revoke with `DELETE /api/api-tokens/{id}`; creation, revocation, and
  denials are audited.
- **Desired state.** `PUT /api/desired-state` takes
  `{"generation": n, "pools": [...], "routes": [...]}` (the same pool and
  route shapes as `/api/load-balancer`). The whole document is validated and
  applied in one runtime swap; an invalid document changes nothing. It
  replaces every pool and route except the `proxy-host-*` ones materialized
  from dashboard proxy hosts, and those names are refused in the document.
  `generation` must be greater than the last applied one (`GET
  /api/desired-state`), otherwise the node answers `409 stale_generation`, so
  a delayed or replayed push cannot roll the node back. Retrying the same
  document with a new generation is safe.
- **Managed certificates and challenges.** The same document may carry
  `"certificates": [{"name", "cert_pem", "key_pem"}]` and
  `"acme_challenges": [{"host", "token", "key_authorization"}]`. Certificates
  are stored as `managed-<name>` and served by SNI; each push replaces the
  whole managed set and leaves certificates uploaded in the dashboard alone.
  Challenges are answered at `/.well-known/acme-challenge/<token>` for their
  host, so a managing plane can complete HTTP-01 for a hostname served by
  several nodes. Challenges live in memory for 10 minutes.

Keep the control API off the public internet. For a managed node, bind it to
a private interface only (`BEARUST_CONTROL_HOST=<wireguard-or-vpc-ip>`) and
allow the managing plane's address in the firewall; never use `0.0.0.0` on a
public interface. The Bearust Cloud edge node below uses a related pattern:
the control API stays on host loopback, Caddy exposes it on 8443 with a
private CA, and UFW limits 8443 to the control-plane address.

## Edge nodes (Bearust Cloud)

A Bearust Cloud edge node is a separate VM that serves tenant traffic on
public 80/443 and exposes its Bearust admin API to the control plane on 8443.
The admin API is never published directly: Caddy terminates TLS on 8443 with a
per-node private CA and proxies to the loopback-only control port. UFW allows
8443 only from the control plane address, so the token and TLS protect an
endpoint that is not reachable from the internet.

`deploy/edge/cloud-init.yaml` provisions one node on Ubuntu 22.04/24.04 or
Debian 12. It installs Docker CE, pulls the pinned `ghcr.io/bearust/bearust`
tag, creates the `bearust-data` and `bearust-tls` volumes, configures UFW, and
starts Caddy. The rendered file is provider user-data; it contains the GHCR
token if one is supplied, so never commit it or paste it into an issue.

### Ports and exposure

| Host port | Exposure | Purpose |
| --- | --- | --- |
| 80/tcp | public | Bearust HTTP data plane |
| 443/tcp | public | Bearust HTTPS data plane |
| 8443/tcp | control-plane IP/CIDR only | Caddy TLS for the admin API |
| 8081/tcp | `127.0.0.1` only | Bearust control API behind Caddy |
| 22/tcp | `BEARUST_EDGE_SSH_ALLOWED_CIDR` | SSH |

The provider security group must mirror these rules; UFW is the second layer.
Docker publishes 80/443 itself, so those two stay public even though UFW
filters host processes on 8443. Do not add a public mapping for 8081.

### Variables

The template uses `${BEARUST_EDGE_*}` placeholders and is rendered with
`envsubst`:

| Variable | Required | Example | Meaning |
| --- | --- | --- | --- |
| `BEARUST_EDGE_CONTROL_PLANE_IP` | yes | `203.0.113.10` or `203.0.113.0/24` | Control-plane egress IP/CIDR allowed to reach 8443 |
| `BEARUST_EDGE_HOSTNAME` | yes | `sin-1-free-admin.bearust.cloud` | DNS name for the admin API; create a DNS-only A record to the node's public IP |
| `BEARUST_EDGE_IMAGE_TAG` | yes | `v0.1.0` or `sha-<commit>` | Immutable `ghcr.io/bearust/bearust` tag; avoid `latest` in production |
| `BEARUST_EDGE_GHCR_USERNAME` | no | `octocat` | GitHub user for a private GHCR package |
| `BEARUST_EDGE_GHCR_TOKEN` | no | `ghp_…` | PAT with `read:packages`; required only while the package is private |
| `BEARUST_EDGE_SSH_ALLOWED_CIDR` | yes | `203.0.113.0/24` | SSH allowlist; provisioning fails without it (set `0.0.0.0/0` only on purpose) |

The admin hostname must resolve from the control plane. Use a DNS-only record
(no Cloudflare proxy): the certificate is a private CA and the control plane
connects to port 8443 directly. A Cloudflare-proxied record would terminate TLS
at Cloudflare and break the CA pinning.

### Render and provision

```sh
export BEARUST_EDGE_CONTROL_PLANE_IP=203.0.113.10
export BEARUST_EDGE_HOSTNAME=sin-1-free-admin.bearust.cloud
export BEARUST_EDGE_IMAGE_TAG=v0.1.0
export BEARUST_EDGE_SSH_ALLOWED_CIDR=203.0.113.0/24
# Optional while the GHCR package is private:
# export BEARUST_EDGE_GHCR_USERNAME=octocat
# export BEARUST_EDGE_GHCR_TOKEN=ghp_…

envsubst '${BEARUST_EDGE_CONTROL_PLANE_IP} ${BEARUST_EDGE_HOSTNAME} ${BEARUST_EDGE_IMAGE_TAG} ${BEARUST_EDGE_GHCR_USERNAME} ${BEARUST_EDGE_GHCR_TOKEN} ${BEARUST_EDGE_SSH_ALLOWED_CIDR}' \
  < deploy/edge/cloud-init.yaml > /tmp/bearust-edge-user-data.yaml

# No placeholder may remain:
grep -n '\${BEARUST_EDGE_' /tmp/bearust-edge-user-data.yaml && exit 1 || true
```

`envsubst` comes from gettext; on macOS install it with `brew install gettext`
if it is not already on `PATH`.

Pass `/tmp/bearust-edge-user-data.yaml` as the instance user-data to an
Ubuntu 22.04/24.04 or Debian 12 VM. Use at least 2 vCPU and 2 GB RAM for a
node running the proxy and Caddy. Open 80/443 to the internet, 8443 only to
`BEARUST_EDGE_CONTROL_PLANE_IP`, and 22 only to the SSH allowlist in the
provider firewall as well. The node commands below assume root (or `sudo -i`).

### First-boot checks

```sh
cloud-init status --wait --long
tail -n 200 /var/log/cloud-init-output.log
cd /opt/bearust-edge
docker compose ps
docker compose logs --tail=50 caddy bearust
ufw status verbose
ss -lntp | grep -E ':(80|443|8443|8081)\b'
```

Expect `bearust` to be healthy, `caddy` running, and the CA at
`/etc/bearust-edge/admin-ca.crt` (SHA-256 digest in
`/etc/bearust-edge/admin-ca.crt.sha256`). If Caddy has not written the CA yet,
check `docker compose logs caddy` and rerun
`/usr/local/sbin/bearust-edge-bootstrap`.

The data plane answers before any tenant is registered (an unknown `Host` is a
`404`, not a connection failure):

```sh
curl -sS -o /dev/null -w 'http=%{http_code}\n' http://127.0.0.1/
curl -k -sS -o /dev/null -w 'https=%{http_code}\n' https://127.0.0.1/
```

### Trust the node CA on the control plane

The admin certificate is signed by a CA generated on the node and stored in
the Caddy volume. Caddy renews the short-lived leaf certificate automatically;
the root CA stays stable until that volume is deleted. The Bearust Cloud
backend must trust the root, or sync fails with
`x509: certificate signed by unknown authority`. Copy the CA and build a
bundle that keeps the public roots:

```sh
# On the node:
sha256sum /etc/bearust-edge/admin-ca.crt

# On the control-plane host:
scp root@<node>:/etc/bearust-edge/admin-ca.crt ./<node>-admin-ca.crt
sha256sum ./<node>-admin-ca.crt
```

Compare the digest with the node output (on macOS use `shasum -a 256`), then
build a bundle from the backend image's system roots (the image is distroless,
so `docker cp` avoids needing a shell in the container):

```sh
stack=<stack-name>   # e.g. bearust-cloud
image=$(docker service inspect "${stack}_backend" \
  --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')
cid=$(docker create "$image")
docker cp "$cid:/etc/ssl/certs/ca-certificates.crt" /tmp/bearust-system-ca.crt
docker rm "$cid" >/dev/null
# If the image has no ca-certificates.crt, use the control-plane host's bundle
# from /etc/ssl/certs/ca-certificates.crt as the base instead.
cat /tmp/bearust-system-ca.crt ./<node>-admin-ca.crt > /tmp/bearust-edge-ca-bundle.crt

docker config create bearust_edge_ca_bundle /tmp/bearust-edge-ca-bundle.crt
docker service update --detach=false \
  --config-add source=bearust_edge_ca_bundle,target=/run/secrets/bearust_edge_ca_bundle \
  --env-add SSL_CERT_FILE=/run/secrets/bearust_edge_ca_bundle \
  "${stack}_backend"
```

If a second node later adds its own CA, rebuild the bundle with both CA files
and create a new config (configs are immutable), then update the service to the
new name. Persist the config and `SSL_CERT_FILE` in the SaaS `docker-stack.yml`
before the next `docker stack deploy`, otherwise the deploy removes them.
The private CA is a closed-beta trade-off: because the control plane trusts
both node CAs, a compromised node could impersonate the other node's admin
endpoint. A publicly trusted certificate per admin hostname (for example a
DNS-01 certificate for the `bearust.cloud` zone) or a shared PKI with per-node
certificates removes that coupling and the CA bundle; revisit it before the
beta grows beyond the two planned nodes.

```yaml
configs:
  bearust_edge_ca_bundle:
    external: true

services:
  backend:
    environment:
      SSL_CERT_FILE: /run/secrets/bearust_edge_ca_bundle
    configs:
      - source: bearust_edge_ca_bundle
        target: /run/secrets/bearust_edge_ca_bundle
```

Verify from the control-plane host before registering:

```sh
curl --cacert ./<node>-admin-ca.crt https://<hostname>:8443/api/health
# {"status":"ok"}
```

If the backend breaks after the bundle update, roll the service change back
with `docker service update --env-rm SSL_CERT_FILE --config-rm
bearust_edge_ca_bundle "${stack}_backend"` and inspect
`docker service logs "${stack}_backend"`.

If the admin hostname does not resolve yet, add the A record and wait for DNS,
or use `curl --resolve <hostname>:8443:<node-ip>` for the manual check only.
The backend does not support `--resolve`; sync needs real DNS.

### Create the admin user and API token

Run this on the node. It uses the one-time setup token, creates the admin
account, and stores the session cookie. The commands resolve the admin name to
`127.0.0.1` so they traverse loopback and are not blocked by the
control-plane-only UFW rule; the certificate still matches the hostname. Use a
password manager for the password; do not pass it on the command line.

```sh
cd /opt/bearust-edge
sudo bash -c '
set -euo pipefail
cd /opt/bearust-edge
umask 077
set -a; . /etc/bearust-edge/edge.env; set +a
NODE_IP=127.0.0.1
read -rsp "Admin password (12+ chars): " ADMIN_PASSWORD; echo
SETUP_TOKEN=$(docker compose exec -T bearust cat /data/setup-token)
PAYLOAD=$(jq -n --arg email admin@example.com --arg password "$ADMIN_PASSWORD" \
  --arg token "$SETUP_TOKEN" \
  "{email:\$email,password:\$password,setup_token:\$token}")
curl --fail --show-error --cacert /etc/bearust-edge/admin-ca.crt \
  --resolve "$EDGE_HOSTNAME:8443:$NODE_IP" \
  -c /root/bearust-edge.cookies \
  -H "Content-Type: application/json" -d "$PAYLOAD" \
  "https://$EDGE_HOSTNAME:8443/api/setup/initialize"
docker compose exec -T bearust rm -f /data/setup-token
'
```

Create the write-scope token the control plane will use. Setup leaves a readable
CSRF cookie, so echo it in `X-CSRF-Token`:

```sh
cd /opt/bearust-edge
sudo bash -c '
set -euo pipefail
cd /opt/bearust-edge
umask 077
set -a; . /etc/bearust-edge/edge.env; set +a
NODE_IP=127.0.0.1
CSRF=$(awk "\$6 == \"bearust_csrf\" {print \$7}" /root/bearust-edge.cookies)
[ -n "$CSRF" ] || { echo "no CSRF cookie; run the setup step first" >&2; exit 1; }
curl --fail --show-error --cacert /etc/bearust-edge/admin-ca.crt \
  --resolve "$EDGE_HOSTNAME:8443:$NODE_IP" \
  -b /root/bearust-edge.cookies -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"bearust-cloud\",\"scope\":\"write\"}" \
  "https://$EDGE_HOSTNAME:8443/api/api-tokens" \
  | tee /root/bearust-cloud-token.json
'
sudo jq -r .secret /root/bearust-cloud-token.json
```

The `brt_…` secret is shown once. Copy it into the Bearust Cloud dashboard now;
keep `/root/bearust-cloud-token.json` until the verification below passes, then
delete it. If it is lost, revoke the token from the dashboard and create a new
one.

### Register the node

In the Bearust Cloud dashboard, edit the edge node and set:

- **Region/tier:** `sin-1` and `free` or `paid`.
- **Address:** the node's public IPv4 address.
- **Health URL:** `https://<hostname>:8443/api/health`.
- **Control URL:** `https://<hostname>:8443`.
- **API token:** the `brt_…` write token.

Save and click **Resync now** if the first reconcile has not run. The sync
status should move from `pending` to `synced`; `applied_generation` should
match the dashboard's desired generation and `last_synced_at` should update.

Verify the token directly on the node (read-only calls; the token is a write
token, so it can also apply desired state, but do not push by hand):

```sh
cd /opt/bearust-edge
sudo bash -c '
set -euo pipefail
cd /opt/bearust-edge
set -a; . /etc/bearust-edge/edge.env; set +a
BRT=$(jq -r .secret /root/bearust-cloud-token.json)
NODE_IP=127.0.0.1
curl --fail --show-error --cacert /etc/bearust-edge/admin-ca.crt \
  --resolve "$EDGE_HOSTNAME:8443:$NODE_IP" \
  -H "Authorization: Bearer $BRT" \
  "https://$EDGE_HOSTNAME:8443/api/desired-state"
curl --fail --show-error --cacert /etc/bearust-edge/admin-ca.crt \
  --resolve "$EDGE_HOSTNAME:8443:$NODE_IP" \
  -H "Authorization: Bearer $BRT" \
  "https://$EDGE_HOSTNAME:8443/api/usage"
'
```

`/api/usage` returns the per-host counters and a `boot_id`. After a tenant
route receives traffic, the counters increase and the Bearust Cloud usage poll
(once per minute) records them for the organization. The dashboard's usage
view and the node's `last_synced_at` are the end-to-end confirmation.

After the checks pass, remove the local copies of the token and session:

```sh
sudo rm -f /root/bearust-cloud-token.json /root/bearust-edge.cookies
```

### Update one node at a time

Pin a new immutable tag and roll the free node first, then the paid node. Keep
the other node serving traffic and do not update both at once.

```sh
cd /opt/bearust-edge
old=$(sed -n 's/^IMAGE_TAG=//p' .env)
echo "current tag: $old"
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=v0.2.0/' .env
# Keep the rendered source in sync if cloud-init is rerun later:
sed -i 's/^IMAGE_TAG=.*/IMAGE_TAG=v0.2.0/' /etc/bearust-edge/edge.env

docker compose pull bearust
docker compose up -d --no-deps bearust
docker compose ps
docker compose exec -T bearust bearust --version
```

The container receives SIGTERM and drains in-flight requests for up to 30
seconds (`stop_grace_period` is 35s). Caddy and the data volumes stay up. After
the node is healthy, confirm `/api/health`, check that the dashboard shows
`synced` and a fresh `last_synced_at`, then repeat on the other node.

Roll back by setting `IMAGE_TAG` to the previous value and repeating the pull
and `up -d --no-deps bearust` steps. The previous image tag must still exist in
GHCR; do not delete release tags.

Caddy is pinned separately. Bump the `caddy:` image in
`/opt/bearust-edge/docker-compose.yml` (and in the cloud-init template) only
after validating the Caddyfile (`docker compose run --rm --no-deps caddy caddy
validate --config /etc/caddy/Caddyfile --adapter caddyfile`); a warning that
the file is not `caddy fmt`-formatted is harmless. Then roll it with `docker
compose pull caddy && docker compose up -d --no-deps caddy`. That only
restarts the admin endpoint.

### Security and recovery notes

- The private CA is bound to the node's Caddy volume. Rebuilding the VM without
  that volume creates a new CA; copy the new `admin-ca.crt` to the control
  plane, rebuild the bundle, and remove the decommissioned node's CA so an old
  disk cannot impersonate the replacement.
- `/data` holds the SQLite database, certificates, managed certificate keys,
  and ACME secrets. Back it up before destructive maintenance and never copy it
  to a public location. Never run `docker compose down -v`: it deletes the
  `bearust-data` and `bearust-tls` volumes. If the volume is lost, the node
  reports generation 0 and the control plane re-pushes its routes and managed
  certificates; any dashboard-managed certificates and ACME credentials must
  be reissued.
- Rotate the GHCR token after provisioning if it was embedded in user-data,
  and remove `/var/lib/cloud/instance/user-data.txt` or rebuild from a
  token-free template when decommissioning the VM.
- The admin API is reachable only from the control-plane address. To use the
  dashboard from an operator workstation, use an SSH tunnel to the node's
  loopback (`ssh -L 8081:127.0.0.1:8081 root@<node>`) and open
  `http://127.0.0.1:8081`, or add the workstation to a temporary UFW allow rule
  and remove it afterwards. Do not open 8443 to the world.
- To decommission a node, disable or delete it in Bearust Cloud, revoke its
  `brt_` token, remove its CA from the control-plane bundle, and then destroy
  the VM.

### Verify the firewall from outside

From a host that is **not** the control plane:

```sh
curl --max-time 5 -sS https://<hostname>:8443/api/health
# curl: (28) Connection timed out (or connection refused)
nc -vz <hostname> 8443
# timed out / refused
```

From the control plane:

```sh
curl --cacert ./<node>-admin-ca.crt https://<hostname>:8443/api/health
# {"status":"ok"}
```

On the node, confirm the listeners and rules:

```sh
ss -lntp | grep -E ':(80|443|8443|8081)\b'
# 80, 443, 8443 on 0.0.0.0/[::]; 8081 on 127.0.0.1
ufw status verbose
# 8443/tcp ALLOW 203.0.113.10; 80/443 ALLOW Anywhere; 22 from the SSH CIDR
```

## Optional AI Advisor

The advisor remains disabled unless both `LLM_API_URL` and `LLM_API_KEY` are
set. Use an OpenAI-compatible `/v1/chat/completions` endpoint; optional bounded
settings include `LLM_MODEL`, `LLM_REQUEST_TIMEOUT_SECONDS`,
`LLM_RESPONSE_LIMIT_BYTES`, `LLM_QUEUE_CAPACITY`, `LLM_WORKER_COUNT`, and
`LLM_CIRCUIT_FAILURE_THRESHOLD`. Empty values use safe defaults. Prompts contain
redacted aggregate snapshots only; raw URLs, headers, bodies, IPs, credentials,
tokens, and provider responses are not retained. Unset both required variables
and restart to disable safely. Self-hosted HTTPS endpoints are supported. Never
commit API keys or include them in support bundles.

## Database profiles

The default `docker compose up -d` keeps the control plane on SQLite at
`/data/bearust.sqlite`, persisted by the `bearust-data` named volume.
PostgreSQL and MySQL are opt-in profiles with health checks and named volumes:

Uncomment and set the matching `DATABASE_URL` and `POSTGRES_*` or `MYSQL_*`
credentials in `.env` (use a long random password in production), then run
exactly one profile:

```sh
docker compose --profile postgres up -d
# or, for MySQL:
docker compose --profile mysql up -d
```

For a non-default env file, use `--env-file`, for example
`docker compose --env-file .env.production --profile postgres up -d`.
Enabling both profiles makes Bearust wait for both health checks while
`DATABASE_URL` selects the backend it uses. Migrations run automatically at startup;
the database volume is retained across restarts and image upgrades. Switching
between SQLite, PostgreSQL, and MySQL is not an in-place operation: perform an
explicit, tested export/import outside this phase and keep the original volume
as a rollback copy. Never paste `DATABASE_URL` values containing passwords into
logs, issue reports, or support bundles; redact credentials before sharing
Compose output or diagnostic archives.

## Optional WASM plugins (Phase 13A)

Production deployments keep plugins disabled unless a reviewed local module is
required. The default is `[plugins].enabled = false` with `directory =
"./plugins"`; when enabled, mount a dedicated read-only plugin directory below
the container and set an explicit absolute path in the TOML configuration:

```toml
[plugins]
enabled = true
directory = "/etc/bearust/plugins"
max_plugins = 64
max_module_bytes = 16777216
max_memory_pages = 256
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

The directory layout is one child per plugin (`plugin.toml` and one `.wasm`
module). Manifests use ABI version `1`, declare one of the supported hook
capabilities (`health_check`, `waf.detect`, `notify.waf_block`,
`transform.request`, `transform.response`, `balance.select` — see
[docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md)), and declare bounded
memory pages, fuel, timeout, and output limits. The runtime provides no WASI,
filesystem, network, environment, clock, random, database, or proxy request
access. It canonicalizes module paths beneath the configured root and rejects
traversal and symlink escapes.

After startup, administrators can use the authenticated control-plane API:
`GET /api/plugins` and `POST /api/plugins/reload` for status/reload,
`POST /api/plugins/{id}/enable` or `/disable`, `DELETE /api/plugins/{id}`, and
`POST /api/plugins/{id}/health-check`. `plugins.read` permits listing and health
checks; `plugins.manage` permits lifecycle changes. The API exposes only
bounded metadata (including SHA-256 digest and safe error code), never paths,
manifest text, module bytes, runtime errors, request data, or secrets.

Invalid configuration, compilation errors, traps, timeouts, fuel exhaustion,
and memory limits disable/isolate the affected plugin. The proxy remains
available and startup continues. Deploy only reviewed modules: fetch them with
`bearust plugin search`/`bearust plugin install` from a registry index you
trust (see the registry section in [docs/manual.md](docs/manual.md)), verify the checksum and signature the
CLI reports, and confirm the trust-on-first-use pin below before reloading.

### Plugin manifest signing and trust-on-first-use (Phase 14)

Set `plugins.require_signature = true` to require every plugin directory to
carry a valid `plugin.sig` (rejecting anything unsigned); leave it `false`
(the default) to allow unsigned modules alongside signed ones:

```toml
[plugins]
enabled = true
directory = "/etc/bearust/plugins"
require_signature = true
max_plugins = 64
max_module_bytes = 16777216
max_memory_pages = 256
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

Sign a reviewed plugin before shipping it to the plugin directory:

```console
$ bearust plugin keygen --out ./keys        # writes ./keys/signing.key (0600), prints the public key
$ bearust plugin sign ./plugins/health-ok --key ./keys/signing.key
```

`plugin sign` writes `plugin.sig` alongside `plugin.toml` and the `.wasm`
module. Keep `signing.key` off the deployed host entirely — sign in CI or on
a workstation and ship only `plugin.toml`, the module, and `plugin.sig`.

The first time Bearust loads a signed plugin ID, it pins that plugin's
public key into `<directory>/trusted-keys.json`. Every subsequent load must
match the pinned key; a mismatch fails closed with `key_mismatch` in the
plugin's `last_error_code` and in `plugin_startup_failed`/reload audit logs.
Because the trust store is written at runtime, **the plugin directory cannot
be fully read-only** if signing is in use — mount it read-write and owned
only by the account running Bearust, or pre-seed `trusted-keys.json`
read-only with the expected pins and mount only that file read-only if you
want to lock pinning down entirely.

If you rotate a plugin's signing key on purpose, the next reload after the
rotation logs `key_mismatch` — this is expected, not a compromise signal by
itself. Recover by removing (or updating) that plugin's entry in
`trusted-keys.json` on the host, then reload; the next load re-pins whatever
key is now present. There is no API for this — it is a deliberate manual
step so a rotation always leaves an operator-visible trace.

Threat-model note: `trusted-keys.json` lives next to the plugin bundles it
protects, so signing plus pinning defends against a tampered *distribution
channel* (a corrupted artifact, a compromised mirror) — it does not defend
against an attacker who already has write access to the plugins directory,
since they could edit the pin file too. Directory ownership/permissions are
still the primary control.

JSON logs include event, level, timestamp, request identifiers, route/upstream context, and error category. Unhealthy TCP/HTTP backends are removed from selection; no healthy backend returns `503`, while a route/host miss returns `404`. For `404`, verify `Host`, path prefix, and pool. For `503`, inspect health addresses/paths and reachability from the container. Roll back by restoring the prior image tag and config, then restart or issue `SIGHUP`.
