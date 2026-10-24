# Development

The supported zero-prerequisite development path is:

```bash
docker compose -f docker-compose.dev.yml up --build
```

This starts the Rust backend with cargo-watch and the API-backed Vite frontend
with hot module reload. Open `http://localhost:5183`; the control API is
available at `http://127.0.0.1:8081`. Frontend dependencies, Rust dependencies,
compiled targets, and development data are cached in Docker volumes, so a new
contributor does not need to install Rust or Node locally or run a preparation
command. The development setup token defaults to `bearust-dev-setup`.

Native development is still supported with Rust 1.97.1, Cargo, clang, cmake,
make, perl, pkg-config, and Node 22.

Tests in `src/` and `tests/` cover routing, balancing, health, reload, logs, HTTP, WebSocket, and shutdown. The repository pins its toolchain in `rust-toolchain.toml`, so plain `cargo` commands use the right compiler. Match CI exactly:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

External database integration tests are opt-in so the normal test suite never
mutates a developer database. Start a PostgreSQL or MySQL instance, then run:

```bash
DATABASE_URL_EXTERNAL=postgres://bearust:bearust@127.0.0.1:5432/bearust cargo test --locked --test external_database
DATABASE_URL_EXTERNAL=mysql://bearust:bearust@127.0.0.1:3306/bearust cargo test --locked --test external_database
```

When `DATABASE_URL_EXTERNAL` is absent, the external test reports an explicit
skip and exits successfully.

The application runs the checked-in SQLx migrations during startup. SQLite
remains the default for local development; switching to PostgreSQL or MySQL
requires setting `DATABASE_URL` and starting the matching Compose profile.
Phase 5 does not automate data export/import between backends, so verify a
backup and restore plan before changing a production database URL.

Focused TDD: add a minimal regression test, run it to observe failure, implement the smallest change, then rerun the focused test and the full suite.

## Single sign-on (OIDC and SAML)

OIDC is always compiled in. SAML is behind the `saml` cargo feature because
it links libxmlsec1; the published Docker image enables it.

```sh
# Debian/Ubuntu
sudo apt-get install libxmlsec1-dev libxml2-dev libxslt1-dev pkg-config
cargo test --features saml --test control_plane_sso_saml

# macOS: libxml2, libxslt, and libxmlsec1 must all come from Homebrew. Mixing
# them with the system libxml2 aborts at runtime inside libxml2.
brew install libxmlsec1 libxslt
export PKG_CONFIG_PATH="$(brew --prefix libxslt)/lib/pkgconfig:$(brew --prefix libxml2)/lib/pkgconfig:$(brew --prefix libxmlsec1)/lib/pkgconfig"
export LIBXML2="$(brew --prefix libxml2)/lib/libxml2.dylib"
cargo test --features saml --test control_plane_sso_saml
```

Providers are managed under **Settings → Single sign-on** or
`PUT /api/sso/providers/{slug}` (requires `system.settings.manage`). The OIDC
callback is `<redirect_base_url>/api/auth/sso/<slug>/callback`; the SAML ACS is
`<redirect_base_url>/api/auth/sso/<slug>/acs` and SP metadata is served at
`/api/auth/sso/<slug>/metadata`. SAML IdP metadata must contain a signing
certificate, and responses must use SHA-256 or stronger signatures and digests.

## OWASP CRS and SecLang

`src/seclang` is a SecLang engine for request phases 1 and 2. The OWASP CRS
4.7.0 request rules are vendored in `crs/` (Apache-2.0) and embedded in the
binary; enable them under **Security → WAF → OWASP Core Rule Set** or
`PUT /api/waf/seclang`. Blocking follows the WAF mode (monitor-only logs).
Custom SecLang rules (up to 60 KB) are compiled before they are saved, so a
bad rule is rejected with its line number. Settings replicate through the
cluster policy state.

Compatibility is measured with the CRS regression suite (go-ftw tests):

```sh
curl -L https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.7.0.tar.gz | tar xz
CRS_DIR=$PWD/coreruleset-4.7.0 cargo test --release --test crs_regression -- --ignored --nocapture
```

At the time of writing 3773/3779 request-phase tests pass (99.8%); the rest
depend on HTTP-server behaviour (e.g. Content-Length with Transfer-Encoding)
or thresholds the suite configures per test. A benign GET costs about 0.4 ms
of CPU at paranoia level 1 (`crs_evaluation_latency` benchmark), so enabling
CRS is a deliberate capacity trade-off. Not supported: response phases,
persistent collections (`IP`, `GLOBAL`), and `exec`/`setenv` side effects.
Unsupported operators, transformations, or actions fail rule loading.

## Plugin registry trust

`bearust plugin search|install|upgrade` and **Plugins → Plugin registry**
read a static JSON index. To make the index itself trustworthy, publish a
detached signature next to it and pin the registry key:

```sh
# index.json.sig = base64(Ed25519 signature over the exact index.json bytes)
[plugins]
registry_url = "https://plugins.example.com/index.json"
registry_public_key = "<base64 Ed25519 public key>"
```

With a pinned key, an index without a valid `index.json.sig` is refused.
Only a verified index may revoke: `"revoked": [{"id": "...", "version":
"..."}]` blocks installing a release, and `"revoked_keys": ["<base64 key>"]`
is persisted to `<plugins dir>/revoked-keys.json`, after which plugins
signed by that key fail to load (`key_revoked`). Installed versions are
recorded in `<plugin>/.registry.json` and drive upgrade detection. The CLI
takes `--registry-key` or `BEARUST_PLUGIN_REGISTRY_KEY`.

## TCP/UDP stream proxying

Non-HTTP services can be proxied at layer 4 from the config file:

```toml
[[streams]]
name = "postgres"
protocol = "tcp"            # or "udp"
listen = "0.0.0.0:5432"
backends = ["10.0.0.10:5432", "10.0.0.11:5432"]
connect_timeout_ms = 3000   # TCP: next backend is tried on failure
idle_timeout_seconds = 300  # idle TCP connections / UDP sessions close
max_connections = 10000     # per listener (UDP: concurrent client sessions)
```

Backends rotate round-robin. UDP keeps one upstream socket per client so
replies return to the right client. The IP security policy applies to
stream clients as well. In Docker, publish the listen ports yourself.

## AI Advisor development

Leave `LLM_API_URL` and `LLM_API_KEY` unset for the default disabled mode. For
manual testing use a local OpenAI-compatible endpoint and keep credentials in
an untracked `.env`. Optional settings are `LLM_MODEL`,
`LLM_REQUEST_TIMEOUT_SECONDS`, `LLM_RESPONSE_LIMIT_BYTES`, `LLM_QUEUE_CAPACITY`,
`LLM_WORKER_COUNT`, and `LLM_CIRCUIT_FAILURE_THRESHOLD`. Inputs are redacted
aggregate snapshots and bounded in-memory results; provider/user data never
belongs in logs or metrics. Unset both variables and restart to test disablement.

## WASM plugin runtime (Phase 13A)

Plugin loading is disabled by default. For a local runtime smoke test, create
an isolated directory and explicitly enable it in TOML:

```toml
[plugins]
enabled = true
directory = "./tests/fixtures/plugins"
max_plugins = 64
max_module_bytes = 16777216
max_memory_pages = 256
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

The deterministic fixture at
`tests/fixtures/plugins/health_ok/health_ok.wat` is compiled in the integration
test with the pinned `wat` crate. It exports the ABI version and health status
`1`; it has no imports. A plugin directory contains `plugin.toml` plus one
module, and the manifest fields/capabilities are documented in [docs/manual.md](docs/manual.md).
Do not copy arbitrary third-party WASM into tests or commit generated compiler
caches.

To exercise a filesystem load manually, compile and copy the deterministic
fixture into a temporary plugin directory (requires `wat2wasm`):

```bash
tmp_plugin="$(mktemp -d)/health-ok"
mkdir -p "$tmp_plugin"
wat2wasm tests/fixtures/plugins/health_ok/health_ok.wat \
  -o "$tmp_plugin/health_ok.wasm"
cp tests/fixtures/plugins/health_ok/plugin.toml "$tmp_plugin/plugin.toml"
```

Point `[plugins].directory` at the temporary parent, run the authenticated
reload/health-check calls, and remove the temporary directory afterward. The
generated binary is intentionally not checked in.

Use the authenticated API to verify lifecycle behavior: `GET /api/plugins`,
`POST /api/plugins/reload`, `POST /api/plugins/{id}/enable`,
`POST /api/plugins/{id}/disable`, `DELETE /api/plugins/{id}`, and
`POST /api/plugins/{id}/health-check`. `plugins.read` is required for listing
and health checks; `plugins.manage` is required for reload, enable, disable,
and unload. Responses and audit/realtime events are bounded and redacted.

The runtime supplies no WASI or host imports and rejects path traversal,
symlink escapes, unknown capabilities, malformed ABI exports, and limits above
the configured maxima. Errors are stable codes (`invalid_manifest`,
`abi_mismatch`, `compile_failed`, `disabled`, `timeout`, `fuel_exhausted`,
`memory_limit`, `trap`, `not_found`, `io_error`, `signature_required`,
`malformed_signature`, `invalid_signature`, `key_mismatch`,
`trust_store_corrupt`). A plugin failure never fails proxy requests or
prevents normal startup. Remote distribution is available through the
community registry index (`bearust plugin search` / `bearust plugin
install`, see [docs/manual.md](docs/manual.md)); treat every installed module as a reviewed
input and confirm its trust-on-first-use pin on first load.

### Plugin manifest signing and trust-on-first-use (Phase 14)

To exercise signing locally, generate a keypair and sign the fixture plugin
directory before pointing `[plugins].directory` at it:

```bash
bearust plugin keygen --out ./tmp-keys
bearust plugin sign "$tmp_plugin" --key ./tmp-keys/signing.key
```

`bearust plugin keygen --out <dir>` writes `<dir>/signing.key` (mode `0600`
on Unix) and prints the base64 public key to stdout; it refuses to run
twice into the same directory (`create_new`, not truncate) so it can never
silently clobber an existing key. `bearust plugin sign <plugin-dir> --key
<key-path>` reads `plugin.toml` and the module, and writes `<plugin-dir>/plugin.sig`.

Set `plugins.require_signature = true` to reject unsigned plugin
directories outright; leave it `false` to let signed and unsigned plugins
coexist (unsigned plugins load as `trust_status = "unsigned"`, signed ones
as `"trusted"` once pinned). The trust store lives at
`<plugins-directory>/trusted-keys.json` and pins the first key seen for
each plugin ID; a later load with a different key for the same ID fails
closed with `key_mismatch` rather than silently re-pinning. To simulate a
legitimate key rotation while testing, remove that plugin's entry from
`trusted-keys.json` and reload — see [docs/manual.md](docs/manual.md) and DEPLOY.md for the full
recovery procedure and the threat-model boundary (the pin file lives next
to the bundles it protects, so it defends the distribution channel, not
against an attacker who already has write access to the plugins
directory).

## Localization contribution workflow

The supported dashboard locale codes are `en` (English, the source and
fallback catalog), `id` (Indonesian), and `ja` (Japanese). Translation catalogs
live in `frontend/src/locales/`; follow [docs/localization.md](docs/localization.md)
for key naming, interpolation, and review guidance.

For every locale catalog change, run the key and interpolation-placeholder
validator before requesting review:

```bash
npm run validate-locales --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
```

Browser-backed responsive coverage uses Playwright with Chromium. After
installing frontend dependencies, install its browser binary once on each
development or CI host, then run the browser suite:

```bash
cd frontend
npx playwright install chromium
npm run test:e2e
```

The JSDOM tests retain structural responsive assertions; only the Playwright
suite measures real document layout and horizontal overflow.

For a release or cross-stack change, use the complete acceptance gate from the
repository root (same commands CI runs, plus the locale validator):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
npm run validate-locales --prefix frontend
npm test --prefix frontend -- --run
npm run build --prefix frontend
git diff --check
```

Container-level coverage lives in `scripts/` and is intentionally outside the
default `cargo`/`npm` suites because it needs a Docker daemon:

```bash
bash scripts/smoke-test.sh        # production image: plaintext + TLS proxy, control API
bash scripts/dev-compose-smoke.sh # dev stack: backend + API-backed frontend
bash scripts/check-legacy-classes.sh  # frontend guard against removed page-specific CSS hooks
```

Both smoke scripts use isolated Compose projects, ephemeral ports
(`18080`/`18081`), and temporary volumes, then clean up after themselves.

## Phase 8 analytics checks

Analytics is deliberately process-local: the one-minute ring buffer is bounded
to 24 hours (1,440 buckets per host) and resets whenever the process restarts.
Queries clamp host and timeseries limits to 100 and 1,440 respectively. The
collector stores only aggregate status, latency histograms, and redacted WAF,
bot, and rate-limit counters; raw IPs, URLs, headers, bodies, credentials,
tokens, and secrets are excluded. Recording is fail-open so an analytics error
does not reject or materially delay a proxy request.

The summary and timeseries endpoints require an authenticated admin, operator,
or viewer session and are read-only. Prometheus is disabled by default; when
enabled, its default internal bind is `127.0.0.1:9090`, and internal-only mode
requires loopback. An externally bound endpoint must require authentication.
Output uses bounded proxy-host/status-class labels and a 256 KiB default cap.
The frontend Analytics panel renders filters, summary cards, latency/error
views, security panels, and loading/error/empty states, then refetches on the
redacted `analytics.changed` SSE invalidation event.

Focused verification commands:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --test analytics --test prometheus --test control_plane_analytics --test proxy_analytics
npm test --prefix frontend -- --run src/analytics.test.tsx src/realtime.test.tsx
npm run build --prefix frontend
git diff --check
```

Durable long-term rollups, Redis/cross-node metric aggregation and event
replay, per-route analytics dimensions, and alerting are intentionally
deferred. Anomaly detection, adaptive tuning, and administrator-configurable
retention are implemented (Phase 9); see the self-learning section in [docs/manual.md](docs/manual.md).
## Basic WAF

Migration `0004_basic_waf.sql` seeds four built-in rules and defaults to
`monitor-only`. Administrators manage configuration through `/api/waf/config`
and `/api/waf/rules` or the dashboard. TOML imports use `version = 1` and are
rejected when any matcher is invalid. The evaluator inspects bounded request
fields and at most 8 KiB of body data.

Focused checks:

```bash
cargo test --test waf_repository --test waf_engine --test proxy_waf --test control_plane_waf
npm test --prefix frontend -- --run waf.test.tsx
```
