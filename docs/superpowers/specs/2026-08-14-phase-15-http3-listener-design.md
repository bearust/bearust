# Phase 15 increment 1: HTTP/3 listener (client-side, minimal)

## Goals

Resolve PRD Open Question #5 ("HTTP/3 support target — included in v1 or
deferred to a later release?") by adding an opt-in HTTP/3 (QUIC) listener
on the client-facing side of Bearust, running alongside the existing
Pingora-based TCP listener rather than replacing it. A browser connecting
over HTTP/3 gets routed and WAF-inspected the same way a browser
connecting over HTTP/1.1 or HTTP/2 already is; the request is then
forwarded upstream over plain HTTP/1.1, identical to how the existing
TCP path talks to backends today.

## Non-goals (this increment)

- **No HTTP/3 to the upstream.** Backends are still reached over
  HTTP/1.1, matching the existing `HttpPeer::new(address, false, ...)`
  behavior in `src/proxy.rs`. Upstream H3 is a separate, later increment
  if ever pursued.
- **No `Alt-Svc` advertisement.** The existing HTTP/1.1/HTTP/2 responses
  do not gain an `Alt-Svc` header pointing clients at the new H3
  listener. Without discovery, only clients explicitly configured to
  try HTTP/3 against this host (or given the port out of band) will use
  it. Automatic upgrade advertisement is deferred to a later increment
  once the listener itself has proven stable.
- **No rate limiting, no bot/challenge protection, no analytics
  collection, and no plugin hook execution (`transform.request`,
  `notify.waf_block`, `balance.select`, etc.) on the HTTP/3 path.** The
  built-in WAF *rule engine* (`waf::evaluate`) runs — see Goals — but
  every other traffic-processing feature `src/proxy.rs`'s `ProxyHttp`
  implementation provides is not reachable from this listener yet. This
  is a real feature gap relative to the HTTP/1.1/HTTP/2 path, not
  something this increment tries to hide: `README.md`'s HTTP/3 section
  states plainly that these are unavailable on H3 until a later
  increment closes the gap.
- **No TLS material live-reload for the H3 listener specifically** — it
  reads the same cert/key files at startup that the Pingora TLS listener
  already does, and does not currently reload them without a process
  restart. This matches the existing Pingora TLS listener's own
  behavior today, so it is not a new limitation, just one this
  increment doesn't attempt to fix on the H3 side either.
- **No load-balancing algorithm changes.** Backend selection reuses
  `PoolState::select`, the same method `src/proxy.rs` already calls;
  this increment adds no new balancing behavior.
- **No decision here on whether/when to advertise this as
  "production-ready."** Given the Non-goals above (particularly the
  missing rate-limit/bot-protection/plugin parity), operators enabling
  this today are choosing an HTTP/3 listener with a narrower security
  and feature surface than the HTTP/1.1/HTTP/2 listener, and the
  documentation must say so.

## Architecture

A new, independent listener stack alongside Pingora's existing one, not
a replacement or a modification of `src/proxy.rs`'s `ProxyHttp`
implementation:

```
Client (HTTP/3, QUIC/UDP) ──► src/http3.rs listener (new: quinn + h3)
                                   │
                                   ├─► waf::evaluate(&snapshot, &context)  [reused]
                                   │      (block ⇒ respond directly, stop here)
                                   │
                                   ├─► RuntimeStore::load().route(authority, path)  [reused]
                                   │      (no match ⇒ 404)
                                   │
                                   ├─► PoolState::select(None)  [reused]
                                   │      (no healthy backend ⇒ 502)
                                   │
                                   └─► plain HTTP/1.1 client ──► upstream backend
                                          (new: minimal client, no TLS,
                                          matching HttpPeer::new(_, false, _))

Client (HTTP/1.1/HTTP/2, TCP) ──► Pingora ProxyHttp (existing, unchanged)
                                   ──► WAF, rate limit, bot protection,
                                       analytics, plugins, upstream (unchanged)
```

**Why a parallel stack instead of extending Pingora:** confirmed by
reading `pingora-core` 0.8.1's own `Cargo.toml` and source tree directly
(the version this project depends on, and the latest version known to
this environment's registry index) — it has no `quic`/`h3` feature, no
`quiche`/`quinn`/`h3` dependency, and no QUIC-related source file
anywhere in the crate. Pingora's upstream project does not currently
ship HTTP/3 support to build on. The standard pure-Rust alternative is
`quinn` (QUIC transport) plus `h3`/`h3-quinn` (HTTP/3 framing over a
`quinn` connection), which is what this increment adds. `quinn`/`h3`'s
TLS layer is `rustls` 0.23.x; this repo's dependency tree already
resolves `rustls` 0.23.43 (via `pingora-rustls`, using the `ring` crypto
provider), confirmed compatible by inspecting `Cargo.lock` and
`pingora-rustls`'s own `Cargo.toml` — no version conflict to resolve.

**Why WAF is reused but nothing else is (yet):** `waf::evaluate(snapshot:
&WafSnapshot, context: &InspectionContext) -> Evaluation` and
`RuntimeStore`'s `route`/pool-selection methods are already plain,
Pingora-independent functions operating on owned data
(`InspectionContext` is `{ method: String, path: String, query: String,
headers: Vec<(String, String)>, body: Vec<u8> }`, confirmed in
`src/waf.rs`) — trivial to construct from an `h3` request and call
directly. Rate limiting, bot/challenge protection, analytics, and plugin
hook invocation, by contrast, are currently wired directly into
`src/proxy.rs`'s `ProxyHttp` trait methods and its `RequestContext`
type, not exposed as similarly reusable free functions; decoupling them
enough to call from a second listener stack is real, non-trivial work
that belongs in its own later increment rather than being bundled into
"add an H3 listener." Skipping WAF specifically was rejected during
brainstorming: it is the one omission that would let a client bypass an
existing security control simply by switching protocols, which this
project's stated care around introducing security vulnerabilities rules
out for a first increment.

## Components

### `src/http3.rs` (new)

- `pub struct Http3Config` (or reuse a config struct from `src/config/mod.rs`
  directly — see Config below) carrying the bind address and enabled flag.
- `pub fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, Http3Error>`
  — loads the same `cert_path`/`key_path` PEM files
  `crate::certificates::CertificateStore` already validates for the
  Pingora listener (reuse `CertificateStore::validate_material_paths`
  for the readability/pairing check before handing paths to `rustls`),
  and builds a `rustls::ServerConfig` with ALPN set to `["h3"]` for
  `quinn`/`h3` to negotiate against.
- `pub async fn serve(bind: SocketAddr, tls_config: Arc<rustls::ServerConfig>, store: Arc<RuntimeStore>, waf: Option<Arc<WafStore>>, mut shutdown: watch::Receiver<bool>) -> Result<(), Http3Error>`
  — binds the QUIC endpoint via `quinn::Endpoint::server`, accepts
  connections in a loop, spawns a task per connection running the `h3`
  request loop, and stops accepting new connections (draining
  in-flight ones, bounded the same way the existing graceful-shutdown
  timeout already bounds Pingora's own drain) when `shutdown` fires —
  matching the shutdown-handle pattern `src/cli.rs`'s `serve_proxy`
  already uses for `control_task`/`cluster_task`.
- `async fn handle_request(...) -> Result<(), Http3Error>` — the
  per-request pipeline: read the `h3` request head + buffered body
  (capped the same way `waf::MAX_INSPECTION_BODY_BYTES`/
  `MAX_NORMALIZED_METADATA_BYTES` already cap the HTTP/1.1/HTTP/2 path,
  so H3 can't inspect or forward an unbounded body either), build
  `waf::InspectionContext`, call `waf::evaluate` if a `WafStore` is
  configured, call `RuntimeStore::route`, call `PoolState::select`,
  forward via a minimal HTTP/1.1 client, stream the response back.
- `Http3Error` — covers bind failure, TLS config construction failure,
  and per-request failures, each mapped to a safe log field the same
  way `PluginError`/`TlsError`/existing proxy errors already avoid
  leaking internals; never panics on client-controlled input.

### `src/config/mod.rs` (modified)

New `Http3Config` nested under `ServerConfig` (mirroring how `TlsConfig`
is already nested):

```rust
pub struct Http3Config {
    pub enabled: bool,       // default: false
    pub bind: SocketAddr,    // UDP bind address; only read when enabled
}
```

`enabled` defaults to `false` — consistent with every other major
optional feature in this project (`plugins.enabled`, cluster
`auth_token`, AI Advisor). `Http3Config` is only meaningful when
`server.tls` is also configured (HTTP/3 mandates TLS 1.3); startup
rejects `http3.enabled = true` with `server.tls = None` as a config
validation error, the same way other cross-field config invariants are
already checked in `config::load`.

### `src/cli.rs` (modified)

In `serve_proxy`, after the existing Pingora `server.bootstrap()` /
service-registration block: if `config.server.http3.enabled`, build the
`rustls::ServerConfig` via `http3::build_rustls_server_config`, spawn
`http3::serve(...)` via `tokio::spawn`, and add its `JoinHandle` to the
same shutdown-coordination `tokio::select!`/timeout-bounded drain
sequence the existing `control_task`/`cluster_task` already go through,
so `serve_proxy`'s existing graceful-shutdown behavior covers the new
listener without a parallel, divergent shutdown path.

### `Cargo.toml` (modified)

New dependencies: `quinn = "0.11"`, `h3 = "0.0.6"` (or whatever the
current `h3`/`h3-quinn` compatible release pinning `quinn` 0.11 and
`rustls` 0.23 turns out to be at plan-writing time — the implementation
plan must pin exact, verified-compatible versions rather than ranges,
following this project's existing pattern of pinning crates with `=`
where compatibility is load-bearing, e.g. `clap`, `openraft`).

## Data Flow

1. **Startup:** `serve_proxy` builds the H3 listener (if enabled) after
   the existing Pingora bootstrap, using the same `RuntimeStore`
   (`Arc`, already shared with the Pingora proxy service) and the same
   `Arc<WafStore>` (if WAF is configured) — no duplicated state, no new
   config-reload plumbing, since both are read fresh on every request
   via their existing `Arc`/snapshot mechanisms.
2. **Per-connection:** `quinn::Endpoint::server` accepts a QUIC
   connection; `h3`'s connection driver negotiates HTTP/3 over it
   (ALPN `h3`); a task is spawned per connection to serve however many
   requests/streams the client opens on it.
3. **Per-request:**
   - Read the request head (`:method`, `:authority`, `:path`, headers)
     and buffer the body up to the existing WAF inspection cap.
   - Build `waf::InspectionContext { method, path, query, headers,
     body }` from those fields — the exact same shape `src/proxy.rs`
     already builds for the HTTP/1.1/HTTP/2 path, so WAF rule
     evaluation behaves identically regardless of which listener
     handled the request.
   - If a `WafStore` is configured, call `waf::evaluate`. A `block`
     verdict returns the same block response shape the existing path
     already returns, and the request goes no further (no upstream
     connection is attempted).
   - Otherwise, call `RuntimeStore::load().route(authority, path)`. No
     match returns 404.
   - Call `pool.select(None)` on the resolved pool. No healthy backend
     returns 502.
   - Forward the request to the selected backend over plain HTTP/1.1
     (no TLS, matching `HttpPeer::new(address, false, ...)`'s existing
     upstream behavior) via a minimal client.
   - Stream the backend's response back over the HTTP/3 response
     stream as it arrives, rather than buffering it fully first.
4. **Shutdown:** the same `graceful_shutdown_seconds`-bounded drain
   `serve_proxy` already applies to its other spawned tasks applies to
   the H3 listener's `JoinHandle` — stop accepting new QUIC connections,
   let in-flight requests finish up to the timeout, then proceed.

## Error Handling

| Condition | Behavior |
|---|---|
| `server.http3.enabled = false` (default) | No UDP socket opened; zero behavioral change to any existing feature |
| `server.http3.enabled = true` with `server.tls = None` | Config validation error at startup (fail closed, matching this project's existing config-validation conventions) |
| QUIC/TLS handshake failure | Handled entirely by `quinn`/`rustls`; never reaches request-handling code |
| WAF block verdict | Block response returned; upstream is never contacted |
| No route match (`RuntimeStore::route` returns `None`) | 404; upstream is never contacted |
| No healthy backend in the resolved pool | 502, matching the existing HTTP/1.1/HTTP/2 path's behavior for the same condition |
| Upstream connection failure/timeout | 502/504; no automatic retry in this increment (matches this increment's minimal scope — sophisticated retry logic is out of scope here just as it would be for a first pass at any new listener) |
| Request body exceeds the existing WAF inspection cap | Rejected before `waf::evaluate` is ever called, using the same cap already enforced on the HTTP/1.1/HTTP/2 path |
| A panic inside per-request handling (should not happen, but the boundary must hold) | Caught at the per-request task boundary (`tokio::spawn` already isolates a panic to that task); the connection continues serving other streams, the process does not crash |

## Testing

- Unit: an `InspectionContext` built from a synthetic H3 request and one
  built from an equivalent HTTP/1.1/HTTP/2 request (same method, path,
  headers, body) compare field-for-field equal — guards against
  semantic drift between the two listener paths' WAF behavior.
- Integration: a real `h3`/`quinn` client (in the test) connects to a
  local H3 listener instance and receives the expected response from a
  local test backend — the same "spin up a local server, drive it with
  a real client" pattern this project's other integration tests already
  use (e.g. `tests/acme_dns01.rs`), adapted to an H3 client instead of
  `reqwest`.
- Integration: a request that the WAF rule engine would block over
  HTTP/1.1 is sent over H3 and confirmed blocked, with the test
  backend asserted to have received zero requests for that case.
- Integration: with `server.http3.enabled = false` (the default),
  confirm no UDP socket is listening on the configured port.
- Integration: graceful shutdown drains an in-flight H3 request rather
  than severing it mid-response, within the configured
  `graceful_shutdown_seconds` bound.

## Follow-up increments (out of scope here)

- Rate limiting, bot/challenge protection, analytics, and plugin hook
  parity with the HTTP/1.1/HTTP/2 path.
- `Alt-Svc` advertisement on existing HTTP/1.1/HTTP/2 responses for
  automatic client upgrade.
- Upstream HTTP/3 (Bearust-to-backend).
- Live TLS material reload for the H3 listener.
