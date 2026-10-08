# Bearust Plugin Authoring Guide

This guide shows how to build a Bearust WASM plugin in Rust: the shared
memory convention every plugin uses, a worked example for each hook
capability, resource limits and failure behavior, signing, and how to
test a plugin locally against a running Bearust instance.

It assumes working knowledge of Rust. It does not cover WASM or
WebAssembly concepts from first principles.

## Contents

- [Overview](#overview)
- [Quickstart](#quickstart)
- [Memory Convention](#memory-convention)
- [Hook Reference](#hook-reference)
- [Limits and Failure Behavior](#limits-and-failure-behavior)
- [Signing and Sharing Your Plugin](#signing-and-sharing-your-plugin)
- [Testing Your Plugin Locally](#testing-your-plugin-locally)

## Overview

A Bearust plugin is a WebAssembly module loaded from a directory that
contains a `plugin.toml` manifest and a compiled `.wasm` module. Plugins
run inside a sandboxed [Wasmtime](https://wasmtime.dev/) instance with no
filesystem, network, or WASI access — only the memory the host explicitly
writes into and reads back from. Every invocation is bounded by the
manifest's `[limits]` table (memory pages, fuel, a wall-clock timeout,
and a maximum output size); the host never trusts plugin output beyond
those bounds. See `manual.md`'s "WASM plugin runtime" section for how
the host enforces this at the server-configuration level, and
"Plugin manifest signing and trust-on-first-use" for optional
cryptographic signing.

There are two manifest ABI versions. `abi_version: 1` supports only a
single `health_check` capability and is documented in `manual.md`; this
guide does not cover it further. `abi_version: 2` is the actively
developed ABI and the one this guide targets — it adds a shared
alloc/dealloc memory convention (below) that every richer hook capability
builds on: `waf.detect`, `transform.request`, `transform.response`,
`notify.waf_block`, and `balance.select`, in addition to an upgraded
health check.

## Quickstart

This builds the smallest possible `abi_version: 2` plugin — one that
loads successfully and passes its health check, with no real hook logic
yet. Later sections add a real capability to this same skeleton.

1. Create a new library crate:

   ```console
   $ cargo new --lib my-plugin
   ```

2. Add the SDK crate and configure the crate for a `cdylib` WASM build.
   Edit `Cargo.toml`:

   ```toml
   [package]
   name = "my-plugin"
   version = "0.1.0"
   edition = "2021"

   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   bearust-plugin-sdk = { path = "../bearust/crates/bearust-plugin-sdk" }
   ```

   `bearust-plugin-sdk` is not published on crates.io — in this repository
   it's a path-only workspace member (see this repo's own `Cargo.toml`).
   The path above is illustrative for a plugin crate checked out next to a
   clone of Bearust; a real external plugin author will need to vendor the
   crate (e.g. via a `git` dependency pinned to a commit, or a local path
   into a copy of this repository) until/unless Bearust publishes it
   somewhere a version specifier like `"0.1"` could actually resolve
   against.

3. Install the WASM target if you haven't already:

   ```console
   $ rustup target add wasm32-wasip1
   ```

4. Write `src/lib.rs`. Every `abi_version: 2` plugin must call the
   `abi_version!` macro once at crate root — this expands to the
   `bearust_abi_version() -> i32` export the host checks first. On its
   own, though, that macro is *not* enough for the plugin to load: for
   `abi_version: 2`, the host requires the guest's linear `memory` plus
   typed `bearust_alloc`, `bearust_dealloc`, and `bearust_health_check_v2`
   exports to all be present before it will load the module at all — a
   module missing any of them fails to load with `abi_mismatch`, it does
   not load and merely fail its health check. `bearust_alloc` and
   `bearust_dealloc` come for free from the SDK; you still need to write
   `bearust_health_check_v2` yourself, exactly as shown in the
   [`health`](#health) hook reference below:

   ```rust
   use bearust_plugin_sdk::{HealthCheckInput, HealthCheckOutput};

   bearust_plugin_sdk::abi_version!(2);

   #[no_mangle]
   pub extern "C" fn bearust_health_check_v2(ptr: i32, len: i32) -> i64 {
       let _input: HealthCheckInput = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
       let output = HealthCheckOutput {
           healthy: true,
           detail: Some("ok".to_owned()),
       };
       bearust_plugin_sdk::write_output(&output)
   }
   ```

   With this in place, the crate exports everything `abi_version: 2`
   requires at load time; adding a real hook capability later is purely
   additive.

5. Build for the WASM target:

   ```console
   $ cargo build --release --target wasm32-wasip1
   ```

   This produces `target/wasm32-wasip1/release/my_plugin.wasm`.

6. Write the manifest. Create `plugin.toml` next to the compiled module:

   ```toml
   id = "my-plugin"
   display_name = "My Plugin"
   abi_version = 2
   module = "my_plugin.wasm"
   capabilities = []

   [limits]
   memory_pages = 1
   fuel = 10000
   invocation_timeout_ms = 100
   max_output_bytes = 1024
   ```

   `id` must be lowercase letters, digits, and hyphens only. `capabilities`
   lists any of `waf.detect`, `transform.request`, `transform.response`,
   `notify.waf_block`, `balance.select` — empty for now, since this
   skeleton doesn't implement one yet. `[limits]` values must stay within
   the server's configured maxima (`manual.md`'s `[plugins]` block), and
   `max_output_bytes` must also clear the floor manifest validation
   enforces for `abi_version: 2` and, once you add one, for each declared
   capability — see the [Limits and Failure
   Behavior](#limits-and-failure-behavior) table and the per-hook floors
   noted in [Hook Reference](#hook-reference) below.

   The `memory_pages = 1` and `fuel = 10000` values above match this
   repo's own WASM test fixtures and are enough for a trivial
   health-check-only module. A real Rust plugin that links `serde` and
   `serde_json` (as the SDK's `encode`/`decode`/`read_input`/
   `write_output` helpers do) will likely need more fuel, and possibly
   more memory pages, than these floor values — if your plugin traps or
   reports `fuel_exhausted` during testing, raise both here first.

7. Assemble the plugin directory under Bearust's configured plugins
   directory (`./plugins` by default):

   ```text
   plugins/
   └── my-plugin/
       ├── plugin.toml
       └── my_plugin.wasm
   ```

8. Reload plugins on a running Bearust instance (see
   [Testing Your Plugin Locally](#testing-your-plugin-locally) for the
   full authenticated request) and confirm it loaded before adding real
   hook logic.

## Memory Convention

Every `abi_version: 2` hook — health check and every capability —
shares one calling convention for moving data across the host/guest
boundary, defined in
`docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md` and
implemented for you by `bearust-plugin-sdk`. You will not normally call
these primitives directly (the per-hook examples in
[Hook Reference](#hook-reference) use the higher-level `read_input`/
`write_output` helpers instead), but understanding them makes the
per-hook examples make sense:

- Every `abi_version: 2` module exports `bearust_alloc(len: i32) -> i32`,
  which returns a pointer to a `len`-byte buffer inside the guest's
  linear memory, and `bearust_dealloc(ptr: i32, len: i32)`, which
  releases a buffer previously returned by `bearust_alloc` or by a hook
  export's own output.
- **Host → guest:** the host calls `bearust_alloc(len)` to get a
  pointer, writes `len` bytes of JSON-encoded input into guest memory at
  that pointer, then calls the hook export with `(ptr, len)`.
- **Guest → host:** a hook export returns a single packed `i64`: the
  guest's output pointer and length packed together as
  `(ptr as i64) << 32 | (len as i64)`. The SDK's `pack`/`unpack`
  functions handle this encoding in both directions; you only need them
  if you bypass `write_output`/`read_input`.
- The SDK provides four small helpers so a plugin never has to touch raw
  pointers by hand:
  - `bearust_plugin_sdk::encode<T: Serialize>(&T) -> Vec<u8>` — JSON-encodes a value.
  - `bearust_plugin_sdk::decode<T: DeserializeOwned>(&[u8]) -> Result<T, serde_json::Error>` — JSON-decodes a value.
  - `unsafe fn bearust_plugin_sdk::read_input<T: DeserializeOwned>(ptr: i32, len: i32) -> T` (guest-only, `wasm32` target) — reads and decodes the host's input directly from the pointer/length pair a hook export receives; `unsafe` because it trusts `(ptr, len)` to describe a live, valid region of the guest's own memory, which holds for the pair a hook export receives from the host. Panics on malformed input, since a well-behaved host never sends malformed input; a trap here is caught and mapped to a `PluginError` on the host side.
  - `bearust_plugin_sdk::write_output<T: Serialize>(&T) -> i64` (guest-only, `wasm32` target) — encodes a value into a freshly allocated guest buffer and returns the packed `i64` result a hook export must return.
- The host allocates, writes, calls, reads, and deallocates on every
  single invocation — plugin memory does not persist between calls.

## Hook Reference

### health

Every `abi_version: 2` plugin must export this, independent of which
`capabilities` it declares. Load time only checks that the export
*exists* with the exact typed signature `(i32, i32) -> i64` — a module
missing it, or exporting it with the wrong signature, fails to load with
`abi_mismatch`; the host does not actually call it during load. The
export is only ever invoked later, on demand, via
`POST /api/plugins/{id}/health-check`.

**Export:** `bearust_health_check_v2(ptr: i32, len: i32) -> i64`

Every `abi_version: 2` plugin's `max_output_bytes` — regardless of which
other capabilities it declares — must be at least 64 bytes
(`MIN_V2_OUTPUT_BYTES` in the host's manifest validation); a smaller
value is rejected at load with `invalid_manifest`, since even the
smallest realistic `HealthCheckInput` JSON payload wouldn't fit under
it.

**Request** (`bearust_plugin_sdk::HealthCheckInput`):

```rust
pub struct HealthCheckInput {
    pub requested_at_ms: u64,
}
```

**Response** (`bearust_plugin_sdk::HealthCheckOutput`):

```rust
pub struct HealthCheckOutput {
    pub healthy: bool,
    pub detail: Option<String>,
}
```

`detail` is free-form and bounded by the manifest's `max_output_bytes`.

**Example:**

```rust
use bearust_plugin_sdk::{HealthCheckInput, HealthCheckOutput};

#[no_mangle]
pub extern "C" fn bearust_health_check_v2(ptr: i32, len: i32) -> i64 {
    let _input: HealthCheckInput = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    let output = HealthCheckOutput {
        healthy: true,
        detail: Some("ok".to_owned()),
    };
    bearust_plugin_sdk::write_output(&output)
}
```

### waf.detect

Declare `capabilities = ["waf.detect"]` in `plugin.toml`. Called for
every request the built-in WAF rule engine evaluates; the plugin's
verdict can only ever *escalate* the rule engine's own decision, never
lower it — see
`docs/superpowers/specs/2026-08-06-phase-13d-waf-detector-design.md`
for the exact merge rule.

A plugin declaring `waf.detect` must set `max_output_bytes` to at least
49152 bytes (`MIN_WAF_DETECT_INPUT_BYTES`) — the request context this
hook receives (method/path/query/headers plus a bounded body) is far
larger than a health check's, and a smaller limit is rejected at load
with `invalid_manifest`. The checked-in
`tests/fixtures/plugins/waf_detect_v2/plugin.toml` fixture uses exactly
this floor value.

**Export:** `bearust_waf_detect(ptr: i32, len: i32) -> i64`

**Request** (`bearust_plugin_sdk::WafDetectRequest`):

```rust
pub struct WafDetectRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

**Response** (`bearust_plugin_sdk::WafDetectVerdict`, `decision` is
`bearust_plugin_sdk::WafPluginDecision`, serialized as
`"allow" | "log" | "block"`):

```rust
pub enum WafPluginDecision {
    Allow,
    Log,
    Block,
}

pub struct WafDetectVerdict {
    pub decision: WafPluginDecision,
    pub category: String,
    pub score: u16,
}
```

**Example** (blocks any request whose path contains `/admin`):

```rust
use bearust_plugin_sdk::{WafDetectRequest, WafDetectVerdict, WafPluginDecision};

#[no_mangle]
pub extern "C" fn bearust_waf_detect(ptr: i32, len: i32) -> i64 {
    let request: WafDetectRequest = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    let verdict = if request.path.contains("/admin") {
        WafDetectVerdict {
            decision: WafPluginDecision::Block,
            category: "custom_admin_guard".to_owned(),
            score: 10,
        }
    } else {
        WafDetectVerdict {
            decision: WafPluginDecision::Allow,
            category: "custom_admin_guard".to_owned(),
            score: 0,
        }
    };
    bearust_plugin_sdk::write_output(&verdict)
}
```

### transform.request

Declare `capabilities = ["transform.request"]` in `plugin.toml`. Called
before a request is forwarded upstream; the returned header list
wholesale-replaces the outbound request's headers. The host
unconditionally reasserts `Host`, `X-Forwarded-For`, and `X-Request-Id`
afterward — this hook can never remove, blank, or spoof those three, so
don't rely on being able to.

A plugin declaring `transform.request` must set `max_output_bytes` to at
least 32768 bytes (`MIN_TRANSFORM_INPUT_BYTES`) — a smaller value is
rejected at load with `invalid_manifest`. The checked-in
`tests/fixtures/plugins/transform_request_v2/plugin.toml` fixture uses
exactly this floor value.

**Export:** `bearust_transform_request(ptr: i32, len: i32) -> i64`

**Request** (`bearust_plugin_sdk::TransformRequest`; no `body` field —
this hook only ever sees and returns headers):

```rust
pub struct TransformRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
}
```

**Response** (`bearust_plugin_sdk::TransformResponse` — despite the
name, this is the *output* of `transform.request`, not related to the
separate `transform.response` hook below):

```rust
pub struct TransformResponse {
    pub headers: Vec<(String, String)>,
}
```

**Example** (adds a header, otherwise passes headers through unchanged):

```rust
use bearust_plugin_sdk::{TransformRequest, TransformResponse};

#[no_mangle]
pub extern "C" fn bearust_transform_request(ptr: i32, len: i32) -> i64 {
    let request: TransformRequest = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    let mut headers = request.headers;
    headers.push(("x-transformed".to_owned(), "yes".to_owned()));
    let output = TransformResponse { headers };
    bearust_plugin_sdk::write_output(&output)
}
```

### transform.response

Declare `capabilities = ["transform.response"]` in `plugin.toml`.
Called after the upstream response body is fully buffered, before it's
sent to the client. Unlike `transform.request`, this hook **cannot**
touch headers — by the time the body decision is known, pingora has
already sent response headers downstream — so there is no `headers`
field on either side. `body` is base64-encoded (not a raw byte array)
to avoid the ~4x JSON expansion a `Vec<u8>` would incur.

A plugin declaring `transform.response` must set `max_output_bytes` to at
least 1572864 bytes (1.5 MiB, `MIN_TRANSFORM_RESPONSE_INPUT_BYTES`) — a
smaller value is rejected at load with `invalid_manifest`. The
checked-in `tests/fixtures/plugins/transform_response_v2/plugin.toml`
fixture uses exactly this floor value. Note that this floor is *larger*
than Bearust's default server-level `[plugins].max_output_bytes`
(65536, per `manual.md`); since the manifest's own limit can never
exceed the server's configured maximum, an operator running a
`transform.response` plugin must also raise the server's
`[plugins].max_output_bytes` to at least 1572864 (its ceiling is 2 MiB,
per `src/config/mod.rs`) — raising only the plugin's own manifest limit
is not enough on its own.

This hook is also skipped entirely, and the response passes through
unmodified, under either of these conditions (see
`src/proxy.rs::should_buffer_response_for_transform`):

- the response body is larger than 1 MiB
  (`RESPONSE_BODY_TRANSFORM_CAP_BYTES`) — bodies over this cap are never
  buffered for the hook, regardless of the manifest's own
  `max_output_bytes`;
- the response carries a `Content-Encoding` other than absent, empty, or
  `identity` — a compressed body is never handed to the hook, since the
  plugin would only see opaque compressed bytes it can't meaningfully
  transform.

(A few other conditions also skip this hook — informational, `204`, and
`304` responses; `HEAD` requests; and `text/event-stream` responses —
see the same function's doc comment in `src/proxy.rs` for the full list.)

**Export:** `bearust_transform_response(ptr: i32, len: i32) -> i64`

**Request** (`bearust_plugin_sdk::TransformResponseRequest`; `status` is
context only, not mutable):

```rust
pub struct TransformResponseRequest {
    pub status: u16,
    pub body: String, // base64-encoded
}
```

**Response** (`bearust_plugin_sdk::TransformResponseResult`; the host
replaces the buffered response body wholesale with the base64-decoded
`body` on success):

```rust
pub struct TransformResponseResult {
    pub body: String, // base64-encoded
}
```

**Example** (passes the body through unchanged — a real plugin would
decode, transform, and re-encode):

```rust
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bearust_plugin_sdk::{TransformResponseRequest, TransformResponseResult};

#[no_mangle]
pub extern "C" fn bearust_transform_response(ptr: i32, len: i32) -> i64 {
    let request: TransformResponseRequest = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    let decoded = STANDARD.decode(&request.body).unwrap_or_default();
    let output = TransformResponseResult {
        body: STANDARD.encode(decoded),
    };
    bearust_plugin_sdk::write_output(&output)
}
```

The example above uses the `base64` crate for illustration; add it to
your plugin's own `Cargo.toml` if you need to inspect or modify the
decoded body (`base64 = "0.22"` matches the version Bearust's host uses).

### notify.waf_block

Declare `capabilities = ["notify.waf_block"]` in `plugin.toml`. Called
as a fire-and-forget notification whenever the built-in WAF blocks a
request — this hook cannot influence the block decision itself (see
`waf.detect` above for that). The event never carries raw headers,
body, query string, or client IP — only the same redacted fields
Bearust's own audit/tracing output already uses.

A plugin declaring `notify.waf_block` must set `max_output_bytes` to at
least 1024 bytes (`MIN_NOTIFY_INPUT_BYTES`) — a smaller value is
rejected at load with `invalid_manifest`. The checked-in
`tests/fixtures/plugins/notify_sink_v2/plugin.toml` fixture uses exactly
this floor value.

**Export:** `bearust_notify_waf_block(ptr: i32, len: i32) -> i32` — note
this returns a plain `i32` status (`0` = success, nonzero =
plugin-reported failure), not a packed `i64`, since there is no output
payload to return.

**Request** (`bearust_plugin_sdk::WafBlockEvent`):

```rust
pub struct WafBlockEvent {
    pub request_id: String,
    pub occurred_at_ms: u64,
    pub category: String,
    pub score: u16,
    pub severity: String,
    pub reason_ids: String,
}
```

**Example:**

```rust
use bearust_plugin_sdk::WafBlockEvent;

#[no_mangle]
pub extern "C" fn bearust_notify_waf_block(ptr: i32, len: i32) -> i32 {
    let _event: WafBlockEvent = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    // Forward `_event` to wherever your plugin sends notifications.
    // Any WASI/network access is unavailable inside the sandbox, so a
    // real plugin would need to accumulate events for the host to read
    // via a future export, or another mechanism outside this guide's
    // scope.
    0
}
```

### balance.select

Declare `capabilities = ["balance.select"]` in `plugin.toml`, and
configure the upstream pool that should use it with `algorithm =
"plugin"` (see `src/config/mod.rs` for the full set of pool options),
for example:

```toml
[[upstream_pools]]
name = "my-pool"
algorithm = "plugin"
```

Called to choose a backend for a pool. The plugin has no authority
beyond suggestion: the host validates the returned `backend_id` against
the pool's live health/exclusion state, and falls back to its own
deterministic selection if the plugin's choice is invalid or the call
fails.

A plugin declaring `balance.select` must set `max_output_bytes` to at
least 49152 bytes (`MIN_BALANCE_INPUT_BYTES`) — a smaller value is
rejected at load with `invalid_manifest`. The checked-in
`tests/fixtures/plugins/balance_select_v2/plugin.toml` fixture uses
exactly this floor value.

**Export:** `bearust_balance_select(ptr: i32, len: i32) -> i64`

**Request** (`bearust_plugin_sdk::LoadBalanceRequest`; `backends` is
capped at 128 entries by the host before this struct is built;
`excluded_backend_id` is set when this call is a failover retry — the
backend that just failed on this same request):

```rust
pub struct BackendCandidate {
    pub id: u64,
    pub address: String,
    pub healthy: bool,
    pub inflight: u32,
}

pub struct LoadBalanceRequest {
    pub pool: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub backends: Vec<BackendCandidate>,
    pub excluded_backend_id: Option<u64>,
}
```

**Response** (`bearust_plugin_sdk::LoadBalanceResult`):

```rust
pub struct LoadBalanceResult {
    pub backend_id: u64,
}
```

**Example** (picks the first healthy, non-excluded backend — a real
plugin would implement its own selection logic):

```rust
use bearust_plugin_sdk::{LoadBalanceRequest, LoadBalanceResult};

#[no_mangle]
pub extern "C" fn bearust_balance_select(ptr: i32, len: i32) -> i64 {
    let request: LoadBalanceRequest = unsafe { bearust_plugin_sdk::read_input(ptr, len) };
    let chosen = request
        .backends
        .iter()
        .find(|b| b.healthy && Some(b.id) != request.excluded_backend_id)
        .map(|b| b.id)
        .unwrap_or(0);
    let output = LoadBalanceResult { backend_id: chosen };
    bearust_plugin_sdk::write_output(&output)
}
```

## Limits and Failure Behavior

Every invocation is bounded by the manifest's `[limits]` table, itself
capped by the server's configured maxima (`manual.md`'s `[plugins]`
block):

| Field | Meaning |
|---|---|
| `memory_pages` | Guest linear memory limit, in 64 KiB pages. |
| `fuel` | Wasmtime fuel budget for one invocation — bounds CPU work independent of wall-clock time. |
| `invocation_timeout_ms` | Wall-clock timeout for one invocation. |
| `max_output_bytes` | Maximum size of the JSON exchanged across the host/guest boundary in *either* direction — it bounds both the host→guest input the host writes into guest memory and the guest→host output the plugin writes back, not just the output. A value too small for the input side of a call fails that call the same way an oversized output would. Manifest validation additionally enforces a per-capability floor on this field beyond the server's configured maximum — see the relevant [Hook Reference](#hook-reference) subsection for the exact floor your declared capabilities require. |

If a plugin traps, times out, exhausts its fuel, or returns malformed or
oversized output, the host never propagates that failure to the client
request. Instead, each hook's caller falls back to Bearust's built-in
behavior for that request, as if the plugin capability weren't
configured at all:

- `waf.detect`: the built-in rule engine's own decision stands
  unchanged — recall from the [Hook Reference](#hook-reference) that a
  plugin verdict can only escalate a decision, never suppress one, so a
  failed call simply contributes nothing.
- `transform.request` / `transform.response`: the request or response
  passes through with its original headers/body unmodified.
- `notify.waf_block`: the notification is dropped; the block itself
  already happened independently and is unaffected. This hook is also
  fire-and-forget by design — it runs off the proxy's hot path through a
  bounded queue, so a slow or failing plugin here can never add latency
  to the request that triggered the block, only lose the notification.
- `balance.select`: the pool falls back to its own configured algorithm
  (round robin, least connections, etc.) for that selection. The same
  fallback also applies if the plugin's chosen `backend_id` doesn't name
  a currently healthy, non-excluded backend — an invalid pick is treated
  the same as a failed call.

Only one plugin is ever active per capability. If two enabled plugins
both declare the same capability (say, two plugins each declaring
`waf.detect`), the host picks the first one by lowest plugin ID as the
active plugin for that capability and the other is simply never called
for it — silently inactive, with no error or warning surfaced anywhere.
If you need to combine logic from two plugins for the same capability,
you currently have to merge that logic into a single plugin yourself.

This is a deliberate fail-open design: a broken or slow plugin degrades
Bearust to its behavior *without* that plugin, rather than failing
traffic. Write your plugin logic knowing that any panic, infinite loop
(caught by the fuel/timeout bounds), or malformed response you produce
is silently ignored by the host, not surfaced to your plugin's caller —
so test failure paths explicitly (see
[Testing Your Plugin Locally](#testing-your-plugin-locally)) rather than
relying on the host to tell you something went wrong.

## Signing and Sharing Your Plugin

Signing is optional. See `manual.md`'s "Plugin manifest signing and
trust-on-first-use" section for the full mechanism
(trust-on-first-use pinning, key rotation, the threat model it does and
doesn't cover) — this section only summarizes the two commands you run
as a plugin author:

```console
$ bearust plugin keygen --out ./keys
<base64 public key printed to stdout>
$ bearust plugin sign ./plugins/my-plugin --key ./keys/signing.key
wrote ./plugins/my-plugin/plugin.sig
```

`keygen` generates an Ed25519 keypair once; `sign` reads your plugin's
manifest and compiled module and writes a `plugin.sig` file next to
them, covering both against tampering. Keep `signing.key` private —
anyone who has it can produce signatures a Bearust instance will accept
as coming from you, for any plugin ID that instance hasn't already
pinned to a different key.

There is no community plugin registry yet — Bearust doesn't provide a
place to publish, discover, or fetch plugins by ID. For now, share your
plugin directory (`plugin.toml`, the compiled `.wasm` module, and
`plugin.sig` if signed) through whatever channel you already use — a
Git repository, a release artifact, an internal file share. Anyone
installing it copies that directory under their own Bearust instance's
configured plugins directory and reloads.

## Testing Your Plugin Locally

With `[plugins].enabled = true` and a running Bearust instance, reload
after adding or changing a plugin directory:

```console
$ curl -b cookies.txt -X POST http://127.0.0.1:8081/api/plugins/reload
{"loaded":1,"failed":0}
```

(This requires an authenticated session with the `plugins.manage`
permission — see `manual.md`'s RBAC section for obtaining
`cookies.txt`.)

Check load status, including the `trust_status` field added by
signing, with:

```console
$ curl -b cookies.txt http://127.0.0.1:8081/api/plugins
```

A plugin that fails to load reports a stable error code (`invalid_manifest`,
`abi_mismatch`, `compile_failed`, `timeout`, `fuel_exhausted`,
`memory_limit`, `trap`, and others — see `manual.md`'s WASM plugin
runtime section for the full list) rather than a raw error message. If yours
reports one of these, re-check the corresponding section above before
assuming the host is at fault.

Trigger a standalone health check (exercises `bearust_health_check_v2`
without going through live traffic):

```console
$ curl -b cookies.txt -X POST http://127.0.0.1:8081/api/plugins/my-plugin/health-check
```

To exercise a traffic hook (`waf.detect`, `transform.request`,
`transform.response`, `notify.waf_block`, `balance.select`), send a
request through a proxy host configured to use it and observe the
effect directly (a modified header, a blocked request, a chosen
backend) — there is no standalone invoke-by-capability endpoint for
these in this increment.

If you're debugging a manifest or directory-layout problem, the fixture
manifests under `tests/fixtures/plugins/` in the Bearust repository are
known-good references for every capability this guide covers — compare
your `plugin.toml` against the one matching your capability (e.g.
`tests/fixtures/plugins/waf_detect_v2/plugin.toml` for `waf.detect`).
