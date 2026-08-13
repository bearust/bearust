# BeaRust Plugin Authoring Guide

This guide shows how to build a BeaRust WASM plugin in Rust: the shared
memory convention every plugin uses, a worked example for each hook
capability, resource limits and failure behavior, signing, and how to
test a plugin locally against a running BeaRust instance.

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

A BeaRust plugin is a WebAssembly module loaded from a directory that
contains a `plugin.toml` manifest and a compiled `.wasm` module. Plugins
run inside a sandboxed [Wasmtime](https://wasmtime.dev/) instance with no
filesystem, network, or WASI access — only the memory the host explicitly
writes into and reads back from. Every invocation is bounded by the
manifest's `[limits]` table (memory pages, fuel, a wall-clock timeout,
and a maximum output size); the host never trusts plugin output beyond
those bounds. See `README.md`'s "Phase 13A WASM plugins" section for how
the host enforces this at the server-configuration level, and
"Phase 14 plugin manifest signing and trust-on-first-use" for optional
cryptographic signing.

There are two manifest ABI versions. `abi_version: 1` supports only a
single `health_check` capability and is documented in `README.md`; this
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
   bearust-plugin-sdk = "0.1"
   ```

3. Install the WASM target if you haven't already:

   ```console
   $ rustup target add wasm32-wasip1
   ```

4. Write `src/lib.rs`. Every `abi_version: 2` plugin must call the
   `abi_version!` macro once at crate root — this expands to the
   `bearust_abi_version() -> i32` export the host checks first:

   ```rust
   bearust_plugin_sdk::abi_version!(2);
   ```

   That's enough for the plugin to load, but not to pass a health check
   — the host also requires every `abi_version: 2` module to export
   `bearust_health_check_v2`, regardless of declared capabilities (see
   [Hook Reference](#hook-reference) below for its exact signature).

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
   the server's configured maxima (`README.md`'s `[plugins]` block).

7. Assemble the plugin directory under BeaRust's configured plugins
   directory (`./plugins` by default):

   ```text
   plugins/
   └── my-plugin/
       ├── plugin.toml
       └── my_plugin.wasm
   ```

8. Reload plugins on a running BeaRust instance (see
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

## Limits and Failure Behavior

## Signing and Sharing Your Plugin

## Testing Your Plugin Locally
