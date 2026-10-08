# Phase 13B — Plugin SDK & Memory Conventions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a public `bearust-plugin-sdk` crate and a stable JSON-over-linear-memory host/guest convention, extending the plugin ABI from a single supported version (`1`) to a bounded set (`{1, 2}`), with `abi_version: 2` plugins able to exchange structured JSON through a new `bearust_health_check_v2` export, while `abi_version: 1` plugins are byte-for-byte unchanged.

**Architecture:** A new workspace member crate (`crates/bearust-plugin-sdk`) implements the guest side of the convention (allocator exports, JSON encode/decode, pointer packing) and defines the shared `HealthCheckInput`/`HealthCheckOutput` types. The host (`src/plugin_runtime.rs`) depends on the same crate for those types and the packing helpers, adds bounds-checked guest-memory read/write helpers, and branches `CompiledPlugin::health_check()` on the plugin's compiled `abi_version`. No host imports, WASI, or new capabilities are introduced — this is a data convention on top of the existing sandbox, not a new hook.

**Tech Stack:** Rust, Cargo workspaces, `wasmtime` 27 (existing pinned dependency), `serde`/`serde_json`, hand-written WAT test fixtures (via the pinned `wat` dev-dependency), `axum` control-plane handlers (existing).

## Global Constraints

- Every existing `abi_version: 1` plugin, manifest, and test must keep working with zero behavior change.
- No plugin gains any host import, WASI capability, filesystem, network, or clock access. This phase changes only how data crosses the existing memory boundary.
- Every guest-supplied pointer/length pair must be bounds-checked against that guest's actual linear memory size before any host read/write; an out-of-range claim must produce `PluginError::Trap`, never a host out-of-bounds access.
- `max_output_bytes` (already an existing per-plugin limit) bounds the new JSON payloads in both directions; exceeding it produces `PluginError::MemoryLimit`.
- No `wasm32-wasip1` build target is required in CI; the runtime side is proven with hand-written WAT fixtures under `tests/fixtures/plugins/`, matching Phase 13A's approach.
- The full gate (`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `DATABASE_URL=sqlite::memory: cargo test --all-targets`, `npm test --prefix frontend -- --run`, `npm run build --prefix frontend`, `npm run validate-locales --prefix frontend`, `git diff --check`) must pass on the project's pinned stable toolchain (`rust-toolchain.toml`, currently `1.97.1`) before the final commit.
- Commit after every task, using the existing repository's commit style (short imperative subject, no trailing period, `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` footer only when explicitly requested by the user — for this plan, commit without that footer unless told otherwise, matching how the repository's own history was written before this session).

---

### Task 1: Workspace conversion and `bearust-plugin-sdk` crate scaffold

**Files:**
- Modify: `Cargo.toml` (add `[workspace]`, add `bearust-plugin-sdk` path dependency)
- Create: `crates/bearust-plugin-sdk/Cargo.toml`
- Create: `crates/bearust-plugin-sdk/src/lib.rs`
- Modify: `Dockerfile:11-12` (copy the new `crates/` directory into the build stage)

**Interfaces:**
- Produces (consumed by Tasks 3–4 in `src/plugin_runtime.rs`, and available to real plugin authors):
  - `bearust_plugin_sdk::pack(ptr: i32, len: i32) -> i64`
  - `bearust_plugin_sdk::unpack(value: i64) -> (i32, i32)`
  - `bearust_plugin_sdk::encode<T: serde::Serialize>(value: &T) -> Vec<u8>`
  - `bearust_plugin_sdk::decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error>`
  - `bearust_plugin_sdk::read_input<T: serde::de::DeserializeOwned>(ptr: i32, len: i32) -> T` (guest-only; unsafe raw-pointer dereference, not exercised by this test suite — see doc comment)
  - `bearust_plugin_sdk::write_output<T: serde::Serialize>(value: &T) -> i64` (guest-only; same caveat)
  - `#[no_mangle] extern "C" fn bearust_alloc(len: i32) -> i32` and `bearust_dealloc(ptr: i32, len: i32)` (guest-exported, real WASM export symbols once this crate is compiled to `wasm32-wasip1` by a plugin author)
  - macro `bearust_plugin_sdk::abi_version!($version:expr)` expanding to the `bearust_abi_version() -> i32` export
  - `bearust_plugin_sdk::HealthCheckInput { pub requested_at_ms: u64 }`
  - `bearust_plugin_sdk::HealthCheckOutput { pub healthy: bool, pub detail: Option<String> }`

- [ ] **Step 1: Convert the root manifest into a workspace and scaffold the new crate's directory**

Read `Cargo.toml` first to confirm the current `[package]` section is still exactly as captured in this plan (it should be unchanged since the toolchain-gate fix). Then edit it: keep the existing `[package]` section as-is, and add a `[workspace]` section right after it (a manifest can have both — the root package is then automatically a workspace member):

```toml
[workspace]
members = ["crates/bearust-plugin-sdk"]
```

Add the new path dependency to the existing `[dependencies]` table (alphabetical position, next to `base64`):

```toml
bearust-plugin-sdk = { path = "crates/bearust-plugin-sdk" }
```

Create the directory:

```bash
mkdir -p crates/bearust-plugin-sdk/src
```

- [ ] **Step 2: Write the new crate's manifest**

Create `crates/bearust-plugin-sdk/Cargo.toml`:

```toml
[package]
name = "bearust-plugin-sdk"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"
license = "MIT OR Apache-2.0"
description = "SDK for building Bearust WASM plugins"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 3: Write the failing tests for the pure (pointer-free) helpers**

Create `crates/bearust-plugin-sdk/src/lib.rs` with only the test module and empty `pack`/`unpack`/`encode`/`decode` stubs so the crate compiles and the tests fail on assertions, not on missing items:

```rust
use serde::{de::DeserializeOwned, Serialize};

pub fn pack(_ptr: i32, _len: i32) -> i64 {
    0
}

pub fn unpack(_value: i64) -> (i32, i32) {
    (0, 0)
}

pub fn encode<T: Serialize>(_value: &T) -> Vec<u8> {
    Vec::new()
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_round_trips_ordinary_values() {
        assert_eq!(unpack(pack(1024, 34)), (1024, 34));
        assert_eq!(unpack(pack(0, 0)), (0, 0));
    }

    #[test]
    fn pack_unpack_round_trips_max_i32_values() {
        assert_eq!(unpack(pack(i32::MAX, i32::MAX)), (i32::MAX, i32::MAX));
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        healthy: bool,
        detail: Option<String>,
    }

    #[test]
    fn encode_decode_round_trips_a_struct() {
        let value = Sample {
            healthy: true,
            detail: Some("ok".to_owned()),
        };
        let bytes = encode(&value);
        let decoded: Sample = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn decode_rejects_malformed_json() {
        let result: Result<Sample, _> = decode(b"not json");
        assert!(result.is_err());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p bearust-plugin-sdk`
Expected: `pack_unpack_round_trips_ordinary_values` and `pack_unpack_round_trips_max_i32_values` FAIL (stub functions return `(0, 0)`); `encode_decode_round_trips_a_struct` FAILS (stub `encode` returns an empty `Vec`); `decode_rejects_malformed_json` PASSES incidentally (a stub is not required to change this one, but leave it as written).

- [ ] **Step 5: Implement `pack`/`unpack`/`encode`/`decode` for real**

Replace the stub bodies in `crates/bearust-plugin-sdk/src/lib.rs`:

```rust
/// Packs a guest pointer and length into the `i64` ABI result used by
/// `bearust_health_check_v2` and future data-carrying exports:
/// `(ptr as i64) << 32 | (len as i64)`, both halves zero-extended so the
/// pack/unpack round trip is exact for any `i32` bit pattern.
pub fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
}

/// Unpacks an ABI result produced by [`pack`] back into `(ptr, len)`.
pub fn unpack(value: i64) -> (i32, i32) {
    let ptr = ((value >> 32) & 0xFFFF_FFFF) as u32 as i32;
    let len = (value & 0xFFFF_FFFF) as u32 as i32;
    (ptr, len)
}

/// Encodes `value` as JSON. Returns an empty buffer if serialization fails
/// (it should not for the SDK's own plain-data types); the host treats an
/// empty or malformed payload as a decode failure, never a crash.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Decodes a JSON payload into `T`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p bearust-plugin-sdk`
Expected: all 4 tests PASS.

- [ ] **Step 7: Add the guest-only allocator, marshaling wrappers, macro, and shared types**

These functions are only meaningful when this crate is compiled to `wasm32-wasip1` by a plugin author — on that target, pointers are genuinely 32 bits, so the `as i32`/`as *mut u8` casts are exact. They are not exercised by this repository's test suite (see the Global Constraints note on the `wasm32-wasip1` target); the hand-written WAT fixture in Task 4 proves the *host's* handling of this contract instead. Append to `crates/bearust-plugin-sdk/src/lib.rs`:

```rust
/// Guest-exported allocator entry point: reserves `len` bytes of this
/// module's own linear memory and returns a pointer the host can write
/// into before calling a plugin function that takes `(ptr, len)`.
///
/// Only meaningful when compiled for `wasm32-wasip1`; not exercised by this
/// repository's test suite (see Task 4's hand-written WAT fixture for the
/// host-side contract this implements).
#[no_mangle]
pub extern "C" fn bearust_alloc(len: i32) -> i32 {
    let len = len.max(0) as usize;
    let buf = vec![0u8; len].into_boxed_slice();
    Box::into_raw(buf) as *mut u8 as i32
}

/// Guest-exported deallocator: releases a buffer previously returned by
/// [`bearust_alloc`] or by a [`write_output`] result, once the host has
/// finished reading it.
///
/// # Safety (informal — this is an `extern "C"` ABI boundary, not `unsafe fn`)
/// `ptr`/`len` must be a pair previously returned by `bearust_alloc` (or by
/// `write_output`, whose buffer has the same provenance) and not already
/// deallocated. The host is the only caller and always passes back exactly
/// the pair it received.
#[no_mangle]
pub extern "C" fn bearust_dealloc(ptr: i32, len: i32) {
    if ptr == 0 {
        return;
    }
    let len = len.max(0) as usize;
    unsafe {
        drop(Box::from_raw(std::slice::from_raw_parts_mut(
            ptr as *mut u8,
            len,
        )));
    }
}

/// Decodes a JSON payload the host wrote into this guest's own memory at
/// `ptr` with length `len`. Guest-only; see the module-level caveat above.
pub fn read_input<T: DeserializeOwned>(ptr: i32, len: i32) -> T {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    decode(bytes).expect("bearust-plugin-sdk: host sent malformed input")
}

/// Encodes `value` as JSON into a freshly allocated guest buffer and
/// returns the packed `(ptr, len)` result the host expects. Guest-only; see
/// the module-level caveat above.
pub fn write_output<T: Serialize>(value: &T) -> i64 {
    let bytes = encode(value);
    let len = bytes.len() as i32;
    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8 as i32;
    pack(ptr, len)
}

/// Expands to the `bearust_abi_version() -> i32` export every plugin must
/// have. Call once at crate root: `bearust_plugin_sdk::abi_version!(2);`.
#[macro_export]
macro_rules! abi_version {
    ($version:expr) => {
        #[no_mangle]
        pub extern "C" fn bearust_abi_version() -> i32 {
            $version
        }
    };
}

/// Input to `bearust_health_check_v2`, shared between host and guest so
/// both sides always agree on the wire shape.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HealthCheckInput {
    pub requested_at_ms: u64,
}

/// Output of `bearust_health_check_v2`. `detail` is free-form and bounded
/// by the plugin's configured `max_output_bytes` on the host side.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct HealthCheckOutput {
    pub healthy: bool,
    pub detail: Option<String>,
}
```

- [ ] **Step 8: Build the whole workspace and run every test to confirm nothing else broke**

Run: `cargo build --workspace`
Expected: builds cleanly; `Cargo.lock` gains a `bearust-plugin-sdk` entry (review the diff — it should be additive only, no version bumps to unrelated crates since `serde`/`serde_json` are already in the dependency graph at compatible versions).

Run: `cargo test -p bearust-plugin-sdk && cargo test --lib --bins`
Expected: all PASS.

- [ ] **Step 9: Fix the production Docker build to include the new crate**

Read `Dockerfile` first. The builder stage currently does `COPY Cargo.toml Cargo.lock rust-toolchain.toml ./` then `COPY src ./src` — it never copies a `crates/` directory, so `cargo build --release --locked` would fail once the workspace member exists. Edit `Dockerfile`, adding a line right after the `COPY src ./src` line:

```dockerfile
COPY crates ./crates
```

- [ ] **Step 10: Verify the container build still works**

Run: `docker build -t bearust:phase13b-check .`
Expected: the build reaches and completes the `builder` stage without a "failed to load manifest" or missing-path error for `crates/bearust-plugin-sdk`. (If Docker is unavailable in this environment, skip this step and note it explicitly in the task's completion notes rather than silently omitting verification — the CI `container` job in `.github/workflows/ci.yml` will catch it if it's wrong.)

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml Cargo.lock Dockerfile crates/bearust-plugin-sdk
git commit -m "feat: add bearust-plugin-sdk crate and JSON memory convention"
```

---

### Task 2: Widen ABI version acceptance to `{1, 2}`

**Files:**
- Modify: `src/plugin_runtime.rs:21` (constant), `:237-239` (`compile`), `:313` (`health_check` runtime check), `:437-439` (`PluginManifest::validate`)
- Test: `tests/plugin_runtime.rs` (extend existing `capabilities_and_abi_rejected`, add one new test)

**Interfaces:**
- Consumes: nothing new from Task 1.
- Produces (consumed by Task 3): `pub const SUPPORTED_ABI_VERSIONS: std::ops::RangeInclusive<u32> = 1..=2;` replacing `SUPPORTED_ABI_VERSION`. `CompiledPlugin` gains a `pub(crate)` — actually needs to stay accessible to `health_check()` in the same `impl` block, so keep it as a private struct field `abi_version: u32` (no external visibility needed; nothing outside this module reads it directly).

- [ ] **Step 1: Write the failing test for the new upper bound**

Open `tests/plugin_runtime.rs`. In `capabilities_and_abi_rejected` (around line 78), the existing case already asserts `abi_version = 99` is rejected — leave it. Add a new test right after it:

```rust
#[test]
fn abi_version_two_is_accepted_at_manifest_validation() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("").replace("abi_version = 1", "abi_version = 2");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test plugin_runtime abi_version_two_is_accepted_at_manifest_validation`
Expected: FAIL — `validate()` currently returns `Err(AbiMismatch)` for `abi_version = 2` because of the `!= SUPPORTED_ABI_VERSION` check.

- [ ] **Step 3: Widen the constant and its three call sites**

In `src/plugin_runtime.rs`, replace line 21:

```rust
pub const SUPPORTED_ABI_VERSIONS: std::ops::RangeInclusive<u32> = 1..=2;
```

In `PluginManifest::validate` (around line 437), replace:

```rust
        if self.abi_version != SUPPORTED_ABI_VERSION {
            return Err(PluginError::AbiMismatch);
        }
```

with:

```rust
        if !SUPPORTED_ABI_VERSIONS.contains(&self.abi_version) {
            return Err(PluginError::AbiMismatch);
        }
```

In `PluginEngine::compile` (around line 237), replace:

```rust
        if manifest.abi_version != SUPPORTED_ABI_VERSION {
            return Err(PluginError::AbiMismatch);
        }
```

with:

```rust
        if !SUPPORTED_ABI_VERSIONS.contains(&manifest.abi_version) {
            return Err(PluginError::AbiMismatch);
        }
```

In `CompiledPlugin` (struct definition around line 203), add a field:

```rust
pub struct CompiledPlugin {
    engine: Engine,
    scheduler: Arc<EpochScheduler>,
    module: Module,
    limits: PluginLimits,
    abi_version: u32,
    has_health_check: bool,
}
```

At the end of `PluginEngine::compile`, where `CompiledPlugin` is constructed (around line 285), add the new field:

```rust
        Ok(CompiledPlugin {
            engine: self.engine.clone(),
            scheduler: Arc::clone(&self.scheduler),
            module,
            limits,
            abi_version: manifest.abi_version,
            has_health_check,
        })
```

In `CompiledPlugin::health_check` (around line 313), replace:

```rust
            if version != SUPPORTED_ABI_VERSION as i32 {
                return Err(PluginError::AbiMismatch);
            }
```

with:

```rust
            if version != self.abi_version as i32 {
                return Err(PluginError::AbiMismatch);
            }
```

- [ ] **Step 4: Run the full plugin_runtime test file to verify everything still compiles and passes**

Run: `cargo test --test plugin_runtime`
Expected: all tests PASS, including the new `abi_version_two_is_accepted_at_manifest_validation` and the pre-existing `abi_version = 99` rejection case in `capabilities_and_abi_rejected`.

- [ ] **Step 5: Commit**

```bash
git add src/plugin_runtime.rs tests/plugin_runtime.rs
git commit -m "feat: accept plugin abi_version 1 or 2"
```

---

### Task 3: Compile-time validation of `abi_version: 2` exports

**Files:**
- Modify: `src/plugin_runtime.rs:265-289` (`PluginEngine::compile`'s export-probing section)
- Test: `tests/plugin_runtime.rs`

**Interfaces:**
- Consumes: `SUPPORTED_ABI_VERSIONS`, `CompiledPlugin.abi_version` from Task 2.
- Produces (consumed by Task 4): a `CompiledPlugin` for a valid `abi_version: 2` module is guaranteed, by construction, to have `bearust_alloc(i32) -> i32`, `bearust_dealloc(i32, i32)`, `bearust_health_check_v2(i32, i32) -> i64`, and a `"memory"` export all present with the exact signatures — Task 4's invocation code can call `get_typed_func`/`get_memory` on those exports without re-checking `Option`/`Result` for "missing export", only for genuine runtime failures.

- [ ] **Step 1: Write the failing tests for missing v2 exports and missing memory**

Add to `tests/plugin_runtime.rs`, near the existing `compile_error` helper (around line 174):

```rust
fn compile_v2(wat: &str, limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    compile_bytes_v2(&wat::parse_str(wat).unwrap(), limits)
}

fn compile_bytes_v2(bytes: &[u8], limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    let engine = PluginEngine::new(PluginPolicy::default())?;
    engine.compile(validated_v2(limits), bytes)
}

fn validated_v2(limits: PluginLimits) -> ValidatedManifest {
    ValidatedManifest {
        abi_version: 2,
        ..validated(limits)
    }
}

#[test]
fn v2_missing_alloc_export_is_abi_mismatch() {
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_v2(wat, limits()).unwrap_err(),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_missing_health_check_v2_export_is_abi_mismatch() {
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32)))"#;
    assert_eq!(
        compile_v2(wat, limits()).unwrap_err(),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_missing_memory_export_is_abi_mismatch() {
    let wat = r#"(module
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_v2(wat, limits()).unwrap_err(),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_wrong_signature_export_is_abi_mismatch() {
    // bearust_alloc declared with the wrong result type (i64 instead of i32).
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i64) i64.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_v2(wat, limits()).unwrap_err(),
        PluginError::AbiMismatch
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test plugin_runtime v2_missing_alloc_export_is_abi_mismatch v2_missing_health_check_v2_export_is_abi_mismatch v2_missing_memory_export_is_abi_mismatch v2_wrong_signature_export_is_abi_mismatch`
Expected: all 4 FAIL to compile or run correctly — `validated_v2`/`compile_v2`/`compile_bytes_v2` don't exist as helpers yet if this is the first time they're added in this file (they are being added in this same step, so this actually means: expected COMPILE ERROR first). Add the three helper functions above the tests (already included in Step 1's code block), then re-run — now expect all 4 tests to FAIL at the `assert_eq!` because `compile()` doesn't yet probe for v2 exports and currently only validates `bearust_abi_version` plus the optional v1 `bearust_health_check`, so these WAT modules (which have no `bearust_health_check` export at all) will actually compile successfully today, making `unwrap_err()` panic. That panic is the expected failure signal.

- [ ] **Step 3: Implement the v2 export/memory probe in `PluginEngine::compile`**

In `src/plugin_runtime.rs`, find the block after `bearust_abi_version` is probed (around line 268-283):

```rust
        instance
            .get_typed_func::<(), i32>(&mut store, "bearust_abi_version")
            .map_err(|_| PluginError::AbiMismatch)?;
        let has_health_check =
            match instance.get_typed_func::<(), i32>(&mut store, "bearust_health_check") {
                Ok(_) => true,
                Err(_)
                    if instance
                        .get_export(&mut store, "bearust_health_check")
                        .is_none() =>
                {
                    false
                }
                Err(_) => return Err(PluginError::AbiMismatch),
            };
```

Replace it with a branch on `manifest.abi_version`:

```rust
        instance
            .get_typed_func::<(), i32>(&mut store, "bearust_abi_version")
            .map_err(|_| PluginError::AbiMismatch)?;
        let has_health_check = if manifest.abi_version == 1 {
            match instance.get_typed_func::<(), i32>(&mut store, "bearust_health_check") {
                Ok(_) => true,
                Err(_)
                    if instance
                        .get_export(&mut store, "bearust_health_check")
                        .is_none() =>
                {
                    false
                }
                Err(_) => return Err(PluginError::AbiMismatch),
            }
        } else {
            // abi_version 2: bearust_health_check is not part of this ABI.
            // Require the memory-convention exports and the guest's linear
            // memory instead, all with exact typed signatures.
            instance
                .get_memory(&mut store, "memory")
                .ok_or(PluginError::AbiMismatch)?;
            instance
                .get_typed_func::<i32, i32>(&mut store, "bearust_alloc")
                .map_err(|_| PluginError::AbiMismatch)?;
            instance
                .get_typed_func::<(i32, i32), ()>(&mut store, "bearust_dealloc")
                .map_err(|_| PluginError::AbiMismatch)?;
            instance
                .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_health_check_v2")
                .map_err(|_| PluginError::AbiMismatch)?;
            false
        };
```

`has_health_check` stays `false` for v2 plugins since it is a v1-only concept; Task 4 will branch on `self.abi_version` at invocation time rather than reusing this flag for v2.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test plugin_runtime v2_missing_alloc_export_is_abi_mismatch v2_missing_health_check_v2_export_is_abi_mismatch v2_missing_memory_export_is_abi_mismatch v2_wrong_signature_export_is_abi_mismatch`
Expected: all 4 PASS.

- [ ] **Step 5: Run the full plugin_runtime suite to confirm v1 plugins are unaffected**

Run: `cargo test --test plugin_runtime`
Expected: all tests PASS, including every pre-existing v1 test.

- [ ] **Step 6: Commit**

```bash
git add src/plugin_runtime.rs tests/plugin_runtime.rs
git commit -m "feat: validate abi_version 2 memory-convention exports at compile time"
```

---

### Task 4: `abi_version: 2` invocation path, bounded memory helpers, and `HealthResult.detail`

**Files:**
- Modify: `src/plugin_runtime.rs` (`HealthResult` struct, `CompiledPlugin::health_check`, new private helper functions)
- Create: `tests/fixtures/plugins/health_ok_v2/plugin.toml`
- Create: `tests/fixtures/plugins/health_ok_v2/health_ok_v2.wat`
- Create: `tests/fixtures/plugins/health_ok_v2/README.md`
- Test: `tests/plugin_runtime.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{pack, unpack, encode, decode, HealthCheckInput, HealthCheckOutput}` from Task 1; the compile-time export guarantee from Task 3.
- Produces (consumed by Task 5): `HealthResult` gains `pub detail: Option<String>` (`None` for `abi_version: 1` plugins, `Some`/`None` per the guest's own output for `abi_version: 2`). `PluginManager::health_check`/`health_check_without_audit` signatures are unchanged (`Result<HealthResult, PluginError>`).

- [ ] **Step 1: Add the checked-in WAT fixture**

Create `tests/fixtures/plugins/health_ok_v2/plugin.toml`:

```toml
id = "health-ok-v2"
display_name = "Deterministic health check v2"
abi_version = 2
module = "health_ok_v2.wasm"
capabilities = ["health_check"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
```

Create `tests/fixtures/plugins/health_ok_v2/health_ok_v2.wat`:

```wat
;; Deterministic Phase 13B fixture. Build with:
;;   wat2wasm health_ok_v2.wat -o health_ok_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"healthy":true,"detail":"wat-v2"}` (34 bytes) stored at
;; memory offset 0, proving the host's alloc/write/call/read/dealloc round
;; trip end to end.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22healthy\22:true,\22detail\22:\22wat-v2\22}")

  (func (export "bearust_abi_version") (result i32)
    i32.const 2)

  (func (export "bearust_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $heap_ptr
    local.set $ptr
    global.get $heap_ptr
    local.get $len
    i32.add
    global.set $heap_ptr
    local.get $ptr)

  (func (export "bearust_dealloc") (param $ptr i32) (param $len i32)
    nop)

  (func (export "bearust_health_check_v2") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 34)))))
```

Create `tests/fixtures/plugins/health_ok_v2/README.md`:

```markdown
# Deterministic v2 plugin fixture

Local-only, no-import WASM fixture for the Phase 13B `abi_version: 2`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_health_check_v2` per the memory convention in
`docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md`. It
ignores the host-supplied input and always returns a fixed JSON literal, so
the test suite can assert an exact `HealthResult.detail` value while still
exercising the full alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

- [ ] **Step 2: Write the failing end-to-end test using the fixture**

Add to `tests/plugin_runtime.rs`:

```rust
#[test]
fn v2_health_fixture_round_trips_json_over_guest_memory() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    let result = manager.health_check("health-ok-v2").unwrap();
    assert_eq!(result.status, 1);
    assert_eq!(result.detail.as_deref(), Some("wat-v2"));
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --test plugin_runtime v2_health_fixture_round_trips_json_over_guest_memory`
Expected: FAIL to compile — `HealthResult` has no `detail` field yet, and `CompiledPlugin::health_check` has no v2 branch (so even once `detail` exists, `status`/`detail` would come back wrong, e.g. `status == 0` because today's code only executes the `has_health_check` v1 branch, which is `false` for this plugin).

- [ ] **Step 4: Add the `detail` field and the bounded guest-memory helpers**

In `src/plugin_runtime.rs`, update `HealthResult` (around line 143):

```rust
/// The bounded result returned by a plugin health invocation. `detail` is
/// populated only by `abi_version: 2` plugins and is length-capped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthResult {
    pub status: i32,
    pub detail: Option<String>,
    pub elapsed: Duration,
}
```

Add a bound just below the existing `HEALTH_RESULT_BYTES` constant (near line 27):

```rust
const MAX_DETAIL_BYTES: usize = 4096;
```

Add three private helper functions right before `impl CompiledPlugin` (around line 292):

```rust
/// Validates that `ptr..ptr+len` (as claimed by a guest) lies entirely
/// within that guest's own linear memory and within `limits.max_output_bytes`.
/// A negative `ptr`/`len`, an overflowing range, or a range that would read
/// or write outside the guest's actual memory is rejected before any byte is
/// touched. Returns the validated `(start, len)` as `usize`.
fn bounded_guest_range(
    memory: &wasmtime::Memory,
    store: &impl wasmtime::AsContext,
    ptr: i32,
    len: i32,
    limits: &PluginLimits,
) -> Result<(usize, usize), PluginError> {
    if ptr < 0 || len < 0 {
        return Err(PluginError::Trap);
    }
    let len = len as usize;
    if len > limits.max_output_bytes {
        return Err(PluginError::MemoryLimit);
    }
    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(PluginError::Trap)?;
    if end > memory.data_size(store) {
        return Err(PluginError::Trap);
    }
    Ok((start, len))
}

/// Writes `bytes` into guest memory at `ptr`, after bounds-checking the
/// target range.
fn write_guest_bytes(
    memory: &wasmtime::Memory,
    store: &mut Store<StoreState>,
    ptr: i32,
    bytes: &[u8],
    limits: &PluginLimits,
) -> Result<(), PluginError> {
    let (start, len) = bounded_guest_range(memory, &*store, ptr, bytes.len() as i32, limits)?;
    debug_assert_eq!(len, bytes.len());
    memory.write(&mut *store, start, bytes).map_err(|_| PluginError::Trap)
}

/// Reads `len` bytes from guest memory at `ptr`, after bounds-checking the
/// source range.
fn read_guest_bytes(
    memory: &wasmtime::Memory,
    store: &Store<StoreState>,
    ptr: i32,
    len: i32,
    limits: &PluginLimits,
) -> Result<Vec<u8>, PluginError> {
    let (start, length) = bounded_guest_range(memory, store, ptr, len, limits)?;
    let mut buf = vec![0u8; length];
    memory.read(store, start, &mut buf).map_err(|_| PluginError::Trap)?;
    Ok(buf)
}
```

- [ ] **Step 5: Implement the v2 branch in `CompiledPlugin::health_check`**

Replace the body of `CompiledPlugin::health_check` (the closure that currently returns `Result<i32, PluginError>` and the `match result` at the end, around lines 294-337) with a version that returns `Result<(i32, Option<String>), PluginError>` from the closure and branches on `self.abi_version`:

```rust
    pub fn health_check(&self) -> Result<HealthResult, PluginError> {
        let started = Instant::now();
        // Keep the scheduler alive for the duration of this invocation.
        let _scheduler = Arc::clone(&self.scheduler);
        let mut store = new_store(&self.engine, &self.limits)?;
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| PluginError::FuelExhausted)?;
        store.set_epoch_deadline(epoch_ticks(self.limits.invocation_timeout_ms));

        let result: Result<(i32, Option<String>), PluginError> = (|| {
            let instance = Instance::new(&mut store, &self.module, &[])
                .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
            let abi = instance
                .get_typed_func::<(), i32>(&mut store, "bearust_abi_version")
                .map_err(|_| PluginError::AbiMismatch)?;
            let version = abi
                .call(&mut store, ())
                .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
            if version != self.abi_version as i32 {
                return Err(PluginError::AbiMismatch);
            }

            if self.abi_version == 2 {
                let memory = instance
                    .get_memory(&mut store, "memory")
                    .ok_or(PluginError::AbiMismatch)?;
                let alloc = instance
                    .get_typed_func::<i32, i32>(&mut store, "bearust_alloc")
                    .map_err(|_| PluginError::AbiMismatch)?;
                let dealloc = instance
                    .get_typed_func::<(i32, i32), ()>(&mut store, "bearust_dealloc")
                    .map_err(|_| PluginError::AbiMismatch)?;
                let health = instance
                    .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_health_check_v2")
                    .map_err(|_| PluginError::AbiMismatch)?;

                let input = bearust_plugin_sdk::encode(&bearust_plugin_sdk::HealthCheckInput {
                    requested_at_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
                });
                let input_len: i32 = input.len().try_into().map_err(|_| PluginError::MemoryLimit)?;
                let input_ptr = alloc
                    .call(&mut store, input_len)
                    .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
                write_guest_bytes(&memory, &mut store, input_ptr, &input, &self.limits)?;

                let packed = health
                    .call(&mut store, (input_ptr, input_len))
                    .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
                let (out_ptr, out_len) = bearust_plugin_sdk::unpack(packed);
                let bytes = read_guest_bytes(&memory, &store, out_ptr, out_len, &self.limits)?;
                dealloc
                    .call(&mut store, (out_ptr, out_len))
                    .map_err(|error| map_runtime_error(&error, started, &self.limits))?;

                let output: bearust_plugin_sdk::HealthCheckOutput =
                    bearust_plugin_sdk::decode(&bytes).map_err(|_| PluginError::Trap)?;
                let status = if output.healthy { 1 } else { 0 };
                let detail = output.detail.map(|mut d| {
                    if d.len() > MAX_DETAIL_BYTES {
                        let mut cut = MAX_DETAIL_BYTES;
                        while !d.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        d.truncate(cut);
                    }
                    d
                });
                return Ok((status, detail));
            }

            if !self.has_health_check {
                return Ok((0, None));
            }
            let health = instance
                .get_typed_func::<(), i32>(&mut store, "bearust_health_check")
                .map_err(|_| PluginError::AbiMismatch)?;
            let status = health
                .call(&mut store, ())
                .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
            Ok((status, None))
        })();

        match result {
            Ok((status, detail)) => Ok(HealthResult {
                status,
                detail,
                elapsed: started.elapsed(),
            }),
            Err(error) => Err(error),
        }
    }
```

Add `use bearust_plugin_sdk;` is not required since the crate is referenced via its full path (`bearust_plugin_sdk::...`) matching how other path-dependencies are used elsewhere in this file — but the dependency must be declared. Confirm `src/plugin_runtime.rs`'s existing `use` block does not need a new import line since the code above always qualifies with the crate name; if `cargo build` reports it's unresolved, add `use bearust_plugin_sdk;` at the top of the file's `use` block as a fallback (this is a normal one-line fix surfaced by the build, not a design change).

- [ ] **Step 6: Run the round-trip test to verify it passes**

Run: `cargo test --test plugin_runtime v2_health_fixture_round_trips_json_over_guest_memory`
Expected: PASS.

- [ ] **Step 7: Write and run the failure-path tests (malformed JSON, out-of-bounds pointer, oversized output)**

Add to `tests/plugin_runtime.rs`:

```rust
#[test]
fn v2_malformed_json_output_is_trap() {
    // health_check_v2 returns a pointer to non-JSON bytes ("xyz", 3 bytes)
    // stored at offset 0.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "xyz")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 64)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const 3)))))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash() {
    // health_check_v2 claims an absurd pointer far outside the guest's
    // single-page (65536-byte) memory.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 1000000)) (i64.const 32))
                (i64.extend_i32_u (i32.const 10)))))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_oversized_output_is_memory_limit_not_trap() {
    // Two pages (131072 bytes) of real memory so the claimed range is
    // in-bounds, but the claimed length (2000) exceeds max_output_bytes
    // (1024, from the `limits()` helper) — isolates the cap check from the
    // bounds check.
    let wat = r#"(module
        (memory (export "memory") 2)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const 2000)))))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(
        plugin.health_check().unwrap_err(),
        PluginError::MemoryLimit
    );
}

#[test]
fn v2_long_detail_is_truncated_at_a_char_boundary() {
    // "détail" repeated has multi-byte UTF-8 characters; build a >4096-byte
    // JSON detail string entirely out of a 4-byte-wide repeated codepoint so
    // any naive byte-index truncation would either panic or split a
    // character, and assert the runtime does neither.
    let long = "\u{1F600}".repeat(2000); // 4 bytes each => 8000 bytes total
    let json = format!(r#"{{"healthy":true,"detail":"{long}"}}"#);
    let json_bytes = json.into_bytes();
    let wat = format!(
        r#"(module
        (memory (export "memory") 4)
        (data (i32.const 0) "{escaped}")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 200000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const {len})))))"#,
        escaped = wat_escape(&json_bytes),
        len = json_bytes.len(),
    );
    let big_limits = PluginLimits {
        max_output_bytes: 65536,
        ..limits()
    };
    let plugin = compile_v2(&wat, big_limits).unwrap();
    let result = plugin.health_check().unwrap();
    let detail = result.detail.unwrap();
    assert!(detail.len() <= MAX_DETAIL_BYTES);
    // No panic and the string is valid UTF-8 by construction (String
    // guarantees this); the assertion above proves truncation happened
    // without needing to inspect a specific cut point.
}

fn wat_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}
```

`MAX_DETAIL_BYTES` is a private `const` in `src/plugin_runtime.rs`; add `MAX_DETAIL_BYTES` to the `use bearust::plugin_runtime::{...}` import list at the top of `tests/plugin_runtime.rs` — first change its visibility from `const MAX_DETAIL_BYTES: usize = 4096;` to `pub(crate) const MAX_DETAIL_BYTES: usize = 4096;`... but `pub(crate)` is not visible to an external integration test crate. Instead, hardcode the same literal `4096` directly in the test's assertion (`assert!(detail.len() <= 4096);`) rather than importing the constant — integration tests in `tests/` are a separate crate and can only see `pub` items. Use the literal `4096` in Step 7's last test instead of `MAX_DETAIL_BYTES`.

Run: `cargo test --test plugin_runtime v2_malformed_json_output_is_trap v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash v2_oversized_output_is_memory_limit_not_trap v2_long_detail_is_truncated_at_a_char_boundary`
Expected: all 4 PASS. If `v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash` instead fails because `1000000` happens to be in-bounds for a differently-sized memory, double check the fixture's WAT declares `(memory (export "memory") 1)` (one page = 65536 bytes), so `1000000 > 65536` is genuinely out of bounds.

- [ ] **Step 8: Run the full plugin_runtime suite**

Run: `cargo test --test plugin_runtime`
Expected: all tests PASS (v1 fixture tests unchanged, all new v2 tests passing).

- [ ] **Step 9: Commit**

```bash
git add src/plugin_runtime.rs tests/plugin_runtime.rs tests/fixtures/plugins/health_ok_v2
git commit -m "feat: implement abi_version 2 health-check invocation over guest memory"
```

---

### Task 5: Surface `detail` through the control-plane health-check response

**Files:**
- Modify: `src/control_plane/models.rs:140-146` (`PluginHealthResponse`)
- Modify: `src/control_plane/plugins.rs:257-260` (`health_check` handler)
- Test: `tests/control_plane_plugins.rs`

**Interfaces:**
- Consumes: `HealthResult.detail` from Task 4.
- Produces: `PluginHealthResponse` gains `pub detail: Option<String>`, serialized as `"detail"` in the JSON response of `GET /api/plugins/{id}/health-check`. No new endpoint, no new permission.

- [ ] **Step 1: Write the failing test**

Add to `tests/control_plane_plugins.rs`. First add a v2 fixture writer next to the existing `write_plugin` helper (around line 100):

```rust
fn write_plugin_v2(root: &Path) {
    let plugin = root.join("plugins/demo-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        r#"id = "demo-plugin-v2"
display_name = "Demo plugin v2"
abi_version = 2
module = "demo.wasm"
capabilities = ["health_check"]
[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#,
    )
    .unwrap();
    fs::write(
        plugin.join("demo.wasm"),
        wat::parse_str(
            r#"(module
      (memory (export "memory") 1)
      (data (i32.const 0) "{\22healthy\22:true,\22detail\22:\22from-api\22}")
      (func (export "bearust_abi_version") (result i32) i32.const 2)
      (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
      (func (export "bearust_dealloc") (param i32 i32))
      (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
        (i64.or
          (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
          (i64.extend_i32_u (i32.const 36)))))"#,
        )
        .unwrap(),
    )
    .unwrap();
}
```

Then add a test near the existing `admin_can_run_bounded_plugin_lifecycle` test:

```rust
#[tokio::test]
async fn health_check_response_includes_bounded_v2_detail() {
    let (app, _db, dir) = app().await;
    write_plugin_v2(dir.path());
    assert_eq!(
        json_request(
            app.clone(),
            "POST",
            "/api/setup/initialize",
            r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#,
            None
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    // Reload is a global, not per-plugin, operation: POST /api/plugins/reload
    // scans the configured plugin directory and (re)loads everything in it.
    let (status, body, _) =
        json_request(app.clone(), "POST", "/api/plugins/reload", "", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["loaded"], 1);
    let (status, body) = request(
        app.clone(),
        "POST",
        "/api/plugins/demo-plugin-v2/health-check",
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health = serde_json::from_str::<Value>(&body).unwrap();
    assert_eq!(health["status"], 1);
    assert_eq!(health["detail"], "from-api");
}
```

Route and method confirmed by reading `admin_can_run_bounded_plugin_lifecycle` directly: reload is `POST /api/plugins/reload` (global, scans the whole plugin directory — there is no per-id reload route), and health-check is `POST /api/plugins/{id}/health-check` (not `GET`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test control_plane_plugins health_check_response_includes_bounded_v2_detail`
Expected: FAIL — `PluginHealthResponse` has no `detail` field yet, so `health["detail"]` is `Value::Null`, not `"from-api"`.

- [ ] **Step 3: Add `detail` to `PluginHealthResponse` and the handler**

In `src/control_plane/models.rs` (around line 140), update:

```rust
/// Safe response for a plugin health invocation. Runtime details and module
/// paths are intentionally not exposed by the control plane. `detail` is
/// populated only for `abi_version: 2` plugins and is already length-capped
/// by the plugin runtime before it reaches this response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginHealthResponse {
    pub status: i32,
    pub elapsed_ms: u64,
    pub detail: Option<String>,
}
```

In `src/control_plane/plugins.rs` (around line 257), update the `Json(PluginHealthResponse { ... })` construction:

```rust
            Json(PluginHealthResponse {
                status: result.status,
                elapsed_ms: result.elapsed.as_millis().min(u64::MAX as u128) as u64,
                detail: result.detail,
            })
            .into_response()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test control_plane_plugins health_check_response_includes_bounded_v2_detail`
Expected: PASS.

- [ ] **Step 5: Run the full control_plane_plugins suite to confirm the v1 response shape is unaffected**

Run: `cargo test --test control_plane_plugins`
Expected: all tests PASS, including `admin_can_run_bounded_plugin_lifecycle`'s existing assertion that the v1 health response has no unexpected fields exposed (re-read that assertion; if it asserts an exact key set rather than just absence of `source_dir`/`module`, it will need `detail` added to its expected-null check — read the test body around line 171 before assuming it already tolerates a new field, and add `assert!(health["detail"].is_null());` there if that line only currently checks `source_dir`/`module`).

- [ ] **Step 6: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/plugins.rs tests/control_plane_plugins.rs
git commit -m "feat: surface abi_version 2 health detail in the plugin health-check response"
```

---

### Task 6: Final gate, docs, and wrap-up

**Files:**
- Modify: `docs/PRD.md` (Phase 13B status section, added after the existing Phase 13A section)
- Create: `docs/superpowers/reviews/phase-13b-final-review.md`

**Interfaces:** None (documentation and verification only).

- [ ] **Step 1: Run the full gate**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
DATABASE_URL=sqlite::memory: cargo test --all-targets
npm test --prefix frontend -- --run
npm run build --prefix frontend
npm run validate-locales --prefix frontend
git diff --check
```

Expected: every command PASSES. If `cargo fmt` reports differences, run `cargo fmt --all` (without `--check`) to fix them and re-run the check. If `clippy` reports new warnings introduced by this plan's code, fix them at the reported location — do not add `#[allow(...)]` without first trying to address the underlying lint.

- [ ] **Step 2: Write the Phase 13B review document**

Create `docs/superpowers/reviews/phase-13b-final-review.md` following the structure of `docs/superpowers/reviews/phase-13a-final-review.md`:

```markdown
# Phase 13B final review

Date: <fill in the actual date this step is run>

## Scope and evidence

Phase 13B adds the public `bearust-plugin-sdk` crate (`crates/bearust-plugin-sdk`)
and a JSON-over-linear-memory host/guest convention. `abi_version: 1` plugins
are unchanged; `abi_version: 2` plugins export `bearust_alloc`, `bearust_dealloc`,
and `bearust_health_check_v2`, exchanging JSON through bounds-checked guest
memory. No new plugin capability, host import, or traffic hook was added.

## Security review

| Check | Result | Evidence |
| --- | --- | --- |
| Guest pointer/length bounds | Pass | `bounded_guest_range` rejects negative values, arithmetic overflow, and any range extending past `memory.data_size`, before any read or write; covered by `v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash`. |
| Output size cap | Pass | `bounded_guest_range` rejects any claimed length over the plugin's configured `max_output_bytes` with `MemoryLimit`, independent of the bounds check; covered by `v2_oversized_output_is_memory_limit_not_trap`. |
| Malformed guest output | Pass | JSON decode failures map to `PluginError::Trap`, never a panic; covered by `v2_malformed_json_output_is_trap`. |
| `detail` truncation safety | Pass | Truncation walks back to the nearest UTF-8 char boundary before cutting, so no panic and no invalid `String`; covered by `v2_long_detail_is_truncated_at_a_char_boundary`. |
| v1 regression | Pass | Every pre-existing Phase 13A test in `tests/plugin_runtime.rs` and `tests/control_plane_plugins.rs` passes unmodified in behavior. |
| No new capability/import | Pass | `Instance::new(&mut store, &self.module, &[])` still installs zero imports; the memory convention only reads/writes the guest's own already-sandboxed linear memory. |

## Acceptance gate

```text
cargo fmt --all -- --check                              PASS
cargo clippy --all-targets -- -D warnings                PASS
DATABASE_URL=sqlite::memory: cargo test --all-targets    PASS
npm test --prefix frontend -- --run                       PASS
npm run build --prefix frontend                            PASS
npm run validate-locales --prefix frontend                 PASS
git diff --check                                            PASS
```

## Deferred scope

The `bearust-plugin-sdk` crate's guest-only unsafe pointer wrappers
(`bearust_alloc`, `bearust_dealloc`, `read_input`, `write_output`) are not
exercised by an actual `wasm32-wasip1` build in this repository's test suite;
the host-side contract they implement is instead proven against a
hand-written WAT fixture. A future increment may add an optional
`wasm32-wasip1`-target CI job to compile a real SDK-based example plugin, but
that remains out of scope here, matching the approved Phase 13B design's
non-goals.

The project-wide CSRF token contract for mutating control-plane endpoints
(noted in the Phase 13A review) remains open and unrelated to this phase's
scope.

Phase 13C (traffic hooks) and Phase 14 (registry/signatures) remain future
work, as documented in `docs/PRD.md`.
```

- [ ] **Step 3: Update the PRD's Phase 13 status**

Read `docs/PRD.md` around the current Phase 13A status section (search for `### Phase 13A status`) and add a new subsection immediately after it:

```markdown
### Phase 13B status: plugin SDK and memory conventions

Phase 13B is complete. The `bearust-plugin-sdk` crate (`crates/bearust-plugin-sdk`,
a new Cargo workspace member) implements a JSON-over-linear-memory convention
for host/guest data exchange: guest-exported `bearust_alloc`/`bearust_dealloc`
plus a packed-`i64` pointer/length return convention. The plugin runtime now
accepts `abi_version` `1` or `2`; `abi_version: 1` plugins are unchanged, and
`abi_version: 2` plugins carry a structured JSON health-check result
(`{"healthy": bool, "detail": Option<String>}`) through the new convention,
surfaced as a new optional `detail` field on the existing
`GET /api/plugins/{id}/health-check` response. Every guest-supplied
pointer/length pair is bounds-checked against the guest's actual linear
memory and against the plugin's configured `max_output_bytes` before any
host read or write; out-of-range claims trap, oversized claims hit the
existing resource-limit error, and malformed JSON never reaches the API as a
raw error. No new plugin capability, host import, or traffic hook was added.

Phase 13C is next: explicitly reviewed traffic hooks, one at a time, using
this same memory convention, with per-hook redaction, backpressure, and
fail-open/fail-closed semantics. Phase 14 remains deferred for registry
distribution and signature verification.
```

- [ ] **Step 4: Final full-repository review**

```bash
git status --short
git diff --check
```

Expected: only the files touched by Tasks 1-6 are modified/created; no stray files. `git diff --check` still passes (no trailing whitespace/conflict markers introduced by the doc edits in this task).

- [ ] **Step 5: Commit**

```bash
git add docs/PRD.md docs/superpowers/reviews/phase-13b-final-review.md
git commit -m "docs: complete phase 13b plugin sdk and memory conventions"
```

---

## Self-review notes (for the plan author, not a task)

- **Spec coverage:** memory convention (Task 4), SDK crate (Task 1), ABI version range (Task 2), compile-time export validation (Task 3), control-plane surface (Task 5), security/testing/gate (Task 4 tests + Task 6) — all six spec sections have a corresponding task.
- **Known gap carried forward on purpose, not silently:** the SDK crate's unsafe pointer wrappers have no automated `wasm32-wasip1` test in this plan, exactly matching the approved spec's non-goal; Task 6's review doc states this explicitly rather than implying full coverage.
- **Type consistency check:** `HealthResult.detail: Option<String>` (Task 4) flows unchanged into `PluginHealthResponse.detail: Option<String>` (Task 5) — same type, no conversion needed. `CompiledPlugin.abi_version: u32` (Task 2) is read as `self.abi_version` consistently in Tasks 3 and 4. `bearust_plugin_sdk::{encode, decode, pack, unpack}` signatures introduced in Task 1 are used with matching type parameters (`HealthCheckInput`/`HealthCheckOutput`) in Task 4 without modification.
