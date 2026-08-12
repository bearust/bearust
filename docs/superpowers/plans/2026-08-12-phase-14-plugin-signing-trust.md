# Phase 14 (increment 1): Plugin Manifest Signing and Trust-on-First-Use Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a plugin author cryptographically sign a plugin (manifest + wasm) and let the host verify that signature and pin trust on first use, so operators can tell a genuine, untampered plugin from an unsigned or tampered one — without any registry, fetch, or GUI work.

**Architecture:** A new `plugin.sig` sibling file (Ed25519 signature over a canonical hash of the manifest's security-relevant fields plus the wasm bytes) is checked during `PluginManager::reload_from_disk`. A new filesystem-based `TrustStore` (`trusted-keys.json`) pins each plugin ID's first-seen public key and rejects any later mismatch. A new `bearust plugin` CLI subcommand group lets authors generate a keypair and sign a plugin offline.

**Tech Stack:** Rust, `ed25519-dalek` 2.x, `rand` 0.8 (for key generation), `base64` (already a dependency), `sha2` (already a dependency), `serde`/`toml` (already dependencies).

## Global Constraints

- Signature format: `plugin.sig`, TOML, fields `algorithm` (always `"ed25519"` in this increment), `public_key` (base64), `signature` (base64).
- Signed message: 64 bytes = `SHA-256(canonical JSON of {id, abi_version, capabilities (sorted), limits})` (32 bytes) `++ SHA-256(wasm bytes)` (32 bytes). Built from the raw, unvalidated `PluginManifest` (not `ValidatedManifest`) so the CLI signer doesn't need a `PluginPolicy` — only the host verifier and the CLI both need the plugin directory's `plugin.toml` and wasm file.
- Trust store: `trusted-keys.json` at `config.directory/trusted-keys.json`, JSON map of `plugin id -> base64 public key`, written atomically (write to `trusted-keys.json.tmp` in the same directory, then `fs::rename`).
- New config flag `plugins.require_signature: bool` (`#[serde(default)]`, default `false`) — governs only *unsigned* plugins. A plugin with a `plugin.sig` present is always verified and trust-checked regardless of this flag.
- Fail-closed on every signature problem: malformed signature file, cryptographically invalid signature, or a public key that doesn't match an existing pin — all three **always** reject the plugin's load, regardless of `require_signature`. Only "no `plugin.sig` at all" is gated by the flag.
- New `PluginError` variants and their `code()` strings: `SignatureRequired` → `"signature_required"`, `MalformedSignature` → `"malformed_signature"`, `InvalidSignature` → `"invalid_signature"`, `KeyMismatch` → `"key_mismatch"`.
- **Refinement over the spec** (decided during plan-writing, not a spec change): the spec's Data Flow section says trust outcome is "carried into the plugin's entry in `ReloadSummary`". `ReloadSummary` today is only `{loaded: usize, failed: usize}` with no per-plugin entries at all — there is no per-plugin list on it to extend, and this plan does not add one (that would be unrelated scope growth). The actual per-plugin observability surface in this codebase is `PluginStatus` (returned by `PluginManager::list()`/`get()` and exposed via the control-plane API as `PluginStatusResponse`), which already carries per-plugin fields like `digest` and `last_error_code`. This plan adds `trust_status: String` (`"unsigned"` or `"trusted"`, empty string for a failed/unloaded record — matching how `digest` is already empty in that case) there instead. Also: `plugin_runtime.rs` has no `tracing::` calls anywhere today (logging happens at CLI/API call sites, not inside the manager) — this plan does not add any, consistent with the existing file's style.
- **Second refinement over the spec**: the spec's Error Handling table names a distinct `event = "plugin_trust_store_corrupt"` log line for a corrupt `trusted-keys.json`. This plan maps that condition to the existing `PluginError::Io` variant instead of adding a new one — `reload_from_disk_inner` already uses `Io` as its catch-all for every other filesystem-layer failure in the same function (a failed `fs::read_dir`, a failed `entry.file_type()`), so a corrupt trust store file failing the same way is consistent with, not a departure from, the existing error taxonomy in this file. The practical effect the spec wants — the entire reload fails loudly with an explicit error code an operator can see in logs — is preserved: `reload_from_disk_impl` (the existing caller) already logs the returned error's `code()` (`"io_error"`) on any `Err` result. No new `PluginError` variant or log event name is introduced for this specific condition.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` must all be clean before any task is considered done.
- Design spec: `docs/superpowers/specs/2026-08-12-phase-14-plugin-signing-trust-design.md` (read this first if anything below is ambiguous).

---

## Task 1: Dependencies and small type changes

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/plugin_runtime.rs` (add `Serialize` to `PluginLimits`'s derive list)
- Modify: `src/config/mod.rs` (`PluginConfig` gains `require_signature`)
- Test: `src/config/mod.rs`'s existing `#[cfg(test)] mod tests` block

**Interfaces:**
- Consumes: nothing new.
- Produces: `PluginLimits: Serialize` (consumed by Task 2's `signing_message`), `PluginConfig::require_signature: bool` (consumed by Task 4's reload wiring).

- [ ] **Step 1: Add dependencies**

In `Cargo.toml`, in the `[dependencies]` section (alongside the existing `base64 = "0.22"` and `sha2 = "0.10"` lines), add:

```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
```

- [ ] **Step 2: Make `PluginLimits` serializable**

In `src/plugin_runtime.rs`, change the import at the top of the file:

```rust
use serde::Deserialize;
```

to:

```rust
use serde::{Deserialize, Serialize};
```

Then change `PluginLimits`'s derive line:

```rust
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginLimits {
```

to:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginLimits {
```

- [ ] **Step 3: Add the failing config test**

In `src/config/mod.rs`, find the `#[cfg(test)] mod tests` block's plugin-related tests (search for `PluginConfig::default()` inside the test module) and add, in that same block:

```rust
    #[test]
    fn plugin_config_require_signature_defaults_to_false() {
        let config = PluginConfig::default();
        assert!(!config.require_signature);
    }

    #[test]
    fn plugin_config_require_signature_round_trips_through_toml() {
        let parsed: PluginConfig = toml::from_str(
            r#"
            enabled = true
            directory = "plugins"
            require_signature = true
            "#,
        )
        .unwrap();
        assert!(parsed.require_signature);
    }
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test --lib config::tests::plugin_config_require_signature -- --nocapture`
Expected: FAIL to compile — `require_signature` is not a field on `PluginConfig`.

- [ ] **Step 5: Add the field**

In `src/config/mod.rs`, in `PluginConfig`'s struct definition, add after the existing `max_output_bytes` field:

```rust
    #[serde(default = "default_plugin_max_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default)]
    pub require_signature: bool,
}
```

And in `PluginConfig`'s `Default` impl, add after the existing `max_output_bytes` line:

```rust
            max_output_bytes: default_plugin_max_output_bytes(),
            require_signature: false,
        }
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib config::tests::plugin_config_require_signature -- --nocapture`
Expected: PASS, both new tests.

- [ ] **Step 7: Run the full crate build to confirm `PluginLimits: Serialize` compiles**

Run: `cargo build --lib`
Expected: PASS (this also confirms nothing downstream broke from the derive addition — `PluginLimits` is `pub` and used across several files, but adding a derive is purely additive).

- [ ] **Step 8: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add Cargo.toml Cargo.lock src/plugin_runtime.rs src/config/mod.rs
git commit -m "feat: add plugin signing dependencies and require_signature config flag"
```

---

## Task 2: `src/plugin_signing.rs` — signing message, format, sign/verify

**Files:**
- Create: `src/plugin_signing.rs`
- Modify: `src/lib.rs` (register the new module)
- Test: inline `#[cfg(test)] mod tests` in `src/plugin_signing.rs`

**Interfaces:**
- Consumes: `crate::plugin_runtime::{PluginManifest, PluginLimits}` (Task 1's `Serialize` addition).
- Produces: `plugin_signing::{PluginSignature, SignatureError, signing_message, verify, sign}` — consumed by Task 4 (host-side verification in `plugin_runtime.rs`) and Task 5 (the CLI `sign` command).

- [ ] **Step 1: Register the module**

In `src/lib.rs`, find the existing `pub mod plugin_runtime;` line and add directly after it:

```rust
pub mod plugin_signing;
```

- [ ] **Step 2: Write the failing tests**

Create `src/plugin_signing.rs` with this content (tests first; the non-test code below the `#[cfg(test)]` block is written in Step 3 — for now, only add the `mod tests` block plus a minimal `use` line so the crate still compiles as an empty module while iterating):

```rust
//! Ed25519 signature construction and verification for plugin manifests.
//!
//! A plugin's signature covers both its manifest's security-relevant
//! fields and its compiled wasm bytes (see `signing_message`), so
//! tampering with either invalidates the signature. This module has no
//! knowledge of trust pinning (see `plugin_trust`) — it only answers "is
//! this a cryptographically valid signature for this exact manifest and
//! wasm pair", nothing about whether the signing key should be trusted.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_runtime::{PluginLimits, PluginManifest};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn sample_manifest() -> PluginManifest {
        PluginManifest {
            id: "demo-plugin".to_string(),
            display_name: "Demo".to_string(),
            abi_version: 2,
            module: "demo.wasm".to_string(),
            capabilities: vec!["health_check".to_string()],
            limits: PluginLimits {
                memory_pages: 4,
                fuel: 1000,
                invocation_timeout_ms: 100,
                max_output_bytes: 1024,
            },
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        assert_eq!(signature.algorithm, "ed25519");
        let verified = verify(&manifest, wasm_bytes, &signature).unwrap();
        assert_eq!(verified.to_bytes(), signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn tampering_with_a_manifest_field_invalidates_the_signature() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        let mut tampered = manifest;
        tampered.capabilities.push("waf.detect".to_string());
        assert_eq!(
            verify(&tampered, wasm_bytes, &signature),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn tampering_with_wasm_bytes_invalidates_the_signature() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        assert_eq!(
            verify(&manifest, b"different-wasm-bytes", &signature),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn capability_declaration_order_does_not_affect_the_signature() {
        let mut manifest_a = sample_manifest();
        manifest_a.capabilities = vec!["health_check".to_string(), "waf.detect".to_string()];
        let mut manifest_b = sample_manifest();
        manifest_b.capabilities = vec!["waf.detect".to_string(), "health_check".to_string()];
        let wasm_bytes = b"pretend-wasm-bytes";
        assert_eq!(
            signing_message(&manifest_a, wasm_bytes),
            signing_message(&manifest_b, wasm_bytes)
        );
    }

    #[test]
    fn malformed_base64_public_key_is_rejected_without_panicking() {
        let manifest = sample_manifest();
        let signature = PluginSignature {
            algorithm: "ed25519".to_string(),
            public_key: "not-valid-base64!!!".to_string(),
            signature: "AAAA".to_string(),
        };
        assert_eq!(
            verify(&manifest, b"wasm", &signature),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn wrong_length_public_key_is_rejected_without_panicking() {
        let manifest = sample_manifest();
        let signature = PluginSignature {
            algorithm: "ed25519".to_string(),
            public_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"too-short"),
            signature: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
        };
        assert_eq!(
            verify(&manifest, b"wasm", &signature),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut signature = sign(&manifest, wasm_bytes, &signing_key);
        signature.algorithm = "rsa".to_string();
        assert_eq!(
            verify(&manifest, wasm_bytes, &signature),
            Err(SignatureError::MalformedSignature)
        );
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib plugin_signing::tests`
Expected: FAIL to compile — `signing_message`, `sign`, `verify`, `PluginSignature`, `SignatureError` don't exist yet.

- [ ] **Step 4: Implement**

Add this content to `src/plugin_signing.rs`, above the `#[cfg(test)]` block:

```rust
use crate::plugin_runtime::{PluginLimits, PluginManifest};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The subset of a manifest's fields that are security-relevant and
/// therefore covered by a plugin's signature. `display_name` (cosmetic)
/// and `module` (a local filename, not the wasm content itself — the wasm
/// bytes are separately hashed by content) are deliberately excluded.
#[derive(Debug, Serialize)]
struct SignedManifestFields {
    id: String,
    abi_version: u32,
    capabilities: Vec<String>,
    limits: PluginLimits,
}

/// Builds the 64-byte message a plugin's signature covers: the manifest's
/// security-relevant fields' digest, concatenated with the wasm bytes'
/// digest. `capabilities` is sorted before serialization so declaration
/// order in `plugin.toml` never changes the signed message.
pub fn signing_message(manifest: &PluginManifest, wasm_bytes: &[u8]) -> [u8; 64] {
    let mut capabilities = manifest.capabilities.clone();
    capabilities.sort();
    let fields = SignedManifestFields {
        id: manifest.id.clone(),
        abi_version: manifest.abi_version,
        capabilities,
        limits: manifest.limits.clone(),
    };
    let manifest_json =
        serde_json::to_vec(&fields).expect("SignedManifestFields always serializes");
    let manifest_digest = Sha256::digest(&manifest_json);
    let wasm_digest = Sha256::digest(wasm_bytes);
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&manifest_digest);
    message[32..].copy_from_slice(&wasm_digest);
    message
}

/// The on-disk (`plugin.sig`, TOML) shape of a plugin's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSignature {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature file's shape, encoding, or algorithm is invalid --
    /// covers everything short of "the crypto check itself failed":
    /// unsupported algorithm, bad base64, or wrong-length decoded bytes.
    MalformedSignature,
    /// Well-formed, but the signature does not verify against the
    /// reconstructed signing message.
    InvalidSignature,
}

impl SignatureError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedSignature => "malformed_signature",
            Self::InvalidSignature => "invalid_signature",
        }
    }
}

/// Verifies `sig` against `manifest`/`wasm_bytes` and returns the
/// signature's public key on success. A valid return here means only
/// "this signature is cryptographically genuine for this exact
/// manifest+wasm pair" -- the caller is still responsible for deciding
/// whether that key should be trusted (see `plugin_trust::TrustStore`).
pub fn verify(
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    sig: &PluginSignature,
) -> Result<VerifyingKey, SignatureError> {
    if sig.algorithm != "ed25519" {
        return Err(SignatureError::MalformedSignature);
    }
    let key_bytes = BASE64
        .decode(sig.public_key.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| SignatureError::MalformedSignature)?;
    let sig_bytes = BASE64
        .decode(sig.signature.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let message = signing_message(manifest, wasm_bytes);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    Ok(verifying_key)
}

/// Signs `manifest`/`wasm_bytes` with `signing_key`, producing the
/// `plugin.sig` content. Used by the `bearust plugin sign` CLI command.
pub fn sign(manifest: &PluginManifest, wasm_bytes: &[u8], signing_key: &SigningKey) -> PluginSignature {
    let message = signing_message(manifest, wasm_bytes);
    let signature = signing_key.sign(&message);
    PluginSignature {
        algorithm: "ed25519".to_string(),
        public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
        signature: BASE64.encode(signature.to_bytes()),
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib plugin_signing::tests`
Expected: PASS, all 7 tests.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/lib.rs src/plugin_signing.rs
git commit -m "feat: add Ed25519 plugin manifest+wasm signing and verification"
```

---

## Task 3: `src/plugin_trust.rs` — trust-on-first-use store

**Files:**
- Create: `src/plugin_trust.rs`
- Modify: `src/lib.rs` (register the new module)
- Test: inline `#[cfg(test)] mod tests` in `src/plugin_trust.rs`

**Interfaces:**
- Consumes: `ed25519_dalek::VerifyingKey` (from Task 2).
- Produces: `plugin_trust::{TrustStore, TrustDecision, TrustStoreError}` — consumed by Task 4's `reload_from_disk_inner` wiring.

- [ ] **Step 1: Register the module**

In `src/lib.rs`, add directly after `pub mod plugin_signing;`:

```rust
pub mod plugin_trust;
```

- [ ] **Step 2: Write the failing tests**

Create `src/plugin_trust.rs`:

```rust
//! Filesystem-backed trust-on-first-use store for plugin signing keys.
//!
//! Maps a plugin ID to the public key it was first seen signed with. A
//! later load with a *different* key for the same ID is a `Mismatch`, not
//! silently re-pinned -- recovering from a legitimate key rotation is a
//! deliberate, manual operator action (see the design spec's Non-goals).

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn key() -> ed25519_dalek::VerifyingKey {
        SigningKey::generate(&mut OsRng).verifying_key()
    }

    #[test]
    fn first_use_pins_the_key() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        let k = key();
        assert_eq!(store.check_or_pin("demo", &k).unwrap(), TrustDecision::Trusted);
    }

    #[test]
    fn the_same_key_stays_trusted_on_a_later_check() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        let k = key();
        store.check_or_pin("demo", &k).unwrap();
        assert_eq!(store.check_or_pin("demo", &k).unwrap(), TrustDecision::Trusted);
    }

    #[test]
    fn a_different_key_for_the_same_id_is_a_mismatch() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("trusted-keys.json")).unwrap();
        store.check_or_pin("demo", &key()).unwrap();
        assert_eq!(
            store.check_or_pin("demo", &key()).unwrap(),
            TrustDecision::Mismatch
        );
    }

    #[test]
    fn a_mismatch_does_not_overwrite_the_existing_pin() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        let store = TrustStore::load(path.clone()).unwrap();
        let original = key();
        store.check_or_pin("demo", &original).unwrap();
        store.check_or_pin("demo", &key()).unwrap();

        let reloaded = TrustStore::load(path).unwrap();
        assert_eq!(
            reloaded.check_or_pin("demo", &original).unwrap(),
            TrustDecision::Trusted
        );
    }

    #[test]
    fn a_pin_survives_reloading_the_store_from_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        let k = key();
        {
            let store = TrustStore::load(path.clone()).unwrap();
            store.check_or_pin("demo", &k).unwrap();
        }
        let reloaded = TrustStore::load(path).unwrap();
        assert_eq!(reloaded.check_or_pin("demo", &k).unwrap(), TrustDecision::Trusted);
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_store() {
        let dir = tempdir().unwrap();
        let store = TrustStore::load(dir.path().join("does-not-exist.json")).unwrap();
        assert_eq!(store.check_or_pin("demo", &key()).unwrap(), TrustDecision::Trusted);
    }

    #[test]
    fn a_corrupt_file_fails_to_load_rather_than_silently_resetting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("trusted-keys.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert_eq!(TrustStore::load(path), Err(TrustStoreError::Corrupt));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib plugin_trust::tests`
Expected: FAIL to compile — `TrustStore`, `TrustDecision`, `TrustStoreError` don't exist yet.

- [ ] **Step 4: Implement**

Add this content to `src/plugin_trust.rs`, above the `#[cfg(test)]` block:

```rust
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::VerifyingKey;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Mutex,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Trusted,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStoreError {
    /// The on-disk file exists but doesn't parse. Never silently reset --
    /// every signed plugin fails to load until an operator fixes or
    /// removes the file (see the design spec's Error Handling table).
    Corrupt,
    /// The atomic write (temp file + rename) failed while pinning a new
    /// key -- disk full, permissions, etc.
    WriteFailed,
}

pub struct TrustStore {
    path: PathBuf,
    pins: Mutex<BTreeMap<String, String>>,
}

impl TrustStore {
    /// Loads the trust store from `path`. A missing file is treated as an
    /// empty store (nothing has been pinned yet); a present-but-unparseable
    /// file is `Err(TrustStoreError::Corrupt)`.
    pub fn load(path: PathBuf) -> Result<Self, TrustStoreError> {
        let pins = match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
                    .map_err(|_| TrustStoreError::Corrupt)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err(TrustStoreError::Corrupt),
        };
        Ok(Self {
            path,
            pins: Mutex::new(pins),
        })
    }

    /// Checks `key` against the pin (if any) already recorded for
    /// `plugin_id`. No prior pin: pins `key` (persisted atomically) and
    /// returns `Trusted`. Prior pin matches `key`: returns `Trusted`
    /// without writing. Prior pin differs: returns `Mismatch` -- the store
    /// is never overwritten on a mismatch.
    pub fn check_or_pin(
        &self,
        plugin_id: &str,
        key: &VerifyingKey,
    ) -> Result<TrustDecision, TrustStoreError> {
        let encoded = BASE64.encode(key.to_bytes());
        let mut pins = self.pins.lock().map_err(|_| TrustStoreError::WriteFailed)?;
        match pins.get(plugin_id) {
            Some(existing) if existing == &encoded => Ok(TrustDecision::Trusted),
            Some(_) => Ok(TrustDecision::Mismatch),
            None => {
                pins.insert(plugin_id.to_string(), encoded);
                self.persist(&pins)?;
                Ok(TrustDecision::Trusted)
            }
        }
    }

    fn persist(&self, pins: &BTreeMap<String, String>) -> Result<(), TrustStoreError> {
        let json = serde_json::to_vec_pretty(pins).map_err(|_| TrustStoreError::WriteFailed)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json).map_err(|_| TrustStoreError::WriteFailed)?;
        std::fs::rename(&tmp_path, &self.path).map_err(|_| TrustStoreError::WriteFailed)?;
        Ok(())
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib plugin_trust::tests`
Expected: PASS, all 7 tests.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/lib.rs src/plugin_trust.rs
git commit -m "feat: add filesystem-backed trust-on-first-use store for plugin signing keys"
```

---

## Task 4: Wire signature verification into `PluginManager::reload_from_disk`

**Files:**
- Modify: `src/plugin_runtime.rs`
- Modify: `src/control_plane/plugins.rs`
- Modify: `src/control_plane/models.rs`
- Create: `tests/fixtures/plugins/signed_health_v2/` (fixture directory — see Step 4)
- Test: `tests/plugin_runtime.rs`

**Interfaces:**
- Consumes: `crate::plugin_signing::{verify, PluginSignature, SignatureError}` (Task 2), `crate::plugin_trust::{TrustStore, TrustDecision, TrustStoreError}` (Task 3), `PluginConfig::require_signature` (Task 1).
- Produces: `PluginStatus::trust_status: String` and `PluginError` gains `SignatureRequired`/`MalformedSignature`/`InvalidSignature`/`KeyMismatch` variants — both consumed by Task 6 (docs only; no further tasks consume these directly).

- [ ] **Step 1: Write the failing fixture-based integration tests**

First, create the fixture directory `tests/fixtures/plugins/signed_health_v2/` with two files, reusing the existing `health_ok_v2` fixture's manifest/wat content verbatim (same shape, new directory so it doesn't collide with the existing fixture's test usage):

`tests/fixtures/plugins/signed_health_v2/plugin.toml`:

```toml
id = "signed-health-v2"
display_name = "Signed Health v2"
abi_version = 2
module = "signed_health_v2.wasm"
capabilities = ["health_check"]

[limits]
memory_pages = 4
fuel = 1000000
invocation_timeout_ms = 100
max_output_bytes = 64
```

`tests/fixtures/plugins/signed_health_v2/signed_health_v2.wat`:

```wat
;; Deterministic fixture for Phase 14 signing tests. Build with:
;;   wat2wasm signed_health_v2.wat -o signed_health_v2.wasm
;;
;; Minimal abi_version: 2 module: always reports healthy (status 1), no
;; detail. Content is irrelevant to these tests -- what's under test is
;; whether the *signature* over this exact manifest+wasm pair is accepted,
;; not the plugin's runtime behavior.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))

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
    i64.const 1))
```

Now add these tests to `tests/plugin_runtime.rs`, at the end of the file. First extend the top-of-file `use` block:

```rust
use bearust::config::PluginConfig;
use bearust::plugin_runtime::{
    module_digest, resolve_module_path, CompiledPlugin, HealthResult, PluginEngine, PluginError,
    PluginLimits, PluginManager, PluginManifest, PluginPolicy, ValidatedManifest,
};
use bearust::plugin_signing::sign;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
```

Then append at the end of the file:

```rust
fn signed_fixture_manager(
    root: &std::path::Path,
    require_signature: bool,
) -> (std::sync::Arc<PluginManager>, SigningKey) {
    let plugin = root.join("signed-health-v2");
    fs::create_dir_all(&plugin).unwrap();
    let manifest_toml = include_str!("fixtures/plugins/signed_health_v2/plugin.toml");
    fs::write(plugin.join("plugin.toml"), manifest_toml).unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/signed_health_v2/signed_health_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("signed_health_v2.wasm"), &module).unwrap();

    let manifest = PluginManifest::from_toml(manifest_toml.as_bytes()).unwrap();
    let signing_key = SigningKey::generate(&mut OsRng);
    let signature = sign(&manifest, &module, &signing_key);
    fs::write(
        plugin.join("plugin.sig"),
        toml::to_string(&signature).unwrap(),
    )
    .unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.to_path_buf(),
        require_signature,
        ..PluginConfig::default()
    });
    (manager, signing_key)
}

#[test]
fn a_validly_signed_plugin_loads_as_trusted() {
    let root = tempdir().unwrap();
    let (manager, _key) = signed_fixture_manager(root.path(), false);
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    assert_eq!(manager.list()[0].trust_status, "trusted");
}

#[test]
fn an_unsigned_plugin_loads_when_signature_is_not_required() {
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
        require_signature: false,
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    assert_eq!(manager.list()[0].trust_status, "unsigned");
}

#[test]
fn an_unsigned_plugin_is_rejected_when_signature_is_required() {
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
        require_signature: true,
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(
        manager.list()[0].last_error_code.as_deref(),
        Some("signature_required")
    );
}

#[test]
fn a_key_that_differs_from_the_pinned_key_is_rejected_even_when_signature_is_not_required() {
    let root = tempdir().unwrap();
    let (manager, _first_key) = signed_fixture_manager(root.path(), false);
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    assert_eq!(manager.list()[0].trust_status, "trusted");

    // Re-sign the same plugin directory with a *different* key, simulating
    // either a key rotation or a spoofing attempt.
    let manifest_toml = include_str!("fixtures/plugins/signed_health_v2/plugin.toml");
    let manifest = PluginManifest::from_toml(manifest_toml.as_bytes()).unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/signed_health_v2/signed_health_v2.wat"
    ))
    .unwrap();
    let other_key = SigningKey::generate(&mut OsRng);
    let other_signature = sign(&manifest, &module, &other_key);
    fs::write(
        root.path()
            .join("signed-health-v2")
            .join("plugin.sig"),
        toml::to_string(&other_signature).unwrap(),
    )
    .unwrap();

    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(
        manager.list()[0].last_error_code.as_deref(),
        Some("key_mismatch")
    );
}

#[test]
fn a_malformed_signature_file_is_rejected() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("signed-health-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/signed_health_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/signed_health_v2/signed_health_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("signed_health_v2.wasm"), &module).unwrap();
    fs::write(plugin.join("plugin.sig"), "not valid toml {{{").unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(
        manager.list()[0].last_error_code.as_deref(),
        Some("malformed_signature")
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test plugin_runtime`
Expected: FAIL to compile — `PluginStatus.trust_status` doesn't exist, `require_signature` isn't a recognized `PluginConfig` field mismatch (it exists from Task 1, so this part compiles), and `manager.list()[0].trust_status` doesn't exist.

- [ ] **Step 3: Extend `PluginError`**

In `src/plugin_runtime.rs`, extend the `PluginError` enum:

```rust
pub enum PluginError {
    InvalidManifest,
    AbiMismatch,
    Disabled,
    Timeout,
    FuelExhausted,
    MemoryLimit,
    Trap,
    CompileFailed,
    NotFound,
    DuplicateId,
    MaxPlugins,
    Io,
    SignatureRequired,
    MalformedSignature,
    InvalidSignature,
    KeyMismatch,
}
```

And its `code()` method:

```rust
            Self::Io => "io_error",
            Self::SignatureRequired => "signature_required",
            Self::MalformedSignature => "malformed_signature",
            Self::InvalidSignature => "invalid_signature",
            Self::KeyMismatch => "key_mismatch",
        }
    }
}
```

Extend `sanitize_error_code`'s allowlist (this gates which error codes are allowed to reach the audit sink):

```rust
fn sanitize_error_code(value: &str) -> Option<String> {
    let safe = matches!(
        value,
        "invalid_manifest"
            | "abi_mismatch"
            | "disabled"
            | "timeout"
            | "fuel_exhausted"
            | "memory_limit"
            | "trap"
            | "compile_failed"
            | "not_found"
            | "duplicate_id"
            | "max_plugins"
            | "io_error"
            | "partial_failure"
            | "signature_required"
            | "malformed_signature"
            | "invalid_signature"
            | "key_mismatch"
    );
    safe.then(|| value.to_owned())
}
```

- [ ] **Step 4: Add `trust_status` to `PluginStatus`**

```rust
pub struct PluginStatus {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub digest: String,
    pub enabled: bool,
    pub loaded: bool,
    pub last_error_code: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub trust_status: String,
}
```

- [ ] **Step 5: Wire verification into `reload_from_disk_inner`**

`PluginManager` does **not** get a `trust_store` field. `TrustStore` is loaded fresh from disk on every `reload_from_disk_inner` call instead of being cached on the struct — a cached-at-construction-time store would go stale: if `trusted-keys.json` becomes corrupt *after* startup, a cached store would never notice on a later reload, silently defeating the "corrupt file always fails the reload" guarantee. Loading fresh each time is cheap (a small JSON file) and keeps `TrustStore` a pure, stateless-between-calls helper — no interior mutability needed on `PluginManager` itself for this.

Add the import at the top of `src/plugin_runtime.rs`:

```rust
use crate::plugin_signing::{self, PluginSignature, SignatureError};
use crate::plugin_trust::{TrustDecision, TrustStore, TrustStoreError};
```

In `src/plugin_runtime.rs`, inside `reload_from_disk_inner`, the loop currently reads:

```rust
            let id = manifest.id.clone();
            if !seen_ids.insert(id.clone()) {
                return Err(PluginError::DuplicateId);
            }
            let old = previous.plugins.get(&id);
            let build = (|| {
                let mut policy = self.policy.clone();
                policy.module_root = child.path();
                let validated = manifest.validate(&policy)?;
                let metadata =
                    fs::metadata(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                if metadata.len() > policy.max_module_bytes as u64 {
                    return Err(PluginError::InvalidManifest);
                }
                let bytes =
                    fs::read(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                let digest = module_digest(&bytes);
                let compiled = engine.compile(validated.clone(), &bytes)?;
                Ok::<_, PluginError>((validated, digest, Arc::new(compiled)))
            })();
```

Also reload the trust store fresh on every reload cycle (rather than trusting the possibly-stale one loaded at construction), right before this loop's opening `for child in children` line — this is what actually turns a corrupt file into a hard per-reload failure per the Error Handling table, not just a construction-time fallback:

```rust
        let trust_store = TrustStore::load(directory.join("trusted-keys.json"))
            .map_err(|_| PluginError::Io)?;
```

(`directory` is already bound earlier in this function as `&self.config.directory`.)

Change the `build` closure to also resolve a trust outcome, returning it as a fourth tuple element:

```rust
            let old = previous.plugins.get(&id);
            let build = (|| {
                let mut policy = self.policy.clone();
                policy.module_root = child.path();
                let validated = manifest.validate(&policy)?;
                let metadata =
                    fs::metadata(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                if metadata.len() > policy.max_module_bytes as u64 {
                    return Err(PluginError::InvalidManifest);
                }
                let bytes =
                    fs::read(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                let trust_status = resolve_trust(
                    &manifest,
                    &bytes,
                    &child.path(),
                    self.config.require_signature,
                    &trust_store,
                )?;
                let digest = module_digest(&bytes);
                let compiled = engine.compile(validated.clone(), &bytes)?;
                Ok::<_, PluginError>((validated, digest, Arc::new(compiled), trust_status))
            })();
```

Update the two places that destructure `build`'s `Ok` variant and construct a `PluginRecord`/`PluginStatus`. The success arm:

```rust
            match build {
                Ok((validated, digest, compiled, trust_status)) => {
```

...and further down in that same arm, add `trust_status` to the `PluginStatus` literal:

```rust
                            status: PluginStatus {
                                id: validated.id,
                                display_name: validated.display_name,
                                abi_version: validated.abi_version,
                                digest,
                                enabled,
                                loaded: true,
                                last_error_code: None,
                                created_at,
                                updated_at: now,
                                trust_status,
                            },
```

The two failure-path `PluginStatus` literals (the "invalid manifest, no previous record" branch and the "build failed, no previous record" branch) each get `trust_status: String::new()` added, matching how `digest: String::new()` already appears in both:

```rust
                                    status: PluginStatus {
                                        id: safe_id,
                                        display_name: String::new(),
                                        abi_version: 0,
                                        digest: String::new(),
                                        enabled: false,
                                        loaded: false,
                                        last_error_code: Some("invalid_manifest".to_owned()),
                                        created_at: chrono::Utc::now(),
                                        updated_at: chrono::Utc::now(),
                                        trust_status: String::new(),
                                    },
```

```rust
                                status: PluginStatus {
                                    id: safe_id,
                                    display_name: safe_display_name,
                                    abi_version: manifest.abi_version,
                                    digest: String::new(),
                                    enabled: false,
                                    loaded: false,
                                    last_error_code: Some(error.code().to_string()),
                                    created_at: chrono::Utc::now(),
                                    updated_at: chrono::Utc::now(),
                                    trust_status: String::new(),
                                },
```

Now add the `resolve_trust` helper function (place it near `module_digest`, after it):

```rust
/// Resolves a plugin's trust status for this load. Returns `"trusted"` or
/// `"unsigned"` on success, or the appropriate `PluginError` (always a
/// rejection -- see the design spec's Error Handling table) on any
/// signature problem.
fn resolve_trust(
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    plugin_dir: &Path,
    require_signature: bool,
    trust_store: &TrustStore,
) -> Result<String, PluginError> {
    let sig_path = plugin_dir.join("plugin.sig");
    let sig_bytes = match fs::read(&sig_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if require_signature {
                Err(PluginError::SignatureRequired)
            } else {
                Ok("unsigned".to_string())
            };
        }
        Err(_) => return Err(PluginError::Io),
    };
    let signature: PluginSignature =
        toml::from_str(std::str::from_utf8(&sig_bytes).map_err(|_| PluginError::MalformedSignature)?)
            .map_err(|_| PluginError::MalformedSignature)?;
    let key = plugin_signing::verify(manifest, wasm_bytes, &signature).map_err(|error| {
        match error {
            SignatureError::MalformedSignature => PluginError::MalformedSignature,
            SignatureError::InvalidSignature => PluginError::InvalidSignature,
        }
    })?;
    match trust_store
        .check_or_pin(&manifest.id, &key)
        .map_err(|_: TrustStoreError| PluginError::Io)?
    {
        TrustDecision::Trusted => Ok("trusted".to_string()),
        TrustDecision::Mismatch => Err(PluginError::KeyMismatch),
    }
}
```

- [ ] **Step 6: Fix the two other `PluginRecord`/`PluginStatus` construction sites**

`reload_from_disk_inner` has exactly four `PluginStatus { ... }` literals total (two already updated in Step 6's snippets — the "no previous record, invalid manifest" one and the "no previous record, build failed" one — plus the success one from Step 6's `Ok((validated, digest, compiled, trust_status))` arm). Search the rest of `src/plugin_runtime.rs` for any other `PluginStatus {` literal (e.g. in `set_enabled_impl`/`unload`, if any exist) and add `trust_status: record.status.trust_status.clone()` (carrying the existing value forward unchanged) to each — these code paths don't re-verify a signature, they only toggle `enabled`/`loaded`, so the previously-resolved trust status is preserved as-is.

- [ ] **Step 7: Update the control-plane API mapping**

In `src/control_plane/models.rs`, add a field to `PluginStatusResponse`:

```rust
pub struct PluginStatusResponse {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub digest: String,
    pub enabled: bool,
    pub loaded: bool,
    pub last_error_code: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub trust_status: String,
}
```

In `src/control_plane/plugins.rs`, add the field to the mapping function:

```rust
fn plugin_status(status: PluginStatus) -> PluginStatusResponse {
    PluginStatusResponse {
        id: status.id,
        display_name: status.display_name,
        abi_version: status.abi_version,
        digest: status.digest,
        enabled: status.enabled,
        loaded: status.loaded,
        last_error_code: status.last_error_code,
        created_at: status.created_at,
        updated_at: status.updated_at,
        trust_status: status.trust_status,
    }
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test --test plugin_runtime`
Expected: PASS, including all 5 new tests from Step 1.

- [ ] **Step 9: Run the full workspace test suite**

Run: `cargo test --workspace --locked > /tmp/phase14-task4-full.log 2>&1` (redirect to a file rather than piping through `tail` — this environment has had multi-hour hangs from a piped `tail` never receiving EOF; read the file afterward instead)
Expected: PASS, 0 failed (aside from any already-known, unrelated flaky test — if `tests/shutdown.rs::serve_exits_promptly_on_sigterm` or a `tests/cluster_command_gateway.rs` raft-quorum timeout appears, rerun that one test file in isolation with `--locked` to confirm it's a pre-existing timing flake before treating it as real).

- [ ] **Step 10: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/plugin_runtime.rs src/plugin_trust.rs src/control_plane/models.rs src/control_plane/plugins.rs tests/plugin_runtime.rs tests/fixtures/plugins/signed_health_v2/
git commit -m "feat: verify plugin signatures and pin trust on load"
```

---

## Task 5: `bearust plugin keygen` / `bearust plugin sign` CLI

**Files:**
- Modify: `src/cli.rs`
- Test: `tests/cli_plugin_signing.rs` (new file)

**Interfaces:**
- Consumes: `crate::plugin_signing::sign` (Task 2), `crate::plugin_signing::verify` (Task 2, used by the test to confirm the CLI's output is valid), `crate::plugin_runtime::PluginManifest::from_toml` (existing).
- Produces: nothing consumed by later tasks — this is the last code task.

- [ ] **Step 1: Write the failing CLI test**

Create `tests/cli_plugin_signing.rs`:

```rust
use bearust::plugin_runtime::PluginManifest;
use bearust::plugin_signing::verify;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn bearust_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bearust")
}

#[test]
fn keygen_then_sign_produces_a_signature_the_verifier_accepts() {
    let key_dir = tempdir().unwrap();
    let keygen = Command::new(bearust_bin())
        .args(["plugin", "keygen", "--out"])
        .arg(key_dir.path())
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    assert!(key_dir.path().join("signing.key").exists());
    let printed_key = String::from_utf8(keygen.stdout).unwrap();
    assert!(!printed_key.trim().is_empty());

    let plugin_dir = tempdir().unwrap();
    fs::write(
        plugin_dir.path().join("plugin.toml"),
        r#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = ["health_check"]

[limits]
memory_pages = 4
fuel = 1000000
invocation_timeout_ms = 100
max_output_bytes = 64
"#,
    )
    .unwrap();
    fs::write(plugin_dir.path().join("demo.wasm"), b"pretend-wasm-bytes").unwrap();

    let sign = Command::new(bearust_bin())
        .args(["plugin", "sign"])
        .arg(plugin_dir.path())
        .arg("--key")
        .arg(key_dir.path().join("signing.key"))
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let sig_path = plugin_dir.path().join("plugin.sig");
    assert!(sig_path.exists());
    let sig_toml = fs::read_to_string(&sig_path).unwrap();
    let signature: bearust::plugin_signing::PluginSignature = toml::from_str(&sig_toml).unwrap();

    let manifest_bytes = fs::read(plugin_dir.path().join("plugin.toml")).unwrap();
    let manifest = PluginManifest::from_toml(&manifest_bytes).unwrap();
    let wasm_bytes = fs::read(plugin_dir.path().join("demo.wasm")).unwrap();
    assert!(verify(&manifest, &wasm_bytes, &signature).is_ok());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test cli_plugin_signing`
Expected: FAIL — `bearust plugin` is not a recognized subcommand yet (non-zero exit, clap usage error).

- [ ] **Step 3: Implement**

In `src/cli.rs`, extend the `Command` enum:

```rust
#[derive(Debug, Subcommand)]
pub enum Command {
    Serve {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        json_logs: bool,
    },
    Validate {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
    },
    Reload {
        #[arg(long, default_value = "./bearust.pid")]
        pid_file: PathBuf,
    },
    Plugin {
        #[command(subcommand)]
        action: PluginCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Generates a new Ed25519 signing keypair for signing plugins.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Signs a plugin directory's manifest + wasm module, writing plugin.sig.
    Sign {
        plugin_dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
}
```

Add a new `AppError` variant:

```rust
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Pid(#[from] reload::PidError),
    #[error("server error: {0}")]
    Server(String),
    #[error("plugin signing error: {0}")]
    PluginSigning(String),
}
```

Wire it into `run`:

```rust
pub fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Command::Validate { config: path } => {
            config::load(&path)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Reload { pid_file } => {
            reload::signal_reload(pid_file)?;
            println!("reload signal sent");
            Ok(())
        }
        Command::Serve {
            config: path,
            json_logs,
        } => serve(path, json_logs),
        Command::Plugin { action } => plugin_command(action),
    }
}
```

Add the implementation functions (near the bottom of the file is fine, alongside other free functions):

```rust
fn plugin_command(action: PluginCommand) -> Result<(), AppError> {
    match action {
        PluginCommand::Keygen { out } => plugin_keygen(&out),
        PluginCommand::Sign { plugin_dir, key } => plugin_sign(&plugin_dir, &key),
    }
}

fn plugin_keygen(out: &Path) -> Result<(), AppError> {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    std::fs::create_dir_all(out).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let key_path = out.join("signing.key");
    std::fs::write(&key_path, signing_key.to_bytes())
        .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    }
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
    println!("{public_key}");
    Ok(())
}

fn plugin_sign(plugin_dir: &Path, key_path: &Path) -> Result<(), AppError> {
    use ed25519_dalek::SigningKey;

    let key_bytes =
        std::fs::read(key_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AppError::PluginSigning("signing key has the wrong length".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let manifest_path = plugin_dir.join("plugin.toml");
    let manifest_bytes =
        std::fs::read(&manifest_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let manifest = crate::plugin_runtime::PluginManifest::from_toml(&manifest_bytes)
        .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let module_path = plugin_dir.join(&manifest.module);
    let wasm_bytes =
        std::fs::read(&module_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;

    let signature = crate::plugin_signing::sign(&manifest, &wasm_bytes, &signing_key);
    let sig_toml =
        toml::to_string(&signature).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let sig_path = plugin_dir.join("plugin.sig");
    std::fs::write(&sig_path, sig_toml).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    println!("wrote {}", sig_path.display());
    Ok(())
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --test cli_plugin_signing`
Expected: PASS.

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace --locked > /tmp/phase14-task5-full.log 2>&1` (redirect to a file, don't pipe through `tail`)
Expected: PASS, 0 failed (same caveat about pre-existing flaky tests as Task 4).

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/cli.rs tests/cli_plugin_signing.rs
git commit -m "feat: add bearust plugin keygen/sign CLI commands"
```

---

## Task 6: Documentation and final acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: nothing new — this task only documents what Tasks 1-5 built.

- [ ] **Step 1: Add the Phase 14 status section to the PRD**

Append to the end of `docs/PRD.md` (directly after the existing Phase 13G status section's closing paragraph):

```markdown

### Phase 14 status: plugin manifest signing and trust-on-first-use (increment 1)

This increment adds the trust foundation the eventual community plugin
registry will build on -- entirely filesystem-based, with no registry
service, fetch/install tooling, or GUI surface yet.

A plugin author runs `bearust plugin keygen --out <dir>` once to generate
an Ed25519 keypair, then `bearust plugin sign <plugin-dir> --key
<dir>/signing.key` to write a `plugin.sig` file alongside the plugin's
existing `plugin.toml` and wasm module. The signature covers a 64-byte
message: the SHA-256 digest of the manifest's security-relevant fields
(`id`, `abi_version`, sorted `capabilities`, `limits`) concatenated with
the SHA-256 digest of the compiled wasm bytes -- tampering with either
invalidates the signature.

On `PluginManager::reload_from_disk`, a plugin with a `plugin.sig` present
has its signature verified and its public key checked against a local,
filesystem-backed trust-on-first-use store (`trusted-keys.json`, one file
per plugins directory). The first time a plugin ID is seen with a validly
signed key, that key is pinned; the same ID showing up later with a
*different* key is always rejected (`key_mismatch`), until an operator
manually edits or removes that entry -- there is no automatic rotation or
central revocation list in this increment. A malformed or cryptographically
invalid signature is likewise always rejected, regardless of any config
flag.

The new `plugins.require_signature` config flag (default `false`) governs
only *unsigned* plugins -- when `false`, a plugin with no `plugin.sig` at
all still loads exactly as it does today, keeping every existing local/dev
plugin working unchanged. When `true`, an unsigned plugin fails to load
with `signature_required`.

Each plugin's resulting trust state (`"trusted"` or `"unsigned"`) is
exposed as a new `trust_status` field on the existing `PluginStatus` /
`PluginStatusResponse` types -- informational only in this increment, not
yet wired into any capability-selection rule (an unsigned plugin can still
be the active `waf.detect`/`transform.request`/etc. plugin when
`require_signature` is `false`).

A registry service, remote fetch/install tooling, a GUI surface for trust
state, automatic key rotation, and a centralized revocation list all
remain deliberately out of scope; see
`docs/superpowers/specs/2026-08-12-phase-14-plugin-signing-trust-design.md`
for the full rationale and follow-up increments.
```

- [ ] **Step 2: Run the final full acceptance gate**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked > /tmp/phase14-task6-full.log 2>&1` (allow up to 5 minutes; redirect to a file rather than piping through `tail`)
Expected: PASS, 0 failed

- [ ] **Step 3: Commit**

```bash
git add docs/PRD.md
git commit -m "docs: mark phase 14 plugin signing and trust increment complete"
```
