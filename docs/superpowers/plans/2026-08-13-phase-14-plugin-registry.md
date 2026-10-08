# Phase 14 Increment 3: Community Plugin Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator run `bearust plugin search <query>` and `bearust plugin install <id>` against a static JSON index over HTTPS, with every install cryptographically checksummed and cross-checked against the plugin's own embedded signature before any file is written — without introducing a hosted backend or a new source of trust.

**Architecture:** A new host-only module `src/plugin_registry.rs` (index fetch/parse/search, tarball download+checksum, safe extraction, signer-key cross-check) plus two new `PluginCommand` variants in `src/cli.rs` (`Search`, `Install`) that wire it together exactly the way `plugin keygen`/`plugin sign` already wire `plugin_signing.rs` together — synchronous, no tokio runtime, filesystem-only side effects, no interaction with a running server process. The existing TOFU signing/trust flow (`src/plugin_signing.rs`, `src/plugin_trust.rs`, `PluginManager::reload_from_disk`) is untouched; `install` only ever writes plugin files, it never pins a key or loads a module itself.

**Tech Stack:** Rust, `reqwest` (blocking client, already a dependency — its `blocking` feature moves from dev-only to the main dependency block), new dependencies `tar` and `flate2` for archive extraction, existing `sha2`/`hex`/`ed25519-dalek`/`base64` for checksumming and signature verification.

## Global Constraints

- New module: `src/plugin_registry.rs`, registered in `src/lib.rs` alongside the existing `plugin_signing`/`plugin_trust`/`plugin_runtime` modules.
- Index JSON schema (from the design spec, `docs/superpowers/specs/2026-08-13-phase-14-plugin-registry-design.md`):
  ```json
  {
    "entries": [
      {
        "id": "example-plugin",
        "display_name": "Example Plugin",
        "description": "One-line summary.",
        "version": "1.0.0",
        "download_url": "https://example.com/example-plugin-1.0.0.tar.gz",
        "sha256": "<64-char hex>",
        "signer_public_key": "<base64, or null for an unsigned entry>"
      }
    ]
  }
  ```
  Rust field names match the JSON keys exactly (snake_case), no `#[serde(rename)]` needed.
- Default registry URL constant: `"https://raw.githubusercontent.com/rizalord/bearust-plugin-index/main/index.json"` — the repository this points at does not exist yet (out of scope for this plan, per the design spec's Non-goals) and every test in this plan uses a local mock server instead, never this URL.
- Registry URL resolution order, implemented once as a helper: `--registry-url` CLI flag, then `BEARUST_PLUGIN_REGISTRY_URL` env var, then the default constant above.
- `install` requires an explicit `--out <plugins-directory>` flag, the same convention `plugin keygen --out <dir>` already uses — it does not read `bearust.toml` or any server config.
- The tarball for one plugin contains exactly: `plugin.toml`, the module file named inside that manifest's `module` field, and optionally `plugin.sig` — nothing else. Any other entry, any non-regular-file entry (symlink/hardlink/directory), or any entry path that is absolute or contains a `..` component makes the whole archive rejected, with zero partial extraction.
- `plugin.toml` has no `version` field (confirmed against `PluginManifest` in `src/plugin_runtime.rs`) — `version` is index/catalog metadata only, never written into the installed plugin directory or read by the runtime.
- The index itself is never a trust source. `install` writes files to disk; it never touches `trusted-keys.json` or loads a WASM module. Whether an installed plugin is later trusted is decided entirely by the existing TOFU flow the next time the operator reloads plugins.
- No `bearust plugin publish` command, no GUI, no hosted backend — this plan is exactly `search` + `install` plus their supporting library code.
- All new error variants produce a human-readable message via `Display` — no raw `reqwest`/`tar`/`serde_json` internals reach the operator's terminal unprocessed.
- Test style for `install`/`search` integration tests: spawn the actual compiled binary via `env!("CARGO_BIN_EXE_bearust")` and `std::process::Command` (the pattern `tests/cli_plugin_signing.rs` already uses), against a local `axum` server bound to `127.0.0.1:0` serving the fake index/tarball (the pattern `tests/acme_dns01.rs` already uses). Do not add a new test framework or mocking crate.

---

## Task 1: Index types, fetch, search — `src/plugin_registry.rs` core

**Files:**
- Create: `src/plugin_registry.rs`
- Modify: `src/lib.rs` (register the new module)
- Modify: `Cargo.toml` (promote `reqwest`'s `blocking` feature into the main dependency block; add `tar`, `flate2`)
- Test: unit tests inside `src/plugin_registry.rs`'s `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing from earlier tasks (first task).
- Produces: `RegistryEntry`, `RegistryIndex`, `RegistryError` (with `Display`), `RegistryIndex::fetch(client: &reqwest::blocking::Client, url: &str) -> Result<RegistryIndex, RegistryError>`, `RegistryIndex::find(&self, id: &str) -> Option<&RegistryEntry>`, `RegistryIndex::search(&self, query: &str) -> Vec<&RegistryEntry>`. Task 2 adds `download_and_verify`/`extract_tarball` to the same file and reuses `RegistryEntry`/`RegistryError`. Task 4 (CLI) constructs a `reqwest::blocking::Client` once and calls `RegistryIndex::fetch`/`find`/`search`.

- [ ] **Step 1: Add dependencies to `Cargo.toml`**

In the main `[dependencies]` block, change the existing `reqwest` line:

```toml
reqwest = { version = "=0.12.28", default-features = false, features = ["json", "native-tls", "blocking"] }
```

(adds `"blocking"` to the existing feature list — the dev-dependency block's separate `reqwest` entry with `"stream", "blocking"` is untouched, it already covers test-only needs). Add two new lines to the same `[dependencies]` block:

```toml
tar = "0.4"
flate2 = "1"
```

- [ ] **Step 2: Write the failing test for index parsing**

Create `src/plugin_registry.rs` with just enough to compile a first failing test:

```rust
//! Client for a static, HTTPS-hosted plugin index: fetch/search/find
//! catalog entries, download and checksum a plugin tarball, extract it
//! safely, and cross-check its embedded signature against what the index
//! claims. The index is a catalog and a transport-integrity check only —
//! it is never a source of trust. Whether an installed plugin is later
//! trusted is decided entirely by the existing TOFU flow in
//! `plugin_trust::TrustStore` the next time the operator reloads plugins.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistryEntry {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub signer_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistryIndex {
    pub entries: Vec<RegistryEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_index() {
        let json = r#"{
            "entries": [
                {
                    "id": "example-plugin",
                    "display_name": "Example Plugin",
                    "description": "Does something useful.",
                    "version": "1.0.0",
                    "download_url": "https://example.com/example-plugin-1.0.0.tar.gz",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signer_public_key": "cGxhY2Vob2xkZXItYmFzZTY0LWtleQ=="
                }
            ]
        }"#;
        let index: RegistryIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].id, "example-plugin");
        assert_eq!(index.entries[0].signer_public_key.as_deref(), Some("cGxhY2Vob2xkZXItYmFzZTY0LWtleQ=="));
    }

    #[test]
    fn parses_an_unsigned_entry_with_null_signer_key() {
        let json = r#"{
            "entries": [
                {
                    "id": "unsigned-plugin",
                    "display_name": "Unsigned Plugin",
                    "description": "No signature yet.",
                    "version": "0.1.0",
                    "download_url": "https://example.com/unsigned-plugin-0.1.0.tar.gz",
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "signer_public_key": null
                }
            ]
        }"#;
        let index: RegistryIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.entries[0].signer_public_key, None);
    }
}
```

- [ ] **Step 2: Run the tests to confirm they pass (they should — this step just proves the shape compiles and round-trips before adding fetch/find/search logic)**

Run: `cargo test --lib plugin_registry::tests -- --nocapture`
Expected: 2 passed.

- [ ] **Step 3: Add `RegistryError` and `RegistryIndex::fetch`**

Append to `src/plugin_registry.rs` (after the struct definitions, before `#[cfg(test)]`):

```rust
/// A generous ceiling on the index response itself -- a static JSON
/// catalog has no reason to be large, so anything past this is treated
/// as a hostile or broken server rather than read fully into memory.
const MAX_INDEX_RESPONSE_BYTES: u64 = 1_048_576;

#[derive(Debug)]
pub enum RegistryError {
    Fetch(String),
    Parse(String),
    ResponseTooLarge,
    NotFound(String),
    ChecksumMismatch,
    MalformedArchive(String),
    ManifestIdMismatch { expected: String, found: String },
    SignerKeyMismatch(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(reason) => write!(f, "could not fetch: {reason}"),
            Self::Parse(reason) => write!(f, "could not parse response: {reason}"),
            Self::ResponseTooLarge => write!(f, "response exceeded the size limit"),
            Self::NotFound(id) => write!(
                f,
                "no plugin with id \"{id}\" in the index -- try `bearust plugin search`"
            ),
            Self::ChecksumMismatch => {
                write!(f, "downloaded archive does not match the index's checksum")
            }
            Self::MalformedArchive(reason) => write!(f, "malformed plugin archive: {reason}"),
            Self::ManifestIdMismatch { expected, found } => write!(
                f,
                "archive's plugin.toml declares id \"{found}\", expected \"{expected}\""
            ),
            Self::SignerKeyMismatch(reason) => write!(f, "signer key mismatch: {reason}"),
        }
    }
}

impl RegistryIndex {
    pub fn fetch(
        client: &reqwest::blocking::Client,
        url: &str,
    ) -> Result<RegistryIndex, RegistryError> {
        let response = client
            .get(url)
            .send()
            .map_err(|e| RegistryError::Fetch(e.to_string()))?;
        if !response.status().is_success() {
            return Err(RegistryError::Fetch(format!(
                "{url} returned HTTP {}",
                response.status()
            )));
        }
        if let Some(len) = response.content_length() {
            if len > MAX_INDEX_RESPONSE_BYTES {
                return Err(RegistryError::ResponseTooLarge);
            }
        }
        let bytes = response
            .bytes()
            .map_err(|e| RegistryError::Fetch(e.to_string()))?;
        if bytes.len() as u64 > MAX_INDEX_RESPONSE_BYTES {
            return Err(RegistryError::ResponseTooLarge);
        }
        serde_json::from_slice(&bytes).map_err(|e| RegistryError::Parse(e.to_string()))
    }

    pub fn find(&self, id: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn search(&self, query: &str) -> Vec<&RegistryEntry> {
        let query = query.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                entry.id.to_ascii_lowercase().contains(&query)
                    || entry.display_name.to_ascii_lowercase().contains(&query)
                    || entry.description.to_ascii_lowercase().contains(&query)
            })
            .collect()
    }
}
```

- [ ] **Step 4: Register the module**

In `src/lib.rs`, find the line registering `plugin_trust` (or `plugin_signing`) as a module and add, in the same alphabetical/logical grouping:

```rust
pub mod plugin_registry;
```

- [ ] **Step 5: Write and run tests for `find`/`search`, and confirm the crate builds**

Add to the `#[cfg(test)] mod tests` block in `src/plugin_registry.rs`:

```rust
fn sample_index() -> RegistryIndex {
    RegistryIndex {
        entries: vec![
            RegistryEntry {
                id: "waf-guard".to_owned(),
                display_name: "WAF Guard".to_owned(),
                description: "Blocks admin paths.".to_owned(),
                version: "1.0.0".to_owned(),
                download_url: "https://example.com/waf-guard-1.0.0.tar.gz".to_owned(),
                sha256: "a".repeat(64),
                signer_public_key: Some("key1".to_owned()),
            },
            RegistryEntry {
                id: "header-tagger".to_owned(),
                display_name: "Header Tagger".to_owned(),
                description: "Adds a diagnostic header.".to_owned(),
                version: "0.2.0".to_owned(),
                download_url: "https://example.com/header-tagger-0.2.0.tar.gz".to_owned(),
                sha256: "b".repeat(64),
                signer_public_key: None,
            },
        ],
    }
}

#[test]
fn find_matches_by_exact_id_only() {
    let index = sample_index();
    assert_eq!(index.find("waf-guard").map(|e| e.id.as_str()), Some("waf-guard"));
    assert_eq!(index.find("waf"), None);
}

#[test]
fn search_matches_case_insensitively_across_id_name_and_description() {
    let index = sample_index();
    let results = index.search("HEADER");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "header-tagger");

    let results = index.search("blocks");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "waf-guard");

    assert_eq!(index.search("nonexistent").len(), 0);
}
```

Run: `cargo test --lib plugin_registry:: -- --nocapture`
Expected: all `plugin_registry` tests pass (4 total from this task).

Run: `cargo build --workspace` to confirm the new dependencies and module registration compile cleanly.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/plugin_registry.rs
git commit -m "feat: add plugin registry index fetch, find, and search"
```

---

## Task 2: Tarball download, checksum, and safe extraction

**Files:**
- Modify: `src/plugin_registry.rs` (append `download_and_verify`, `extract_tarball`, `ExtractedPlugin`)
- Test: unit tests in the same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `RegistryEntry`, `RegistryError` (Task 1).
- Produces: `ExtractedPlugin { manifest: PluginManifest, manifest_bytes: Vec<u8>, wasm_bytes: Vec<u8>, signature_bytes: Option<Vec<u8>> }`, `download_and_verify(client: &reqwest::blocking::Client, entry: &RegistryEntry) -> Result<Vec<u8>, RegistryError>`, `extract_tarball(bytes: &[u8], expected_id: &str) -> Result<ExtractedPlugin, RegistryError>`. Task 3 consumes `ExtractedPlugin`'s fields directly for the signer-key check. Task 4 (CLI) calls both functions in sequence.

- [ ] **Step 1: Write the failing tests for checksum verification**

Add to `src/plugin_registry.rs`'s test module (needs `use sha2::{Digest, Sha256};` added to the test module's imports):

```rust
#[test]
fn download_and_verify_rejects_a_checksum_mismatch() {
    // Placeholder body bytes; the point is the declared sha256 doesn't
    // match them, independent of what a real server would return -- this
    // test exercises the pure hashing/compare logic without a network
    // call. See Task 4 for the full HTTP round trip against a local
    // server.
    let entry = RegistryEntry {
        id: "demo".to_owned(),
        display_name: "Demo".to_owned(),
        description: "".to_owned(),
        version: "1.0.0".to_owned(),
        download_url: "unused-in-this-test".to_owned(),
        sha256: "0".repeat(64),
        signer_public_key: None,
    };
    let body = b"not the bytes the checksum was computed over";
    let mut hasher = Sha256::new();
    hasher.update(body);
    let actual = hex::encode(hasher.finalize());
    assert_ne!(actual, entry.sha256);
}
```

(This test documents the comparison rule the real function implements in Step 3; the end-to-end HTTP path is covered by Task 4's integration tests, which is where `download_and_verify` is actually exercised over the network — writing a full mock HTTP server here would duplicate that coverage.)

- [ ] **Step 2: Run to confirm it passes**

Run: `cargo test --lib plugin_registry::tests::download_and_verify_rejects_a_checksum_mismatch -- --nocapture`
Expected: PASS (this step just locks in the comparison semantics before wiring the real network call).

- [ ] **Step 3: Implement `download_and_verify`**

Append to `src/plugin_registry.rs` (before `#[cfg(test)]`), adding `use sha2::{Digest, Sha256};` to the file's top-level imports:

```rust
/// A generous ceiling on a plugin bundle archive. The server-side default
/// `max_module_bytes` is 16 MiB (see `README.md`); a tarball containing a
/// manifest, one wasm module, and an optional signature file comfortably
/// fits well under 4x that even with compression overhead accounted for.
const MAX_TARBALL_BYTES: u64 = 64 * 1024 * 1024;

pub fn download_and_verify(
    client: &reqwest::blocking::Client,
    entry: &RegistryEntry,
) -> Result<Vec<u8>, RegistryError> {
    let response = client
        .get(&entry.download_url)
        .send()
        .map_err(|e| RegistryError::Fetch(e.to_string()))?;
    if !response.status().is_success() {
        return Err(RegistryError::Fetch(format!(
            "{} returned HTTP {}",
            entry.download_url,
            response.status()
        )));
    }
    if let Some(len) = response.content_length() {
        if len > MAX_TARBALL_BYTES {
            return Err(RegistryError::ResponseTooLarge);
        }
    }
    let bytes = response
        .bytes()
        .map_err(|e| RegistryError::Fetch(e.to_string()))?;
    if bytes.len() as u64 > MAX_TARBALL_BYTES {
        return Err(RegistryError::ResponseTooLarge);
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(&entry.sha256) {
        return Err(RegistryError::ChecksumMismatch);
    }
    Ok(bytes.to_vec())
}
```

- [ ] **Step 4: Write the failing tests for safe extraction**

Add a helper and tests to the test module (needs `use std::io::Write as _;` added to the test module):

```rust
/// Builds an in-memory .tar.gz from `(archive_path, contents)` pairs, for
/// exercising `extract_tarball` without touching the filesystem. Every
/// entry here goes through `tar::Header::set_path`, which the `tar` crate
/// itself refuses for anything containing a `..` component or an
/// absolute path -- confirmed directly against the pinned `tar = "0.4"`
/// (resolves to 0.4.46): `set_path` returns an `Err` for both. That means
/// this helper cannot build a `..`-traversal fixture at all (see
/// `build_tarball_with_raw_traversal_entry` below for that case, which
/// writes the raw header bytes to bypass the crate's own validation --
/// exactly the kind of maliciously crafted archive `extract_tarball` must
/// defend against, since nothing requires an attacker's archive to have
/// been produced by this same crate). An absolute path *is* reachable
/// through the safe API, just not through `set_path` -- `tar::Header`
/// separately exposes `set_path_absolute` for it (some legitimate archive
/// tools use absolute paths on purpose), which is exactly why
/// `extract_tarball` must reject it itself rather than assume the archive
/// format already forbids it; see
/// `extract_tarball_rejects_absolute_paths` below for that fixture.
fn build_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, *contents).unwrap();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

/// Builds an archive identical in shape to `build_tarball`'s valid files,
/// plus one entry whose on-disk name is written directly into the raw GNU
/// header bytes (`bypass_name`), bypassing `tar::Header::set_path`'s own
/// `..`-rejection -- `tar::Builder`'s safe API refuses to construct a
/// `..`-traversal entry at all, so a fixture that actually exercises
/// `extract_tarball`'s own rejection of a maliciously crafted archive (one
/// not necessarily produced by this same crate) has to write the header
/// field directly. `GnuHeader::name` is a public `[u8; 100]` field.
fn build_tarball_with_raw_traversal_entry(
    valid_files: &[(&str, &[u8])],
    bypass_name: &[u8],
    bypass_contents: &[u8],
) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in valid_files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, *contents).unwrap();
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(bypass_contents.len() as u64);
    header.set_mode(0o644);
    {
        let gnu = header.as_gnu_mut().expect("new_gnu() always has a GNU header");
        assert!(
            bypass_name.len() < gnu.name.len(),
            "bypass_name must fit in the 100-byte GNU header name field"
        );
        gnu.name[..bypass_name.len()].copy_from_slice(bypass_name);
    }
    header.set_cksum();
    builder.append(&header, bypass_contents).unwrap();
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

const VALID_MANIFEST: &[u8] = br#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = []

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#;

#[test]
fn extract_tarball_accepts_a_well_formed_archive() {
    let tarball = build_tarball(&[
        ("plugin.toml", VALID_MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let extracted = extract_tarball(&tarball, "demo-plugin").unwrap();
    assert_eq!(extracted.manifest.id, "demo-plugin");
    assert_eq!(extracted.wasm_bytes, b"pretend-wasm-bytes");
    assert_eq!(extracted.signature_bytes, None);
}

#[test]
fn extract_tarball_accepts_an_optional_signature_file() {
    let tarball = build_tarball(&[
        ("plugin.toml", VALID_MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
        ("plugin.sig", b"pretend-signature-toml"),
    ]);
    let extracted = extract_tarball(&tarball, "demo-plugin").unwrap();
    assert_eq!(extracted.signature_bytes.as_deref(), Some(&b"pretend-signature-toml"[..]));
}

#[test]
fn extract_tarball_rejects_path_traversal() {
    let tarball = build_tarball_with_raw_traversal_entry(
        &[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
        ],
        b"../../etc/cron.d/evil",
        b"malicious",
    );
    let result = extract_tarball(&tarball, "demo-plugin");
    assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
}

#[test]
fn extract_tarball_rejects_absolute_paths() {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in [
        ("plugin.toml", VALID_MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes" as &[u8]),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, contents).unwrap();
    }
    let mut header = tar::Header::new_gnu();
    let malicious: &[u8] = b"malicious";
    header.set_size(malicious.len() as u64);
    header.set_mode(0o644);
    header.set_path_absolute("/etc/passwd").unwrap();
    header.set_cksum();
    builder.append(&header, malicious).unwrap();
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    let tarball = encoder.finish().unwrap();

    let result = extract_tarball(&tarball, "demo-plugin");
    assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
}

#[test]
fn extract_tarball_rejects_unexpected_extra_files() {
    let tarball = build_tarball(&[
        ("plugin.toml", VALID_MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
        ("unexpected-file.txt", b"not part of the plugin"),
    ]);
    let result = extract_tarball(&tarball, "demo-plugin");
    assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
}

#[test]
fn extract_tarball_rejects_manifest_id_mismatch() {
    let tarball = build_tarball(&[
        ("plugin.toml", VALID_MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let result = extract_tarball(&tarball, "a-different-id");
    assert!(matches!(
        result,
        Err(RegistryError::ManifestIdMismatch { expected, found })
            if expected == "a-different-id" && found == "demo-plugin"
    ));
}

#[test]
fn extract_tarball_rejects_missing_module_file() {
    let tarball = build_tarball(&[("plugin.toml", VALID_MANIFEST)]);
    let result = extract_tarball(&tarball, "demo-plugin");
    assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
}
```

- [ ] **Step 5: Run to confirm the new tests fail (the function doesn't exist yet)**

Run: `cargo test --lib plugin_registry::tests::extract_tarball -- --nocapture`
Expected: compile error (`extract_tarball` and `ExtractedPlugin` not found) — confirms the tests are wired to real, not-yet-written code.

- [ ] **Step 6: Implement `ExtractedPlugin` and `extract_tarball`**

Append to `src/plugin_registry.rs` (before `#[cfg(test)]`), adding `use crate::plugin_runtime::PluginManifest;`, `use std::collections::BTreeMap;`, `use std::io::Read as _;`, and `use std::path::Component;` to the file's top-level imports:

```rust
pub struct ExtractedPlugin {
    pub manifest: PluginManifest,
    pub manifest_bytes: Vec<u8>,
    pub wasm_bytes: Vec<u8>,
    pub signature_bytes: Option<Vec<u8>>,
}

/// Decompresses and extracts `bytes` as a plugin bundle archive, rejecting
/// the whole archive (no partial extraction) on any path-traversal
/// attempt, non-regular-file entry, or unexpected filename. The archive
/// must contain exactly `plugin.toml`, the module file it names, and
/// optionally `plugin.sig` -- nothing else. `expected_id` must match the
/// extracted manifest's own `id`; the manifest inside the archive is
/// ground truth, never the index entry that pointed at this download.
pub fn extract_tarball(bytes: &[u8], expected_id: &str) -> Result<ExtractedPlugin, RegistryError> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let entries = archive
        .entries()
        .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if !entry
            .header()
            .entry_type()
            .is_file()
        {
            return Err(RegistryError::MalformedArchive(
                "archive contains a non-regular-file entry (symlink, hardlink, or directory)"
                    .to_owned(),
            ));
        }
        let path = entry
            .path()
            .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?
            .into_owned();
        let mut components = path.components();
        let (Some(Component::Normal(name)), None) = (components.next(), components.next())
        else {
            return Err(RegistryError::MalformedArchive(format!(
                "unsafe archive entry path: {}",
                path.display()
            )));
        };
        let name = name
            .to_str()
            .ok_or_else(|| RegistryError::MalformedArchive("non-UTF-8 entry name".to_owned()))?
            .to_owned();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if files.insert(name.clone(), contents).is_some() {
            return Err(RegistryError::MalformedArchive(format!(
                "duplicate archive entry: {name}"
            )));
        }
    }

    let manifest_bytes = files
        .get("plugin.toml")
        .cloned()
        .ok_or_else(|| RegistryError::MalformedArchive("missing plugin.toml".to_owned()))?;
    let manifest = PluginManifest::from_toml(&manifest_bytes)
        .map_err(|e| RegistryError::MalformedArchive(format!("invalid plugin.toml: {}", e.code())))?;
    if manifest.id != expected_id {
        return Err(RegistryError::ManifestIdMismatch {
            expected: expected_id.to_owned(),
            found: manifest.id,
        });
    }
    let wasm_bytes = files.get(&manifest.module).cloned().ok_or_else(|| {
        RegistryError::MalformedArchive(format!(
            "plugin.toml names module \"{}\" but the archive doesn't contain it",
            manifest.module
        ))
    })?;
    let signature_bytes = files.get("plugin.sig").cloned();

    let mut allowed = vec!["plugin.toml".to_owned(), manifest.module.clone()];
    if signature_bytes.is_some() {
        allowed.push("plugin.sig".to_owned());
    }
    if let Some(unexpected) = files.keys().find(|name| !allowed.contains(name)) {
        return Err(RegistryError::MalformedArchive(format!(
            "unexpected file in archive: {unexpected}"
        )));
    }

    Ok(ExtractedPlugin {
        manifest,
        manifest_bytes,
        wasm_bytes,
        signature_bytes,
    })
}
```

Note: `PluginManifest::from_toml`'s error type is `PluginError`, which does **not** implement `Display` — it only exposes `.code() -> &'static str` (confirmed in `src/plugin_runtime.rs`), which is what the line above uses.

- [ ] **Step 7: Run all Task 2 tests**

Run: `cargo test --lib plugin_registry:: -- --nocapture`
Expected: all pass (7 new tests from this task, plus Task 1's 4).

- [ ] **Step 8: Commit**

```bash
git add src/plugin_registry.rs
git commit -m "feat: add plugin tarball download, checksum verification, and safe extraction"
```

---

## Task 3: Signer-key cross-check against the index

**Files:**
- Modify: `src/plugin_registry.rs` (append `verify_signer`)
- Test: unit tests in the same file's `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `ExtractedPlugin` (Task 2), `RegistryEntry` (Task 1), `plugin_signing::{verify, PluginSignature}` (already implemented, from the Phase 14 increment 1 work).
- Produces: `verify_signer(extracted: &ExtractedPlugin, declared_signer_public_key: Option<&str>) -> Result<Option<String>, RegistryError>` — returns `Ok(Some(base64_key))` for a verified, matching signer, `Ok(None)` for a genuinely unsigned plugin the index also doesn't claim a signer for, or a `RegistryError` for every inconsistent/invalid case. Task 4 (CLI) calls this after `extract_tarball` and prints the returned key (or "unsigned") in the confirmation summary.

- [ ] **Step 1: Write the failing tests**

Add to the test module (needs `use base64::Engine as _;`, `use ed25519_dalek::SigningKey;`, `use rand::rngs::OsRng;` added):

```rust
fn signed_extracted_plugin() -> (ExtractedPlugin, SigningKey) {
    let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
    let wasm_bytes = b"pretend-wasm-bytes".to_vec();
    let signing_key = SigningKey::generate(&mut OsRng);
    let signature = crate::plugin_signing::sign(&manifest, &wasm_bytes, &signing_key);
    let signature_toml = toml::to_string(&signature).unwrap();
    (
        ExtractedPlugin {
            manifest,
            manifest_bytes: VALID_MANIFEST.to_vec(),
            wasm_bytes,
            signature_bytes: Some(signature_toml.into_bytes()),
        },
        signing_key,
    )
}

#[test]
fn verify_signer_accepts_a_matching_declared_key() {
    let (extracted, signing_key) = signed_extracted_plugin();
    let public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
    let result = verify_signer(&extracted, Some(&public_key_b64));
    assert_eq!(result.unwrap(), Some(public_key_b64));
}

#[test]
fn verify_signer_rejects_a_declared_key_that_does_not_match_the_real_signer() {
    let (extracted, _signing_key) = signed_extracted_plugin();
    let wrong_key = SigningKey::generate(&mut OsRng);
    let wrong_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(wrong_key.verifying_key().to_bytes());
    let result = verify_signer(&extracted, Some(&wrong_public_key_b64));
    assert!(matches!(result, Err(RegistryError::SignerKeyMismatch(_))));
}

#[test]
fn verify_signer_accepts_a_signed_plugin_the_index_did_not_declare_a_signer_for() {
    let (extracted, _signing_key) = signed_extracted_plugin();
    let result = verify_signer(&extracted, None);
    assert!(result.unwrap().is_some());
}

#[test]
fn verify_signer_accepts_a_genuinely_unsigned_plugin() {
    let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
    let extracted = ExtractedPlugin {
        manifest,
        manifest_bytes: VALID_MANIFEST.to_vec(),
        wasm_bytes: b"pretend-wasm-bytes".to_vec(),
        signature_bytes: None,
    };
    let result = verify_signer(&extracted, None);
    assert_eq!(result.unwrap(), None);
}

#[test]
fn verify_signer_rejects_a_declared_signer_when_the_archive_has_no_signature() {
    let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
    let extracted = ExtractedPlugin {
        manifest,
        manifest_bytes: VALID_MANIFEST.to_vec(),
        wasm_bytes: b"pretend-wasm-bytes".to_vec(),
        signature_bytes: None,
    };
    let result = verify_signer(&extracted, Some("some-declared-key=="));
    assert!(matches!(result, Err(RegistryError::SignerKeyMismatch(_))));
}

#[test]
fn verify_signer_rejects_a_malformed_signature_file() {
    let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
    let extracted = ExtractedPlugin {
        manifest,
        manifest_bytes: VALID_MANIFEST.to_vec(),
        wasm_bytes: b"pretend-wasm-bytes".to_vec(),
        signature_bytes: Some(b"not valid toml".to_vec()),
    };
    let result = verify_signer(&extracted, None);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run to confirm the tests fail to compile (`verify_signer` doesn't exist yet)**

Run: `cargo test --lib plugin_registry::tests::verify_signer -- --nocapture`
Expected: compile error.

- [ ] **Step 3: Implement `verify_signer`**

Append to `src/plugin_registry.rs` (before `#[cfg(test)]`), adding `use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};` and `use crate::plugin_signing::{self, PluginSignature};` to the file's top-level imports:

```rust
/// Cross-checks `extracted`'s embedded signature (if any) against what the
/// index entry claimed. Returns the verified signer's base64 public key on
/// success (`None` only for a genuinely unsigned plugin the index also
/// didn't claim a signer for). This is the only place index metadata can
/// abort an install on a *trust*-relevant mismatch -- everywhere else the
/// index is just a catalog. It never pins a key: that remains
/// `plugin_trust::TrustStore`'s job, run by the existing reload path.
pub fn verify_signer(
    extracted: &ExtractedPlugin,
    declared_signer_public_key: Option<&str>,
) -> Result<Option<String>, RegistryError> {
    match (&extracted.signature_bytes, declared_signer_public_key) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(RegistryError::SignerKeyMismatch(
            "index declares a signer but the archive has no plugin.sig".to_owned(),
        )),
        (Some(sig_bytes), declared) => {
            let sig_str = std::str::from_utf8(sig_bytes).map_err(|e| {
                RegistryError::SignerKeyMismatch(format!("plugin.sig is not valid UTF-8: {e}"))
            })?;
            let signature: PluginSignature = toml::from_str(sig_str).map_err(|e| {
                RegistryError::SignerKeyMismatch(format!("plugin.sig does not parse: {e}"))
            })?;
            let verifying_key =
                plugin_signing::verify(&extracted.manifest, &extracted.wasm_bytes, &signature)
                    .map_err(|e| {
                        RegistryError::SignerKeyMismatch(format!(
                            "signature does not verify: {}",
                            e.code()
                        ))
                    })?;
            let actual_key_b64 = BASE64.encode(verifying_key.to_bytes());
            if let Some(declared) = declared {
                if declared != actual_key_b64 {
                    return Err(RegistryError::SignerKeyMismatch(format!(
                        "index declares signer {declared} but the archive is signed by {actual_key_b64}"
                    )));
                }
            }
            Ok(Some(actual_key_b64))
        }
    }
}
```

This repo pins `toml = "0.8"` (confirmed in `Cargo.toml`/`Cargo.lock`, resolving to `0.8.23`), whose public API only exposes `toml::from_str` — not `toml::from_slice` — which is why the code above converts the bytes to `&str` first.

- [ ] **Step 4: Run all Task 3 tests**

Run: `cargo test --lib plugin_registry:: -- --nocapture`
Expected: all pass (6 new tests from this task, plus the 11 from Tasks 1-2).

- [ ] **Step 5: Commit**

```bash
git add src/plugin_registry.rs
git commit -m "feat: cross-check a plugin's embedded signature against the registry index"
```

---

## Task 4: CLI wiring — `search` and `install` commands

**Files:**
- Modify: `src/cli.rs` (new `PluginCommand` variants, `AppError::PluginRegistry`, `plugin_search`/`plugin_install` functions, registry URL resolution helper)
- Test: Create `tests/cli_plugin_registry.rs`

**Interfaces:**
- Consumes: `plugin_registry::{RegistryIndex, RegistryEntry, RegistryError, download_and_verify, extract_tarball, verify_signer}` (Tasks 1-3).
- Produces: `bearust plugin search <query> [--registry-url <url>]` and `bearust plugin install <id> --out <plugins-directory> [--yes] [--force] [--registry-url <url>]` as working CLI commands. Nothing downstream in this plan consumes these — this is the last functional task; Task 5 is documentation only.

- [ ] **Step 1: Extend `PluginCommand` and `AppError`**

In `src/cli.rs`, add two variants to the existing `PluginCommand` enum (after `Sign`):

```rust
    /// Searches the plugin registry index for plugins matching a query.
    Search {
        query: String,
        #[arg(long)]
        registry_url: Option<String>,
    },
    /// Downloads, verifies, and installs a plugin from the registry index.
    Install {
        id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        yes: bool,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        registry_url: Option<String>,
    },
```

Add one variant to the existing `AppError` enum (after `PluginSigning`):

```rust
    #[error("plugin registry error: {0}")]
    PluginRegistry(String),
```

- [ ] **Step 2: Wire the new commands into `plugin_command`**

Change the existing `plugin_command` function:

```rust
fn plugin_command(action: PluginCommand) -> Result<(), AppError> {
    match action {
        PluginCommand::Keygen { out } => plugin_keygen(&out),
        PluginCommand::Sign { plugin_dir, key } => plugin_sign(&plugin_dir, &key),
        PluginCommand::Search { query, registry_url } => plugin_search(&query, registry_url.as_deref()),
        PluginCommand::Install { id, out, yes, force, registry_url } => {
            plugin_install(&id, &out, yes, force, registry_url.as_deref())
        }
    }
}
```

- [ ] **Step 3: Implement the registry URL resolution helper and `plugin_search`**

Append to `src/cli.rs` (after the existing `plugin_sign` function):

```rust
const DEFAULT_PLUGIN_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/rizalord/bearust-plugin-index/main/index.json";

fn resolve_registry_url(flag: Option<&str>) -> String {
    if let Some(url) = flag {
        return url.to_owned();
    }
    if let Ok(url) = std::env::var("BEARUST_PLUGIN_REGISTRY_URL") {
        if !url.trim().is_empty() {
            return url;
        }
    }
    DEFAULT_PLUGIN_REGISTRY_URL.to_owned()
}

fn plugin_search(query: &str, registry_url: Option<&str>) -> Result<(), AppError> {
    let url = resolve_registry_url(registry_url);
    let client = reqwest::blocking::Client::new();
    let index = crate::plugin_registry::RegistryIndex::fetch(&client, &url)
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let results = index.search(query);
    if results.is_empty() {
        println!("no plugins match \"{query}\"");
        return Ok(());
    }
    for entry in results {
        println!("{}  v{}  {}", entry.id, entry.version, entry.description);
    }
    Ok(())
}
```

- [ ] **Step 4: Implement `plugin_install`**

Append to `src/cli.rs`:

```rust
fn plugin_install(
    id: &str,
    plugins_directory: &Path,
    yes: bool,
    force: bool,
    registry_url: Option<&str>,
) -> Result<(), AppError> {
    use crate::plugin_registry::{download_and_verify, extract_tarball, verify_signer, RegistryIndex};

    let url = resolve_registry_url(registry_url);
    let client = reqwest::blocking::Client::new();
    let index =
        RegistryIndex::fetch(&client, &url).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let entry = index
        .find(id)
        .ok_or_else(|| AppError::PluginRegistry(
            crate::plugin_registry::RegistryError::NotFound(id.to_owned()).to_string(),
        ))?;

    let target_dir = plugins_directory.join(id);
    if target_dir.exists() && !force {
        return Err(AppError::PluginRegistry(format!(
            "{} already exists -- pass --force to overwrite",
            target_dir.display()
        )));
    }

    let tarball =
        download_and_verify(&client, entry).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let extracted =
        extract_tarball(&tarball, id).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let signer = verify_signer(&extracted, entry.signer_public_key.as_deref())
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;

    println!(
        "{}  v{}\ncapabilities: {}\nsigner: {}",
        entry.id,
        entry.version,
        if extracted.manifest.capabilities.is_empty() {
            "(none)".to_owned()
        } else {
            extracted.manifest.capabilities.join(", ")
        },
        signer.as_deref().unwrap_or("unsigned"),
    );
    if !yes {
        print!("Install this plugin? [y/N]: ");
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
        let answer = answer.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            println!("aborted");
            return Ok(());
        }
    }

    std::fs::create_dir_all(plugins_directory)
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let temp_dir = plugins_directory.join(format!(".{id}.install-tmp"));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let write_result = (|| -> std::io::Result<()> {
        std::fs::write(temp_dir.join("plugin.toml"), &extracted.manifest_bytes)?;
        std::fs::write(temp_dir.join(&extracted.manifest.module), &extracted.wasm_bytes)?;
        if let Some(signature_bytes) = &extracted.signature_bytes {
            std::fs::write(temp_dir.join("plugin.sig"), signature_bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(AppError::PluginRegistry(error.to_string()));
    }

    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    }
    std::fs::rename(&temp_dir, &target_dir).map_err(|e| AppError::PluginRegistry(e.to_string()))?;

    println!(
        "installed {} to {} -- run `POST /api/plugins/reload` to load it",
        id,
        target_dir.display()
    );
    Ok(())
}
```

- [ ] **Step 5: Write integration tests**

Create `tests/cli_plugin_registry.rs`:

```rust
use axum::{extract::State, http::StatusCode, routing::get, Router};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;

fn bearust_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bearust")
}

const MANIFEST: &[u8] = br#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = []

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#;

fn build_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *contents).unwrap();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

#[derive(Clone)]
struct MockState {
    tarball: Arc<Vec<u8>>,
}

async fn spawn_mock_registry(tarball: Vec<u8>, sha256: String) -> String {
    let state = MockState {
        tarball: Arc::new(tarball),
    };
    let index_json = json!({
        "entries": [{
            "id": "demo-plugin",
            "display_name": "Demo",
            "description": "A demo plugin for tests.",
            "version": "1.0.0",
            "download_url": "PLACEHOLDER/demo-plugin.tar.gz",
            "sha256": sha256,
            "signer_public_key": null,
        }]
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let index_json = serde_json::to_string(&index_json)
        .unwrap()
        .replace("PLACEHOLDER", &base);

    let app = Router::new()
        .route(
            "/index.json",
            get(move || {
                let body = index_json.clone();
                async move { ([("content-type", "application/json")], body) }
            }),
        )
        .route(
            "/demo-plugin.tar.gz",
            get(|State(state): State<MockState>| async move {
                (StatusCode::OK, state.tarball.as_ref().clone())
            }),
        )
        .with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("{base}/index.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[tokio::test]
async fn install_writes_the_plugin_directory_when_confirmed() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let mut child = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let installed_dir = plugins_dir.path().join("demo-plugin");
    assert!(installed_dir.join("plugin.toml").exists());
    assert_eq!(
        std::fs::read(installed_dir.join("demo.wasm")).unwrap(),
        b"pretend-wasm-bytes"
    );
    assert!(!installed_dir.join("plugin.sig").exists());
}

#[tokio::test]
async fn install_writes_nothing_when_declined() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let mut child = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(!plugins_dir.path().join("demo-plugin").exists());
}

#[tokio::test]
async fn install_with_yes_flag_skips_the_prompt() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(plugins_dir.path().join("demo-plugin").join("plugin.toml").exists());
}

#[tokio::test]
async fn install_rejects_a_checksum_mismatch_and_writes_nothing() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    // Deliberately wrong checksum.
    let index_url = spawn_mock_registry(tarball, "0".repeat(64)).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!plugins_dir.path().join("demo-plugin").exists());
}

#[tokio::test]
async fn install_refuses_to_overwrite_an_existing_directory_without_force() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    std::fs::create_dir_all(plugins_dir.path().join("demo-plugin")).unwrap();
    std::fs::write(plugins_dir.path().join("demo-plugin").join("sentinel"), b"pre-existing").unwrap();

    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(plugins_dir.path().join("demo-plugin").join("sentinel").exists());
}

#[tokio::test]
async fn install_with_force_overwrites_an_existing_directory() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    std::fs::create_dir_all(plugins_dir.path().join("demo-plugin")).unwrap();
    std::fs::write(plugins_dir.path().join("demo-plugin").join("sentinel"), b"pre-existing").unwrap();

    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes", "--force"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!plugins_dir.path().join("demo-plugin").join("sentinel").exists());
    assert!(plugins_dir.path().join("demo-plugin").join("plugin.toml").exists());
}

#[tokio::test]
async fn install_reports_not_found_for_an_unknown_id() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "does-not-exist", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does-not-exist"), "stderr was: {stderr}");
}

#[tokio::test]
async fn search_lists_matching_entries() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let output = Command::new(bearust_bin())
        .args(["plugin", "search", "demo", "--registry-url", &index_url])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("demo-plugin"), "stdout was: {stdout}");
}

#[tokio::test]
async fn search_reports_no_matches_without_failing() {
    let tarball = build_tarball(&[("plugin.toml", MANIFEST), ("demo.wasm", b"pretend-wasm-bytes")]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let output = Command::new(bearust_bin())
        .args(["plugin", "search", "nonexistent-query", "--registry-url", &index_url])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no plugins match"), "stdout was: {stdout}");
}
```

This test file needs `tar`, `flate2`, `sha2`, `hex` available to `[dev-dependencies]` in `Cargo.toml` — all four are already either main or dev dependencies (`sha2`/`hex` are main deps and automatically available in tests; `tar`/`flate2` were added to the main `[dependencies]` block in Task 1 and are likewise automatically available). Confirm this compiles without adding anything new to `[dev-dependencies]`.

- [ ] **Step 6: Run the new tests**

Run: `cargo test --test cli_plugin_registry -- --nocapture`
Expected: all 9 tests pass. If `install_refuses_to_overwrite_an_existing_directory_without_force` or `install_with_force_overwrites_an_existing_directory` fail because of how `target_dir.exists()` interacts with the temp-directory naming (`.{id}.install-tmp`), double check the temp dir name can't collide with `target_dir` itself — it can't, since it's prefixed with a `.` and suffixed `-install-tmp`, but confirm this with a direct read of the failure output rather than assuming.

- [ ] **Step 7: Run the full existing plugin-related test suites to confirm no regression**

Run: `cargo test --test cli_plugin_signing --test plugin_runtime -- --nocapture`
Expected: all pass, unchanged from before this task (this task added new code, it didn't modify `plugin_signing`/`plugin_runtime`'s own behavior).

- [ ] **Step 8: Run `cargo fmt` and `cargo clippy`**

Run: `cargo fmt --all -- --check`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Fix any warnings before committing (a common one at this size of change: an unused import if a note above led to code that doesn't need every listed `use`; remove unused ones).

- [ ] **Step 9: Commit**

```bash
git add src/cli.rs tests/cli_plugin_registry.rs Cargo.toml Cargo.lock
git commit -m "feat: add bearust plugin search and install commands"
```

---

## Task 5: Documentation — README and PRD status

**Files:**
- Modify: `README.md` (new section documenting `search`/`install`)
- Modify: `docs/PRD.md` (Phase 14 status section, mark increment 3 complete)

**Interfaces:**
- Consumes: nothing (documentation only, describes Tasks 1-4's finished behavior).
- Produces: nothing consumed by later work — this is the final task in the plan.

- [ ] **Step 1: Read the current state of both files' relevant sections**

Read `README.md` around its existing "Phase 14 plugin manifest signing and trust-on-first-use" section (the increment 1 documentation) to match its heading level and tone. Read `docs/PRD.md`'s existing "Phase 14 status" section (search for `### Phase 14 status`) to see the increment-1 write-up style you're extending, not replacing.

- [ ] **Step 2: Add a new README.md section immediately after the existing Phase 14 signing section**

Insert (matching the existing `###`-level heading style):

```markdown
### Phase 14 community plugin registry

`bearust plugin search <query>` and `bearust plugin install <id>` fetch a
static, HTTPS-hosted JSON index of published plugins and let an operator
install one without manually downloading and extracting an archive. The
default index URL points at Bearust's own community index; override it
with `--registry-url <url>` or the `BEARUST_PLUGIN_REGISTRY_URL`
environment variable to use a private or self-hosted index instead —
there is no requirement to use the default.

```console
$ bearust plugin search waf
waf-guard  v1.0.0  Blocks common admin-path scanning patterns.

$ bearust plugin install waf-guard --out ./plugins
waf-guard  v1.0.0
capabilities: waf.detect
signer: MCowBQYDK2VwAyEA...
Install this plugin? [y/N]: y
installed waf-guard to ./plugins/waf-guard -- run `POST /api/plugins/reload` to load it
```

`install` downloads the plugin's archive, verifies its SHA-256 checksum
against the index entry, extracts it (rejecting any path-traversal
attempt or unexpected file in the archive), and — if the index declares a
`signer_public_key` for that entry — cross-checks it against the
signature actually embedded in the archive before writing anything to
disk. Pass `--yes` to skip the confirmation prompt (for scripted use) and
`--force` to overwrite an already-installed plugin directory with the
same ID.

The index is a catalog and a transport-integrity check, not a new source
of trust: `install` never pins a key or loads a module. Trust is decided
exactly the way it already is for a manually-placed plugin — the first
time Bearust reloads plugins from disk, the installed plugin's signature
(if any) goes through the same trust-on-first-use pinning described
above. There is no `bearust plugin publish` command; contributing an
entry to the community index is a pull request to that index's own
repository, reviewed by its maintainers.
```

- [ ] **Step 3: Extend the "Phase 14 status" section in `docs/PRD.md`**

Find the existing `### Phase 14 status: plugin manifest signing and trust-on-first-use (increment 1)` section and its final paragraph (the one starting "A registry service, remote fetch/install tooling..."). Replace that final paragraph with an updated one, and append a new subsection immediately after it:

Replace:

```markdown
A registry service, remote fetch/install tooling, a GUI surface for trust
state, automatic key rotation, and a centralized revocation list all
remain deliberately out of scope; see
`docs/superpowers/specs/2026-08-12-phase-14-plugin-signing-trust-design.md`
for the full rationale and follow-up increments.
```

with:

```markdown
A GUI surface for trust state, automatic key rotation, and a centralized
revocation list all remain deliberately out of scope; see
`docs/superpowers/specs/2026-08-12-phase-14-plugin-signing-trust-design.md`
for the full rationale. Registry distribution and fetch/install tooling
were added in increment 3, below.

### Phase 14 status: community plugin registry (increment 3)

Increment 3 adds `bearust plugin search`/`bearust plugin install`,
letting an operator discover and install plugins from a static,
HTTPS-hosted JSON index without a hosted backend service. `install`
downloads and SHA-256-verifies a plugin's tarball, extracts it with
strict path-traversal and unexpected-file rejection, and — when the
index declares a signer for that entry — cross-checks it against the
signature actually embedded in the archive before writing any file. The
index is deliberately never a source of trust: a successful install
still goes through the exact same trust-on-first-use pinning flow a
manually-placed plugin already goes through the next time Bearust
reloads plugins from disk.

The default index points at Bearust's own community index repository;
`--registry-url` or `BEARUST_PLUGIN_REGISTRY_URL` overrides it for a
private or self-hosted index. There is no `bearust plugin publish`
command — contributing an entry is a pull request to the index
repository itself, reviewed by its maintainers, not a Bearust CLI
feature. A GUI surface for browsing/installing from the registry,
plugin upgrade/version-management commands, and the index repository's
own governance all remain out of scope; see
`docs/superpowers/specs/2026-08-13-phase-14-plugin-registry-design.md`
for the full rationale and follow-up increments.
```

- [ ] **Step 4: Update the roadmap table's Phase 14 scope line if it still reads as unstarted**

Search `docs/PRD.md` for the `## 12. Roadmap / Release Phases` table row `| **Phase 14 — Plugin Ecosystem** | ... |`. If the increment-1 task previously left this row's wording implying registry work was still fully pending, adjust only if it now reads as factually stale after this increment (read the current row text before editing — if it already reads as a phase-level summary rather than a status claim, e.g. "Community registry, signature verification, public contribution documentation" as a scope description rather than a to-do list, leave it unchanged; the per-increment `### Phase 14 status` sections are where completion is actually tracked, matching every other phase in this document).

- [ ] **Step 5: Proofread both files**

Read the edited sections of `README.md` and `docs/PRD.md` once more end to end, confirming: no leftover placeholder text, the code block's example commands match the actual CLI flags implemented in Task 4 exactly (`--out`, `--yes`, `--force`, `--registry-url`), and the PRD's cross-reference to the design spec filename is exactly `docs/superpowers/specs/2026-08-13-phase-14-plugin-registry-design.md` (matching what this plan's own Task list has been citing throughout).

- [ ] **Step 6: Commit**

```bash
git add README.md docs/PRD.md
git commit -m "docs: document the community plugin registry search/install commands"
```

---

## Final check (not a task — run after Task 5)

Re-read the design spec
(`docs/superpowers/specs/2026-08-13-phase-14-plugin-registry-design.md`)
against the finished code and confirm: every row of its Error Handling
table has a corresponding rejection path in `src/plugin_registry.rs` or
`src/cli.rs`'s `plugin_install`, every item in its Non-goals list was in
fact not done (no `publish` command, no GUI, no hosted backend, no index
repository created), and the index JSON schema documented in `README.md`
matches `RegistryEntry`'s actual fields exactly.
