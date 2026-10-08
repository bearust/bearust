# Phase 14 increment 3: community plugin registry (static index)

## Goals

Let a Bearust operator discover and install third-party plugins without
manually locating a download URL, extracting an archive, and copying
files by hand: `bearust plugin search <query>` and
`bearust plugin install <id>`. The registry is a static, versioned JSON
index — not a hosted service Bearust must operate — and it never becomes
a new source of trust: every plugin installed through it still goes
through the exact TOFU signing/pinning flow
(`docs/superpowers/specs/2026-08-12-phase-14-plugin-signing-trust-design.md`)
that a manually-placed plugin already goes through.

## Non-goals

- No hosted backend service (API server, database, accounts) for the
  registry — the index is a static file over plain HTTPS.
- No `bearust plugin publish` command. Contributing an entry to the
  index is a manual pull request to the (separate) index repository,
  reviewed by its maintainers — not a Bearust CLI feature.
- No GUI trust surface — this is a CLI-only increment, consistent with
  `plugin keygen`/`plugin sign` from the prior increment.
- The index treating a listed plugin as pre-vetted or automatically
  trusted. Listing in the index is not an endorsement the runtime acts
  on; the runtime's only trust decisions remain signature verification
  and the TOFU pin store, both already implemented.
- Creating the actual index repository, its hosting, or its initial
  content. This plan only builds the client-side code that expects a
  specific index JSON schema (documented here) to exist somewhere
  reachable over HTTPS; standing up that repository is a manual,
  out-of-band action, not part of this implementation.
- Plugin versioning/upgrade semantics beyond "install fails if the
  target directory already exists, unless `--force`." There is no
  `bearust plugin upgrade` or dependency resolution in this increment.
- Multiple simultaneously configured index sources. One registry URL at
  a time (overridable), not a search path of several.

## Architecture

No new host import, WASI capability, or change to the WASM runtime.
Everything here is CLI-side, host-only code — `install` writes into the
plugins directory exactly like an operator copying files by hand, then
the existing `reload_from_disk_inner` path (signature verification, TOFU
pinning) runs completely unchanged the next time the operator reloads.

```
operator
  │ bearust plugin search/install
  ▼
src/plugin_registry.rs  ── fetch/parse index.json over HTTPS (reqwest)
  │
  ▼ (install only)
download tarball ── verify SHA-256 against index entry ── extract
  │
  ▼
parse plugin.toml from the extracted files (existing manifest parser)
cross-check id and, if plugin.sig is present, its signer key against
what the index entry claimed
  │
  ▼
print summary, confirm (unless --yes)
  │
  ▼
atomic write into <plugins-directory>/<id>/
  (operator still runs `POST /api/plugins/reload` afterward — install
  never talks to a running server process)
```

**Why the index is not a trust source:** the index is fetched over plain
HTTPS from a repository Bearust doesn't control the contents of beyond
review at merge time, so treating a checksum/public-key match against
the index as sufficient trust would let anyone who can get a malicious
entry merged (or anyone who can serve a spoofed index to an operator
with an overridden URL) bypass signing entirely. Instead the index's
`sha256` field only proves the downloaded bytes weren't corrupted or
tampered with in transit — a transport integrity check, not an identity
check — and its `signer_public_key` field is cross-checked against the
signature actually embedded in the downloaded tarball, so a mismatched
or absent signature is caught before any file is written. Whether that
signer is *trusted* is still decided entirely by the pre-existing TOFU
pin store the first time (or every time, for later loads) Bearust
reloads plugins from disk.

## Components

### `src/plugin_registry.rs` (new)

```rust
pub struct RegistryEntry {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub signer_public_key: Option<String>,
}

pub struct RegistryIndex {
    pub entries: Vec<RegistryEntry>,
}
```

- `RegistryIndex::fetch(url: &str) -> Result<RegistryIndex, RegistryError>`
  — blocking `reqwest` GET (the CLI is synchronous, matching
  `plugin_keygen`/`plugin_sign`'s existing style in `src/cli.rs`), parse
  JSON, bounded response size (reuse the same order-of-magnitude ceiling
  already applied to plugin signature files — a static index has no
  reason to be large; a multi-megabyte response is itself a signal
  something is wrong).
- `RegistryIndex::find(id: &str) -> Option<&RegistryEntry>`.
- `RegistryIndex::search(query: &str) -> Vec<&RegistryEntry>` — case-
  insensitive substring match over `id`, `display_name`, `description`.
- `download_and_verify(entry: &RegistryEntry) -> Result<Vec<u8>, RegistryError>`
  — GET `download_url`, compute SHA-256 over the full response body,
  compare to `entry.sha256` (constant-time comparison is unnecessary
  here — this is integrity, not a secret comparison), return the bytes
  or a `ChecksumMismatch` error before any extraction happens.
- `extract_tarball(bytes: &[u8], expected_id: &str) -> Result<ExtractedPlugin, RegistryError>`
  — decompress with `flate2`, walk entries with the `tar` crate. Reject
  the whole archive (no partial extraction) if: any entry path is
  absolute, contains `..`, or resolves outside the target directory;
  any entry isn't exactly one of `plugin.toml`, the module filename
  named inside `plugin.toml` (parsed after the manifest entry itself is
  read), or `plugin.sig`; the manifest's `id` doesn't equal
  `expected_id`. Returns the three (or two, if unsigned) file contents
  in memory — nothing touches the real plugins directory yet.
- `RegistryError` — `Fetch(reqwest::Error)`, `Parse(serde_json::Error)`,
  `NotFound(String)`, `ChecksumMismatch`, `MalformedArchive(String)`,
  `ManifestIdMismatch { expected: String, found: String }`,
  `SignerKeyMismatch`, `ResponseTooLarge`. Every variant maps to a
  distinct, human-readable CLI error message — no raw `reqwest`/`tar`
  internals leak into what the operator sees, consistent with how
  `PluginError` is already sanitized before reaching a caller.

### `src/cli.rs` (modified)

Two new `PluginCommand` variants alongside the existing `Keygen`/`Sign`:

```rust
PluginCommand::Search {
    query: String,
    registry_url: Option<String>,
},
PluginCommand::Install {
    id: String,
    registry_url: Option<String>,
    yes: bool,
    force: bool,
},
```

Registry URL resolution order: `--registry-url` flag, then
`BEARUST_PLUGIN_REGISTRY_URL` env var, then a hardcoded default constant
pointing at the official index's raw-file URL. `plugin_search()` and
`plugin_install()` functions follow the exact structure
`plugin_keygen()`/`plugin_sign()` already established: synchronous,
return `Result<(), AppError>`, a new `AppError::PluginRegistry(String)`
variant analogous to the existing `AppError::PluginSigning(String)`.

`plugin_install()`'s confirmation prompt (skipped when `yes` is true)
reads a line from stdin after printing the summary; anything other than
`y`/`yes` (case-insensitive) aborts with no files written.

### `Cargo.toml` (modified)

Two new dependencies for tarball extraction:
- `tar = "0.4"`
- `flate2 = "1"`

No new HTTP client — `reqwest` (already a dependency, `default-features
= false, features = ["json", "native-tls"]` in the main dependency
block) covers both the index fetch and the tarball download; its
blocking API needs the existing dev-dependency block's `blocking`
feature promoted into the main dependency declaration (currently
`blocking` is only enabled under `[dev-dependencies]`).

## Index JSON schema (documented here; the actual index repo is out of scope)

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
      "signer_public_key": "<base64, matches plugin.sig's key if present, or null for an unsigned entry>"
    }
  ]
}
```

`version` exists only at this index/catalog level — `plugin.toml` itself
has no version field (confirmed against `PluginManifest` in
`src/plugin_runtime.rs`), so a plugin's identity inside Bearust remains
just its `id`; the index's `version` is catalog metadata, not something
the runtime ever reads.

## Data Flow

Covered in detail during brainstorming and reproduced here for the
record:

**`bearust plugin search <query>`:** fetch index → filter by substring
match on `id`/`display_name`/`description` → print a table to stdout.

**`bearust plugin install <id> [--yes] [--force] [--registry-url <url>]`:**
fetch index → find exact `id` match (error, suggesting `search`, if
absent) → reject if `<plugins-directory>/<id>/` already exists unless
`--force` → download tarball → verify SHA-256 against the index entry,
aborting before any extraction on mismatch → extract with the
traversal/unexpected-entry checks above → parse the extracted
`plugin.toml`, cross-check its `id` against both the requested id and
the index entry's id → if `plugin.sig` is present, verify it
(`plugin_signing::verify`, already implemented — returns the signature's
`VerifyingKey` on success) and cross-check the recovered signer key
against the index entry's `signer_public_key`
→ print a summary (id, version, capabilities, signer key fingerprint)
and prompt for confirmation unless `--yes` → atomically write the
plugin directory (temp directory + rename, the same pattern
`TrustStore::persist` already uses) → print success and remind the
operator to call `POST /api/plugins/reload`. Installing is a pure
filesystem operation; it never talks to a running Bearust server
process, matching `plugin keygen`/`plugin sign`'s existing behavior.

## Error Handling

| Condition | Behavior |
|---|---|
| Index unreachable (network/DNS/TLS) | Clear error naming the URL used; no files written |
| Index JSON malformed | Clear error naming the parse failure |
| Index response larger than the size ceiling | Rejected before full parse |
| `id` not found in index | Error suggesting `bearust plugin search` |
| `<plugins-directory>/<id>/` already exists | Rejected, suggests `--force` |
| Tarball SHA-256 mismatch | Aborted before any extraction |
| Archive entry is a path-traversal attempt or an unexpected filename | Whole install rejected, no partial extraction |
| Extracted manifest `id` ≠ requested id or index entry's id | Rejected — index/tarball inconsistency |
| Extracted signature's signer key ≠ index entry's `signer_public_key` | Rejected — index misrepresents the signer |
| `plugin.sig` absent but index entry declares a `signer_public_key` | Rejected — inconsistent index entry |
| Registry URL override unreachable or malformed | Clear error naming the URL that was tried |
| Operator declines the confirmation prompt | Aborted, no files written, no error (this is the expected decline path) |

After a successful write, every existing trust/reload behavior (TOFU
pinning, `plugins.require_signature`, `key_mismatch` on a later
signer-key change) applies unmodified — `install` introduces no new
runtime code path in `src/plugin_runtime.rs`.

## Testing

- Unit: index JSON parsing (valid and malformed).
- Unit: checksum verification (mismatch rejected, confirmed no
  filesystem write occurs — e.g. via a fresh `tempfile::tempdir()`
  asserted empty afterward).
- Unit: tarball extraction rejects path traversal, absolute paths, and
  unexpected entry names, using a small hand-built malicious archive
  fixture.
- Unit: manifest-id-mismatch and signer-key-mismatch both rejected.
- Integration: a local `axum` server (already a dev-dependency) serving
  a fake index and a fake tarball; run `install` end-to-end with
  `--yes` against a `tempfile::tempdir()`-based plugins directory and
  assert the final files match exactly what was expected.
- Integration: `--force` overwrites an existing directory; without it,
  install is rejected.
- Integration: declining the confirmation prompt (simulate stdin `"n\n"`)
  leaves the plugins directory untouched.

## Follow-up increments (out of scope here)

- `bearust plugin publish` tooling to help a contributor generate an
  index entry (checksum, signer key) from a local plugin directory.
- A GUI surface in the control-plane dashboard for browsing/installing
  from the registry.
- Plugin upgrade/version-management commands.
- The actual index repository's creation, governance, and initial
  content.
