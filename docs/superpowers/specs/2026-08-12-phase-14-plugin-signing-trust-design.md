# Phase 14 (increment 1): Plugin Manifest Signing and Trust-on-First-Use — Design Spec

Status: Approved for implementation planning.

## Goals

- Give operators a way to verify a plugin's authenticity and integrity
  before trusting it, as the foundation the eventual community registry
  (a later increment) will build on.
- Establish a signature format that covers both the manifest's
  security-relevant fields (capabilities, ABI version, limits) and the
  compiled WASM bytes, so tampering with either invalidates the signature.
- Ship the minimum tooling needed to make the feature usable end to end:
  a way for plugin authors to generate a keypair and sign a plugin, and a
  way for the host to verify and pin trust on load.
- Keep existing unsigned local/dev plugins working unchanged by default.

## Non-goals

- **No registry service.** No hosted index, no remote fetch, no `install`
  command. Plugins are still distributed and placed into the plugins
  directory exactly as they are today (manually, out of band). A registry
  is a later Phase 14 increment that builds on this trust foundation.
- **No GUI surface.** Trust state is visible only through existing logs
  and the existing `ReloadSummary` — no new control-plane API or dashboard
  page in this increment.
- **No centralized revocation list.** There is no "this key is globally
  revoked" mechanism. An operator recovers from a legitimate key rotation
  by manually editing/removing the stale entry in the local trust store.
- **No automatic key rotation.** Rotating a signing key always requires
  explicit operator action (see Error Handling).
- **No multi-signer or threshold signatures.** Exactly one Ed25519
  keypair signs a given plugin.
- **No signature expiry.** A signature does not carry a timestamp or
  validity window in this increment.
- **No new ABI version, no new plugin capability.** Signing is a
  host-side, pre-load concern — the guest WASM module and the existing
  `abi_version`/capability system are completely unaffected.

## Architecture

Three new pieces, all filesystem-based, consistent with `PluginManager`'s
existing dependency-free design (it works off `config.directory` alone
today, with no database dependency):

1. **Signature format** (`plugin.sig`, a sibling file next to `plugin.toml`
   in each plugin's directory): a TOML file holding `algorithm` (always
   `"ed25519"` in this increment — the field exists so the format can grow
   without breaking), `public_key` (base64), and `signature` (base64).

2. **Signed message construction**: the message an author signs (and the
   host re-derives to verify) is the 64-byte concatenation of two SHA-256
   digests:
   - `SHA-256` of a canonical serialization of the manifest's
     security-relevant fields only: `id`, `abi_version`, `capabilities`
     (sorted), and `limits`. `display_name` and `module` (the wasm
     filename) are excluded — they're cosmetic/pointer fields, not
     security-relevant, and the wasm content itself is separately hashed
     by content, not by filename.
   - `SHA-256` of the raw compiled `.wasm` file's bytes.

   Concatenating rather than hashing-of-hashes-together keeps the
   construction simple to reproduce independently in both the signing CLI
   and the host verifier without needing a third hashing pass.

3. **Local trust store** (`trusted-keys.json`, a sibling file at the root
   of the plugins directory, i.e. `config.directory/trusted-keys.json`):
   maps `plugin id -> pinned Ed25519 public key (base64)`. Written
   atomically (write to a temp file in the same directory, then rename)
   so a crash mid-write can never leave a corrupt or partial file.

A new config flag, `plugins.require_signature` (default `false`), controls
whether a plugin with **no** `plugin.sig` at all is still allowed to load.
This is independent of trust-on-first-use: a plugin that *has* a signature
is always cryptographically verified and pinned/checked against the trust
store, regardless of this flag. The flag only decides the fate of
*unsigned* plugins.

A new CLI subcommand group, `bearust plugin`, adds the two commands needed
to actually produce a valid signature:

- `bearust plugin keygen --out <dir>` — generates an Ed25519 keypair,
  writes the private key to `<dir>/signing.key` (mode `0600`), and prints
  the public key (base64) to stdout.
- `bearust plugin sign <plugin-dir> --key <path-to-signing.key>` — reads
  the plugin's `plugin.toml` and wasm module, builds the signed message,
  signs it, and writes `<plugin-dir>/plugin.sig`.

## Components

- **`src/plugin_signing.rs`** (new module in the main binary crate, not
  the plugin SDK — this is host-side code, never compiled to WASM):
  - `struct SignedManifestFields { id: String, abi_version: u32, capabilities: Vec<String>, limits: PluginLimits }`
    — built from a `PluginManifest` with `capabilities` sorted before
    serialization, so declaration order in `plugin.toml` never affects
    the signed digest.
  - `fn signing_message(manifest: &PluginManifest, wasm_bytes: &[u8]) -> [u8; 64]`
    — the shared construction used by both the CLI signer and the host
    verifier, so there is exactly one implementation of "what gets
    signed" in the codebase.
  - `struct PluginSignature { algorithm: String, public_key: String, signature: String }`
    — the parsed `plugin.sig` shape (`#[serde(deny_unknown_fields)]`,
    matching the existing manifest parsing convention).
  - `fn verify(manifest: &PluginManifest, wasm_bytes: &[u8], sig: &PluginSignature) -> Result<VerifyingKey, SignatureError>`
    — decodes the base64 fields, reconstructs the signing message, and
    verifies the Ed25519 signature. Returns the verified public key on
    success (the caller still has to check it against the trust store —
    a cryptographically valid signature is not yet the same as "trusted").
  - `SignatureError` variants: `MalformedSignature` (bad base64, wrong
    key/signature length), `InvalidSignature` (well-formed but doesn't
    verify).

- **`TrustStore`** (new, `src/plugin_trust.rs`):
  - Loads `trusted-keys.json` once at `PluginManager` construction and
    keeps it in memory behind the same kind of interior-mutable guard the
    rest of `PluginManager` already uses for hot-reloadable state.
  - `enum TrustDecision { Trusted, Mismatch }`
  - `fn check_or_pin(&self, plugin_id: &str, key: &VerifyingKey) -> Result<TrustDecision, TrustStoreError>`
    — no existing pin for `plugin_id`: writes the new pin atomically and
    returns `Trusted`. Existing pin matches: returns `Trusted` without a
    write. Existing pin differs: returns `Mismatch` (no write — the store
    is never silently overwritten on a mismatch).
  - `TrustStoreError::Corrupt` — the on-disk file exists but doesn't
    parse; surfaced loudly (see Error Handling), never silently reset.

- **Integration point: `PluginManager::reload_from_disk_inner`** (existing
  function in `src/plugin_runtime.rs`, extended, not restructured): for
  each candidate plugin directory, after the existing manifest
  parse/validate step and before `PluginEngine::compile`, resolve a new
  `TrustOutcome` (`Unsigned`, `Trusted`, or a rejection reason) by checking
  for `plugin.sig` and running it through `plugin_signing::verify` +
  `TrustStore::check_or_pin`. A rejection short-circuits exactly like an
  existing manifest-validation failure does today — the plugin is skipped,
  the reason is recorded in `ReloadSummary`, and every other plugin in the
  directory is unaffected. `Unsigned`/`Trusted` both proceed to compile as
  today; the outcome is carried into the plugin's entry in `ReloadSummary`
  purely for observability (log line + summary field), and does not
  change any existing selection-by-capability logic (an unsigned plugin
  can still be the active `waf.detect`/`transform.request`/etc. plugin
  when `require_signature` is `false` — trust state is informational in
  this increment, not yet wired into any capability-selection rule).

- **`src/cli.rs`**: new `plugin` subcommand group (`keygen`, `sign`) as
  described in Architecture. These are local, offline, file-in/file-out
  operations — no network calls, no interaction with a running BeaRust
  instance or its config.

- **`src/config/mod.rs`**: `PluginConfig` gains `require_signature: bool`
  (`#[serde(default)]`, so existing configs without the field keep
  today's behavior).

## Data Flow

**Signing (author, offline, via CLI):**

1. Author runs `bearust plugin keygen` once, gets `signing.key` (private,
   kept by the author) and a printed public key.
2. Author writes `plugin.toml` + `<module>.wasm` as they do today.
3. Author runs `bearust plugin sign <dir> --key signing.key`; the tool
   reads the manifest and wasm, builds the signing message, signs it, and
   writes `plugin.sig` into the same directory.
4. Author distributes all three files (`plugin.toml`, `<module>.wasm`,
   `plugin.sig`) to the operator, out of band (email, a shared repo, a
   file copy) — there is no registry to publish to in this increment.

**Verification (host, on `reload_from_disk`):**

1. For each plugin subdirectory, parse and validate `plugin.toml` exactly
   as today.
2. Check for `plugin.sig`.
   - **Absent, `require_signature = false`** (default): load proceeds,
     trust outcome `Unsigned` — today's behavior, unchanged.
   - **Absent, `require_signature = true`**: load rejected, reason
     `signature_required`.
   - **Present**: read the wasm bytes, rebuild the signing message, call
     `plugin_signing::verify`.
     - Malformed (bad TOML, bad base64, wrong lengths): load rejected,
       reason `malformed_signature` — **always**, regardless of the flag.
     - Well-formed but cryptographically invalid: load rejected, reason
       `invalid_signature` — **always**.
     - Valid: call `TrustStore::check_or_pin(id, key)`.
       - No prior pin: pin this key, load proceeds, trust outcome
         `Trusted`.
       - Prior pin matches: load proceeds, trust outcome `Trusted`.
       - Prior pin differs: load rejected, reason `key_mismatch` —
         **always**, until the operator manually edits/removes that
         plugin's entry in `trusted-keys.json` (documented in the plugin
         README alongside the existing plugin-authoring docs).
3. Each plugin's trust outcome (`Unsigned` / `Trusted` / a rejection
   reason) is included in the existing `ReloadSummary` and logged the same
   way existing manifest-validation failures already are — no new
   observability surface needs to be built, this reuses what's there.

## Error Handling

| Condition | Behavior |
|---|---|
| `plugin.sig` absent, `require_signature = false` (default) | Load proceeds, outcome `Unsigned` — today's behavior, unchanged |
| `plugin.sig` absent, `require_signature = true` | Load rejected, reason `signature_required` |
| `plugin.sig` present but malformed (bad TOML, bad base64, wrong key/signature length) | Load rejected, reason `malformed_signature` — always, regardless of the flag |
| `plugin.sig` present, cryptographically invalid for the manifest+wasm pair | Load rejected, reason `invalid_signature` — always |
| `plugin.sig` valid, but its public key differs from the pin already stored for this plugin `id` | Load rejected, reason `key_mismatch` — always, until manual operator re-approval |
| `trusted-keys.json` absent or empty | Treated as an empty trust store — the next validly-signed plugin for any `id` is pinned as first-use |
| `trusted-keys.json` present but corrupt (unparseable JSON) | The **entire** trust store fails to load with an explicit error (`event = "plugin_trust_store_corrupt"`); never silently reset or overwritten — an operator must fix or remove the file before any signed plugin can load, so a corrupted store can't quietly downgrade every plugin to "first use" |
| Atomic write to `trusted-keys.json` fails (disk full, permissions) while pinning a new key | That plugin's load fails this cycle (fail-closed) — a pin is never considered applied unless the write actually succeeded; every other plugin in the directory is unaffected |

These all follow the existing `ReloadSummary` failure-isolation pattern —
one plugin's rejection never affects any other plugin's load in the same
reload cycle, so no change to that mechanism is needed.

## Testing

- **`plugin_signing.rs` unit tests**: sign→verify round trip with a test
  keypair; tampering with a manifest field (e.g. one `capabilities` entry)
  invalidates the signature; tampering with the wasm bytes invalidates the
  signature; malformed base64/wrong-length inputs return a typed error,
  never panic.
- **`plugin_trust.rs` unit tests**: first pin succeeds; same key on a
  later check stays `Trusted`; different key returns `Mismatch` without
  mutating the store; a corrupt on-disk file surfaces `Corrupt` rather
  than silently resetting; a pin survives a reload of the store from disk
  (atomicity/durability).
- **`plugin_runtime.rs` integration tests** (same checked-in WAT fixture
  pattern used by every existing capability): a validly-signed fixture
  loads as `Trusted`; an unsigned fixture loads as `Unsigned` when
  `require_signature = false`; the same unsigned fixture is rejected when
  `require_signature = true`; a fixture signed with a *different* key than
  one already pinned for its `id` is rejected even when
  `require_signature = false`.
- **CLI tests**: `bearust plugin keygen` produces a key `plugin_signing::verify`
  can be exercised against; `bearust plugin sign` run against a fixture
  directory produces a `plugin.sig` that the same verify function accepts.

## Follow-up increments

- A community registry (index format, publish/fetch flow) that plugins
  signed under this scheme can be distributed through.
- A CLI/API surface for re-approving a rotated key without hand-editing
  `trusted-keys.json`.
- Surfacing trust state in the control-plane API/GUI once there's an
  actual multi-plugin ecosystem to manage.
- Revisiting whether trust state should ever gate capability *selection*
  (e.g. "only a `Trusted` plugin may be the active `waf.detect` plugin")
  — deliberately left as informational-only in this increment.
