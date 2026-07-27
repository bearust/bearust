# Phase 13A WASM Plugin Runtime Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, deny-by-default `wasmtime` plugin runtime with a versioned health-check ABI, bounded resources, atomic lifecycle, and authenticated admin control without adding traffic hooks.

**Architecture:** A focused `plugin_runtime` module owns manifest validation, compilation, per-call stores, resource limits, and an `ArcSwap` snapshot. The control plane exposes redacted list/load/enable/disable/unload operations through `AppState`; failures remain isolated from proxy routing. Plugin permissions and lifecycle telemetry reuse existing RBAC, audit, realtime, and Prometheus patterns.

**Tech Stack:** Rust 1.84+, Tokio, `wasmtime`, `serde`/TOML, `sha2`, `arc-swap`, Axum, SQLx, existing RBAC/audit/realtime/Prometheus infrastructure, `wat` for deterministic WASM fixtures.

## Global Constraints

- No WASI imports or host functions are available in Phase 13A.
- Only the `health_check` capability and ABI version `1` are accepted.
- Plugin modules are loaded only from the configured directory after canonical path containment validation.
- Every invocation uses a fresh bounded store with fuel, memory, duration, and output limits.
- Plugin failure must never fail, delay, or mutate the proxy request path.
- API responses, audit records, realtime events, logs, and metrics must not contain module bytes, manifest contents, secrets, or raw runtime backtraces.
- Plugin count, identifier length, manifest size, module size, and response sizes are bounded constants covered by tests.
- SQLite remains the default; migration SQL must remain compatible with the existing MySQL/PostgreSQL migration strategy.

---

### Task 1: Add runtime configuration and dependency boundary

**Files:**
- Modify: `Cargo.toml` — add the pinned `wasmtime` runtime dependency and `wat` as a dev dependency.
- Modify: `src/config/mod.rs` — add `PluginConfig` and defaults under `[plugins]`.
- Modify: `src/lib.rs` — export `plugin_runtime`.
- Modify: `tests/config_validation.rs` — add parsing/default/upper-bound tests.

**Interfaces:**
- Produces `Config.plugins: PluginConfig` with `enabled: bool`, `directory: PathBuf`, `max_plugins: usize`, `max_module_bytes: usize`, `max_memory_pages: u32`, `max_fuel: u64`, `invocation_timeout_ms: u64`, and `max_output_bytes: usize`.
- `PluginConfig::validate()` rejects zero limits, values above server maxima, and a directory string that is empty when `enabled = true`.

- [ ] **Step 1: Write failing configuration tests** for omitted `[plugins]`, valid TOML, zero limits, oversized limits, and `enabled = true` with an empty path.
- [ ] **Step 2: Run `cargo +stable test --test config_validation plugins`** and verify the new tests fail because the type/config field is absent.
- [ ] **Step 3: Add the dependency, config type, serde defaults, validation, and module export.** Keep defaults disabled and conservative; do not read the filesystem during config parsing.
- [ ] **Step 4: Run `cargo +stable fmt --all -- --check && cargo +stable test --test config_validation`**; expect PASS.
- [ ] **Step 5: Commit** `feat: add phase 13a plugin configuration`.

### Task 2: Implement manifest parsing, path containment, and safe error codes

**Files:**
- Create: `src/plugin_runtime.rs` — manifest structs, constants, validation errors, digest helper, and path resolver.
- Create: `tests/plugin_runtime.rs` — parser/path/digest tests.
- Modify: `src/lib.rs` — export any public runtime types needed by tests/control plane.

**Interfaces:**
- `PluginManifest::from_toml(bytes: &[u8]) -> Result<Self, PluginError>`.
- `PluginManifest::validate(&self, policy: &PluginPolicy) -> Result<ValidatedManifest, PluginError>`.
- `resolve_module_path(root: &Path, relative: &str) -> Result<PathBuf, PluginError>`.
- `module_digest(bytes: &[u8]) -> String` returns lowercase fixed-length SHA-256 hex.
- `PluginError::code() -> &'static str` returns only the stable codes from the design.

- [ ] **Step 1: Write failing tests** for valid manifest, unknown TOML field, uppercase/empty ID, duplicate/unknown capability, unsupported ABI, path traversal, absolute path, symlink escape, oversized declared limits, missing module, and stable digest.
- [ ] **Step 2: Run `cargo +stable test --test plugin_runtime manifest`** and verify failure.
- [ ] **Step 3: Implement deny-by-default manifest validation** with `#[serde(deny_unknown_fields)]`, lowercase kebab-case identifier validation, capability allow-list, bounded strings, and canonical path containment. Do not include raw TOML or filesystem paths in `Display` output.
- [ ] **Step 4: Run the focused tests and `cargo +stable clippy --test plugin_runtime -- -D warnings`**; expect PASS.
- [ ] **Step 5: Commit** `feat: validate wasm plugin manifests`.

### Task 3: Build the bounded WASM engine and versioned health ABI

**Files:**
- Modify: `src/plugin_runtime.rs` — engine creation, module compilation, store limits, ABI calls, and timeout/fuel mapping.
- Modify: `tests/plugin_runtime.rs` — deterministic WAT modules and resource tests.

**Interfaces:**
- `PluginEngine::new(policy: PluginPolicy) -> Result<Self, PluginError>`.
- `PluginEngine::compile(&self, manifest: ValidatedManifest, module_bytes: &[u8]) -> Result<CompiledPlugin, PluginError>`.
- `CompiledPlugin::health_check(&self) -> Result<HealthResult, PluginError>`.
- `HealthResult` contains only bounded integer status and elapsed duration.

- [ ] **Step 1: Add failing WAT-backed tests** for ABI version `1`, optional health export, missing ABI export, wrong export signature, invalid WASM, fuel exhaustion, memory growth beyond the limit, timeout, trap, and successful bounded status.
- [ ] **Step 2: Run `cargo +stable test --test plugin_runtime engine`** and verify failure.
- [ ] **Step 3: Configure `wasmtime::Config` without WASI/linker imports, enable fuel consumption, and apply store memory limits.** Instantiate a fresh store per invocation; clamp manifest limits to server policy; map all failures to stable `PluginError` codes.
- [ ] **Step 4: Enforce the ABI export signatures** (`bearust_abi_version() -> i32`, optional `bearust_health_check() -> i32`) and reject non-`1` versions before health execution.
- [ ] **Step 5: Run focused tests under `cargo +stable test --test plugin_runtime`** and inspect that no raw runtime error text appears in test-facing errors.
- [ ] **Step 6: Commit** `feat: add bounded wasm health runtime`.

### Task 4: Add atomic plugin lifecycle and bounded snapshots

**Files:**
- Modify: `src/plugin_runtime.rs` — `PluginManager`, immutable snapshots, load/enable/disable/unload, and status models.
- Modify: `src/cli.rs` — initialize the manager from config and keep startup fail-open.
- Modify: `src/control_plane/mod.rs` — add the manager to `AppState` and expose it to handlers.
- Modify: `tests/plugin_runtime.rs` — lifecycle and snapshot tests.

**Interfaces:**
- `PluginManager::new(config: PluginConfig) -> Arc<Self>`.
- `PluginManager::reload_from_disk(&self) -> Result<ReloadSummary, PluginError>`.
- `PluginManager::set_enabled(&self, id: &str, enabled: bool) -> Result<PluginStatus, PluginError>`.
- `PluginManager::unload(&self, id: &str) -> Result<(), PluginError>`.
- `PluginManager::list(&self) -> Vec<PluginStatus>` returns bounded redacted status.
- `PluginManager::health_check(&self, id: &str) -> Result<HealthResult, PluginError>`.

- [ ] **Step 1: Write failing tests** for empty/missing directory startup, valid load, invalid plugin isolation, duplicate IDs, max-plugin bound, enable/disable/unload, failed reload retaining the old snapshot, and a concurrent health call observing one immutable snapshot.
- [ ] **Step 2: Run `cargo +stable test --test plugin_runtime lifecycle`** and verify failure.
- [ ] **Step 3: Implement discovery of immediate child plugin directories** only, candidate compilation off the read path, duplicate-ID rejection, and `ArcSwap` snapshot publication after all candidates validate.
- [ ] **Step 4: Ensure old compiled instances remain valid for captured readers** while subsequent readers observe the candidate snapshot; never partially publish a reload.
- [ ] **Step 5: Wire startup construction so disabled/invalid plugins log safe codes and the main server continues.** Do not spawn a plugin task that owns proxy resources.
- [ ] **Step 6: Run focused lifecycle tests plus `cargo +stable test --all-targets` with `DATABASE_URL=sqlite::memory:`**; expect existing suites to remain green.
- [ ] **Step 7: Commit** `feat: add atomic plugin lifecycle manager`.

### Task 5: Add plugin permissions, migration, and admin control-plane API

**Files:**
- Create: `migrations/0016_plugin_permissions.sql` — additive permission seeds after the current `0015_ai_advisor.sql` migration.
- Modify: `src/control_plane/rbac.rs` — add `PluginsRead` and `PluginsManage` permission keys and built-in role mappings.
- Modify: `src/control_plane/mod.rs` — add routes and `AppState.plugin_manager`.
- Create: `src/control_plane/plugins.rs` — authenticated handlers and safe request/response models.
- Modify: `src/control_plane/models.rs` — bounded plugin status and lifecycle request types.
- Modify: `tests/control_plane_plugins.rs` — API/RBAC/migration tests.
- Modify: `tests/control_plane_roles.rs` — update exact permission baseline.

**Interfaces:**
- `GET /api/plugins` requires `plugins.read`.
- `POST /api/plugins/reload` requires `plugins.manage`.
- `POST /api/plugins/{id}/enable` and `/disable` require `plugins.manage`.
- `DELETE /api/plugins/{id}` requires `plugins.manage`.
- `POST /api/plugins/{id}/health-check` requires `plugins.read` and returns only bounded status/error code.

- [ ] **Step 1: Write failing tests** for admin success, operator/viewer denial, safe 404/409/400 mapping, redacted status fields, and migration idempotence across SQLite.
- [ ] **Step 2: Run `DATABASE_URL=sqlite::memory: cargo +stable test --test control_plane_plugins`** and verify failure.
- [ ] **Step 3: Add explicit plugin permissions** using the existing seed/migration conventions. Keep lifecycle operations unavailable to roles without `plugins.manage`; do not use a hard-coded admin enum check in handlers.
- [ ] **Step 4: Implement handlers with the existing session, CSRF, authorization, and `user_error` helpers.** Validate IDs as path parameters, cap request bodies, and map runtime errors to stable envelopes without raw details.
- [ ] **Step 5: Register routes and initialize the manager in `AppState`/CLI** while preserving control-plane startup when the plugin directory is absent.
- [ ] **Step 6: Run focused API tests and the control-plane role baseline**; expect PASS.
- [ ] **Step 7: Commit** `feat: expose admin plugin lifecycle api`.

### Task 6: Wire redacted audit, realtime invalidation, and Prometheus metrics

**Files:**
- Modify: `src/plugin_runtime.rs` — lifecycle event sink and metric hooks.
- Modify: `src/control_plane/audit.rs` or `src/control_plane/plugins.rs` — record safe lifecycle events.
- Modify: `src/control_plane/realtime.rs` — publish a bounded `plugins` invalidation event using the existing contract.
- Modify: `src/observability.rs` and `src/control_plane/mod.rs` — fixed-label plugin counters in `/metrics`.
- Create/modify: `tests/plugin_observability.rs` — redaction, event, and label tests.

**Interfaces:**
- Event kind: `plugins.changed`.
- Metrics: `bearust_plugins_operations_total{operation="reload|enable|disable|unload|health_check",outcome="success|failure"}` and a single bounded `bearust_plugins_loaded` gauge; plugin IDs are never metric labels.

- [ ] **Step 1: Write failing tests** proving audit/details contain only plugin ID, operation, outcome, and safe error code; SSE contains no path/digest/module contents; Prometheus ignores unknown labels and stays under the output cap.
- [ ] **Step 2: Implement lifecycle instrumentation** at the manager boundary so every API and future caller uses the same redaction path.
- [ ] **Step 3: Publish realtime invalidation only after atomic snapshot publication**; failed reloads must not emit a successful change event.
- [ ] **Step 4: Add fixed metric counters and bounded rendering** following `AdvisorMetrics`/Prometheus conventions.
- [ ] **Step 5: Run focused observability tests and `git diff --check`**; expect PASS.
- [ ] **Step 6: Commit** `feat: add plugin audit realtime and metrics`.

### Task 7: Complete documentation, fixtures, and acceptance verification

**Files:**
- Create: `tests/fixtures/plugins/health_ok/plugin.toml` and `health_ok.wasm`/WAT build fixture.
- Modify: `README.md`, `DEVELOPMENT.md`, `DEPLOY.md` — disabled defaults, local plugin layout, limits, API examples, and security boundaries.
- Modify: `docs/PRD.md` — add Phase 13A status and explicitly defer 13B/13C/14.
- Create: `docs/superpowers/reviews/phase-13a-final-review.md` — evidence and deferred scope.

- [ ] **Step 1: Add a deterministic valid fixture and invalid fixture cases** used by integration tests; do not commit generated dependency caches or arbitrary third-party WASM.
- [ ] **Step 2: Document configuration, plugin directory layout, manifest fields, permission denial, lifecycle API, error codes, and the guarantee that proxy traffic is unaffected.** Include a warning that Phase 13A has no signature verification.
- [ ] **Step 3: Run the complete gate:** `cargo +stable fmt --all -- --check`; `cargo +stable clippy --all-targets -- -D warnings`; `DATABASE_URL=sqlite::memory: cargo +stable test --all-targets`; `npm test --prefix frontend -- --run`; `npm run build --prefix frontend`; `npm run validate-locales --prefix frontend`; and `git diff --check`.
- [ ] **Step 4: Perform a security review** for path traversal, capability escalation, unbounded resource use, secret/raw module leakage, and proxy-path coupling. Record each check and any fix in `docs/superpowers/reviews/phase-13a-final-review.md`.
- [ ] **Step 5: Update PRD status only after all gates pass**, mark Phase 13A complete, and state Phase 13B as next.
- [ ] **Step 6: Commit** `docs: complete phase 13a plugin runtime`.

## Plan self-review checklist

- Manifest, runtime, lifecycle, API, observability, and documentation requirements from the Phase 13A spec each have a task.
- No task adds traffic hooks, SDK, registry, signatures, WASI capabilities, or frontend marketplace behavior.
- Every public interface is typed, bounded, and referenced by later tasks.
- Every task has failing-test, implementation, verification, and commit steps.
- No raw runtime errors, module paths, manifest contents, or module bytes enter user-facing surfaces.
