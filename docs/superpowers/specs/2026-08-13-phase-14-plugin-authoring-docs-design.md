# Phase 14 increment 2: plugin authoring documentation

## Goals

Give an external developer everything needed to write, build, test, and
sign a BeaRust WASM plugin in Rust, without reading the host source or the
per-phase design specs first. The document is the single onboarding path
for plugin authors; today that knowledge is scattered across six
`docs/superpowers/specs/2026-08-*-phase-13*-design.md` files, `src/plugin_runtime.rs`
doc comments, and `crates/bearust-plugin-sdk/src/lib.rs`.

## Non-goals

- Not a WASM/Rust tutorial from scratch — assumes working Rust knowledge.
- Not a contribution process for submitting plugins *into the BeaRust
  repository itself* (no CONTRIBUTING.md-style PR workflow). If BeaRust
  later wants first-party example plugins under version control, that is
  a separate, smaller follow-up.
- Not registry documentation. No plugin registry, fetch/install tooling,
  or GUI trust surface exists yet (deferred to a future Phase 14
  increment); the guide says so plainly rather than implying one exists.
- No new example plugin *project* (Cargo crate) is added to the repo.
  Code in the guide is illustrative Rust embedded in the Markdown, not a
  compiled, tested artifact — see Testing below for what "accurate"
  means here instead.
- No changes to the plugin runtime, SDK, or ABI. Documentation only.

## Audience

External developers building WASM plugins for their own BeaRust
deployment, writing in Rust against `bearust-plugin-sdk`. Not aimed at
non-Rust guest languages (the ABI is language-agnostic in principle, but
Rust + the SDK crate is the only supported path today, and the guide
doesn't pretend otherwise).

## Architecture

One new file, `docs/PLUGIN_AUTHORING.md`, plus a one-line cross-link added
to `README.md`'s existing plugin section. No other files change.

### Why one file, not several

Six hooks share one memory convention and one manifest shape; splitting
per-hook would duplicate the shared quickstart and memory-convention
sections six times, or force a reader to jump between files to assemble
one working plugin. A single ordered document (quickstart → shared
convention → per-hook reference → limits → signing → local testing) lets
a reader who wants *one* hook skip straight to its subsection via a table
of contents, while a reader building their first plugin reads top to
bottom once.

### Source of truth per section

Every technical claim in the guide is traceable to an existing artifact,
listed so drafting doesn't invent behavior:

| Section | Source |
|---|---|
| Memory convention (alloc/dealloc/pack/unpack) | `docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md`, `crates/bearust-plugin-sdk/src/lib.rs` |
| `health` hook | Phase 13B spec, `HealthCheckInput`/`HealthCheckOutput` in the SDK |
| `notify.waf_block` | `docs/superpowers/specs/2026-08-06-phase-13c-notification-sink-design.md`, `WafBlockEvent` in the SDK |
| `waf.detect` | `docs/superpowers/specs/2026-08-06-phase-13d-waf-detector-design.md`, `WafDetectRequest`/`WafDetectVerdict`/`WafPluginDecision` in the SDK |
| `transform.request` | `docs/superpowers/specs/2026-08-08-phase-13e-transform-request-design.md`, `TransformRequest`/`TransformResponse` in the SDK |
| `transform.response` | `docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`, `TransformResponseRequest`/`TransformResponseResult` in the SDK |
| `balance.select` | `docs/superpowers/specs/2026-08-12-phase-13g-load-balancing-hooks-design.md`, `BackendCandidate`/`LoadBalanceRequest`/`LoadBalanceResult` in the SDK |
| Export names, capability strings | `src/plugin_runtime.rs` (`CompiledPlugin` invocation methods), fixture READMEs under `tests/fixtures/plugins/*/README.md` |
| Limits (fuel/timeout/memory/output size) | `plugin.toml` `[limits]` fields as used in `tests/fixtures/plugins/*/plugin.toml` |
| Signing & trust | `README.md`'s existing "Phase 14 plugin manifest signing" section (not duplicated, only linked) |

The WAT fixtures (`tests/fixtures/plugins/*/*.wat`) are cited as the
low-level ground truth for export names and wire shapes where a spec is
ambiguous, but are never quoted as example code — they're deliberately
minimal test doubles in WebAssembly Text, not representative of what a
Rust plugin author writes.

## Components (document outline)

1. **Overview** — what a BeaRust plugin is, `abi_version: 2` as the
   recommended target (`abi_version: 0`, health-only, mentioned as legacy
   in one sentence with a pointer to the 13A spec, not otherwise covered),
   one paragraph on the sandbox model (WASM, fuel/timeout/memory limits,
   optional signing) with a link to `README.md` for enforcement details.
2. **Quickstart** — `cargo new --lib`, add `bearust-plugin-sdk` as a
   dependency, target `wasm32-wasip1`, minimal `plugin.toml`, the
   `bearust_plugin_sdk::abi_version!(2)` macro call, build command,
   drop into the configured plugins directory, `POST
   /api/plugins/reload`. Ends with a working (if useless) health-only
   plugin the reader can see load successfully before adding a real hook.
3. **Memory convention** — `bearust_alloc`/`bearust_dealloc`, the packed
   `i64` pointer/length result (`pack`/`unpack`), `encode`/`decode`,
   `read_input`/`write_output` helpers. Explained once; every hook
   section below just says "same convention."
4. **Hook reference** — one subsection per capability, each with: the
   capability string, export function signature, request/response Rust
   types (from the SDK, field-by-field), a short illustrative example,
   and a link to that hook's design spec for edge cases the guide won't
   restate (bounding rules, escalate-only merge semantics for
   `waf.detect`, the three headers `transform.request` can never
   override, `transform.response`'s base64-encoded body and inability to
   touch headers, `balance.select`'s host-enforced exclusion/health
   check). Covers, in this order: `health` (implicit, all v2 plugins),
   `waf.detect`, `transform.request`, `transform.response`,
   `notify.waf_block`, `balance.select`.
5. **Limits & failure behavior** — `[limits]` fields
   (`memory_pages`/`fuel`/`invocation_timeout_ms`/`max_output_bytes`) and
   what happens on trap/timeout/fuel exhaustion/malformed output: each
   hook's caller in `src/proxy.rs` falls back to BeaRust's built-in
   behavior (fail-open) rather than failing the request, except
   `waf.detect`'s verdict can only ever escalate an existing decision,
   never suppress one. Stated once at the general level, with a
   one-line note per hook only where the fallback target isn't obvious
   (e.g. `balance.select` falling back to the pool's own algorithm).
6. **Signing & sharing your plugin** — two short paragraphs: how to run
   `bearust plugin keygen`/`sign` (linking to `README.md` rather than
   repeating its content), and an honest statement that no community
   registry exists yet — for now, plugin authors distribute the plugin
   directory (manifest + wasm + optional `plugin.sig`) through their own
   channel (git repo, release artifact, etc.), and operators install it
   by dropping it into their configured plugins directory.
7. **Testing your plugin locally** — reload endpoint, checking
   `GET /api/plugins` for `trust_status`/`status`, triggering
   `POST /api/plugins/{id}/health-check`, and a pointer to
   `tests/fixtures/plugins/` as a source of known-good manifests to
   compare against when debugging a load failure.

### README.md change

In the existing "Phase 13A WASM plugins" section, near the sentence
describing the plugins directory layout, add one sentence: a link to
`docs/PLUGIN_AUTHORING.md` for the full hook reference and Rust examples.
No other README content moves or duplicates.

## Data flow

N/A — this is a documentation-only change; no runtime data flow is
introduced or altered.

## Error handling

N/A — no code changes. The guide's "Limits & failure behavior" section
*describes* existing error handling; it does not add any.

## Testing

No automated tests: the deliverable is Markdown, and no example project
is compiled as part of this increment (see Non-goals). Verification is
manual, done during drafting and again as a self-review pass before this
spec's implementation is considered complete:

- Every export name, struct field, and capability string in the guide is
  cross-checked against the SDK source
  (`crates/bearust-plugin-sdk/src/lib.rs`) and the corresponding
  `docs/superpowers/specs/2026-08-*-phase-13*-design.md`, not retyped
  from memory.
- Every illustrative code block is checked for internal consistency
  (correct macro/function names, matching types) by reading it against
  the SDK signatures, even though it is not compiled.
- The quickstart's shell commands (`cargo new`, target triple, build
  command) are checked against `crates/bearust-plugin-sdk/Cargo.toml`'s
  own target/edition to avoid recommending a mismatched toolchain setup.

## Follow-up increments (out of scope here)

- A first-party example plugin crate (compiled and tested in CI) if
  drift between this guide's illustrative code and the real ABI becomes
  a recurring problem.
- `CONTRIBUTING.md` for submitting plugins/hooks into the BeaRust repo
  itself.
- Community plugin registry and any documentation for it (Phase 14
  increment 3).
