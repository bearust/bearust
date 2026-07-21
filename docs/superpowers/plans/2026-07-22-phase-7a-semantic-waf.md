# Phase 7A Semantic WAF Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic, bounded semantic attack detection to the existing in-process WAF while preserving Phase 6 compatibility and monitor-only defaults.

**Architecture:** Keep `InspectionContext`, immutable `WafSnapshot`, and atomic `WafStore` as the integration boundaries. Add a bounded normalization layer and semantic signal evaluator inside the WAF module, then merge semantic results with existing signature-rule decisions before the proxy applies the result.

**Tech Stack:** Rust, Pingora, `regex`, SQLx-backed existing WAF persistence, Axum control-plane APIs, React/Tailwind dashboard, Cargo test/Clippy/fmt.

## Global Constraints

- Body inspection remains capped at `8 KiB` (`MAX_INSPECTION_BODY_BYTES`).
- Evaluation is deterministic, in-process, and bounded; no network calls or ML dependencies.
- Existing WAF API, TOML formats, explicit rule actions, audit redaction, and SSE behavior remain compatible.
- Default mode remains `monitor_only`; block thresholds are conservative and not persisted in this increment.
- Never persist full request bodies, credentials, or raw sensitive headers.

---

### Task 1: Bounded request normalization

**Files:**
- Modify: `src/waf.rs`
- Test: `tests/waf_engine.rs`

**Interfaces:**
- Consumes: `InspectionContext`.
- Produces: private normalized field views used by semantic and signature evaluation.

- [ ] **Step 1: Write failing tests** for one-level percent decoding, case folding, separator normalization, malformed encoding tolerance, and the existing body cap in `tests/waf_engine.rs`.
- [ ] **Step 2: Run** `cargo +stable test --test waf_engine normalized_ -q`; confirm the new tests fail because no normalization helper exists.
- [ ] **Step 3: Implement** a private `normalize_context(context: &InspectionContext) -> NormalizedContext` with bounded decoding (maximum two passes), ASCII lowercase where detectors require it, canonical whitespace/separators, and body truncation to `MAX_INSPECTION_BODY_BYTES`. Malformed `%` sequences remain literal.
- [ ] **Step 4: Update signature matching** to consume normalized views without changing `WafRule` or TOML schemas.
- [ ] **Step 5: Run** `cargo +stable test --test waf_engine -q` and `cargo +stable fmt --all -- --check`.
- [ ] **Step 6: Commit** with `git add src/waf.rs tests/waf_engine.rs && git commit -m "feat: normalize bounded waf inputs"`.

### Task 2: Semantic signals and risk scoring

**Files:**
- Modify: `src/waf.rs`
- Test: `tests/waf_engine.rs`

**Interfaces:**
- Consumes: `NormalizedContext` from Task 1.
- Produces: `SemanticSignal`, score/severity metadata, and a merged `Evaluation` result.

- [ ] **Step 1: Add failing tests** covering positive and benign cases for SQL injection, XSS, path traversal, command injection, and protocol anomalies; include mixed indicators and assert stable category/score output.
- [ ] **Step 2: Run** `cargo +stable test --test waf_engine semantic_ -q`; confirm failure before implementation.
- [ ] **Step 3: Implement** private detectors returning bounded `SemanticSignal { category, weight, field, reason }`. Use static compiled regexes or equivalent deterministic checks; cap signal count and reason length.
- [ ] **Step 4: Extend** `Evaluation` with `semantic_score: u16`, `severity: Option<String>`, and redacted signal reasons while retaining all existing fields and decision semantics.
- [ ] **Step 5: Merge** signature matches and semantic signals deterministically: explicit `Block` remains dominant; monitor mode logs detections; block mode blocks only at the conservative fixed threshold.
- [ ] **Step 6: Run** `cargo +stable test --test waf_engine -q` and `cargo +stable clippy --all-targets --all-features -- -D warnings`.
- [ ] **Step 7: Commit** with `git add src/waf.rs tests/waf_engine.rs && git commit -m "feat: add semantic waf scoring"`.

### Task 3: Proxy-path integration and redacted telemetry

**Files:**
- Modify: `src/proxy.rs`, `src/control_plane/mod.rs` (only where existing WAF audit payloads are assembled)
- Test: `tests/proxy_waf.rs`, `tests/waf_end_to_end.rs`

**Interfaces:**
- Consumes: enriched `Evaluation` from Task 2.
- Produces: unchanged allow/log/block proxy behavior plus bounded audit metadata.

- [ ] **Step 1: Write failing integration tests** proving semantic detections are logged in monitor mode, blocked at threshold in block mode, and never include full body, authorization headers, or credentials in audit/event payloads.
- [ ] **Step 2: Run** targeted proxy/WAF tests and confirm failure.
- [ ] **Step 3: Pass** the enriched evaluation through the existing proxy request and body-inspection paths; preserve the current bounded body collection and snapshot reload behavior.
- [ ] **Step 4: Update** audit/event serialization to include only category, score, severity, and bounded reason identifiers; redact or omit raw values.
- [ ] **Step 5: Run** `cargo +stable test --test proxy_waf --test waf_end_to_end -q`.
- [ ] **Step 6: Commit** with `git add src/proxy.rs src/control_plane/mod.rs tests/proxy_waf.rs tests/waf_end_to_end.rs && git commit -m "feat: integrate semantic waf telemetry"`.

### Task 4: Regression coverage and documentation

**Files:**
- Modify: `docs/PRD.md`, `docs/superpowers/specs/2026-07-22-phase-7a-semantic-waf-design.md` only if clarified by implementation
- Test: `tests/waf_engine.rs`, `tests/proxy_waf.rs`, `tests/log_contract.rs` (only if a new redaction assertion belongs there)

**Interfaces:**
- Consumes: completed semantic evaluator and proxy integration.
- Produces: documented Phase 7A status and a repeatable verification gate.

- [ ] **Step 1: Add regression tests** for snapshot reload, explicit rule precedence, oversized bodies, malformed encodings, and benign requests through the proxy.
- [ ] **Step 2: Run the complete backend gate:** `cargo +stable fmt --all -- --check && cargo +stable clippy --all-targets --all-features -- -D warnings && cargo +stable test --all-targets`.
- [ ] **Step 3: Update** the PRD with a Phase 7A status paragraph describing delivered scope and explicitly deferred Phase 7B/7C capabilities.
- [ ] **Step 4: Run frontend checks** if dashboard behavior changed: `cd frontend && npm test -- --run && npm run build`.
- [ ] **Step 5: Review** `git diff --check`, inspect audit payloads for secrets, and verify no unrelated working-tree files are staged.
- [ ] **Step 6: Commit** with `git add docs/PRD.md tests && git commit -m "docs: complete phase 7a semantic waf"`.

