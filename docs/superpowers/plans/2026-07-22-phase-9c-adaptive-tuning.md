# Phase 9C Adaptive Tuning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menyediakan adaptive tuning per-host yang aman, opt-in, dapat diaudit, dan dapat di-rollback.

**Architecture:** Recommendation engine menerjemahkan anomaly score menjadi bounded policy patch. Policy mode `monitor` (default), `recommend`, atau `enforce` disimpan bersama host configuration; apply memakai version check dan atomic update, dengan cooldown, confidence floor, emergency disable, serta rollback.

**Tech Stack:** Rust, Axum, SQLite repository/migrations, Tokio, React, Vitest.

## Global Constraints

- Default mode `monitor`; monitor/recommend tidak mengubah policy aktif.
- Delta maksimum, cooldown, confidence floor, dan global emergency disable wajib enforced di backend.
- Apply/rollback harus atomic; konflik versi tidak boleh menghasilkan partial update.
- Semua apply, reject, cooldown, dan rollback dicatat sebagai audit event redacted.

### Task 1: Policy and recommendation model

**Files:** Create `src/adaptive_tuning.rs`, `tests/adaptive_tuning.rs`; Modify `src/control_plane/models.rs`, `src/config/mod.rs`.

- [ ] Tulis test mode default, confidence floor, max delta, cooldown, recommendation determinism, dan reject unsafe patch.
- [ ] Implementasikan:

```rust
pub enum TuningMode { Monitor, Recommend, Enforce }
pub struct TuningPolicy { pub mode: TuningMode, pub max_delta_percent: u8, pub cooldown_seconds: u64, pub min_confidence: f64 }
pub struct PolicyRecommendation { pub host_id: i64, pub patch: PolicyPatch, pub confidence: f64, pub reason: String }
pub fn recommend(&self, anomaly: &AnomalyRecord, current: &RateLimitPolicy) -> Option<PolicyRecommendation>;
```

- [ ] Validasi finite confidence, bounded reason length, dan allowed patch fields.
- [ ] Jalankan focused tests dan commit `feat: add adaptive tuning recommendations`.

### Task 2: Persistence, atomic apply, rollback, and audit

**Files:** Modify `src/control_plane/repository.rs`, migrations under `migrations/`, `src/rate_limit_store.rs`, `src/waf_store.rs`; Create `tests/adaptive_tuning_api.rs`.

- [ ] Tulis test migration idempotence, scoped admin authorization, optimistic version conflict, cooldown, emergency disable, apply, dan rollback.
- [ ] Tambahkan tabel/config untuk tuning policy dan versioned recommendation history.
- [ ] Implementasikan transaction yang menyimpan previous policy sebelum apply serta rollback atomik.
- [ ] Pastikan runtime store menerima perubahan hanya setelah commit database berhasil.
- [ ] Publikasikan `adaptive_tuning.changed` tanpa policy secret atau raw request data.
- [ ] Jalankan focused Rust tests dan commit `feat: persist guarded adaptive tuning`.

### Task 3: Control-plane API and dashboard

**Files:** Modify `src/control_plane/router.rs`, `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/realtime.ts`; Create `frontend/src/adaptiveTuning.test.tsx`.

- [ ] Tambahkan endpoint read/update policy, list recommendations, apply, rollback, dan emergency disable.
- [ ] Terapkan host scope dan admin/operator permission sesuai operasi; viewer read-only.
- [ ] Tambahkan UI mode selector, guardrail fields, recommendation reason, apply/rollback confirmation, dan visible monitor-only default.
- [ ] Refetch setelah `adaptive_tuning.changed`; tampilkan error conflict/cooldown tanpa mengungkap detail internal.
- [ ] Jalankan frontend focused tests dan build; commit `feat: add adaptive tuning controls`.

### Task 4: Verification and rollout gate

- [ ] Jalankan `cargo +stable fmt --check`, `cargo +stable test --all-targets`, frontend tests/build, dan `git diff --check`.
- [ ] Jalankan failure injection untuk DB error, runtime store error, concurrent apply, dan restart.
- [ ] Pastikan emergency disable mematikan enforcement tanpa restart.
- [ ] Simpan `docs/superpowers/reviews/phase-9c-final-review.md`, update `README.md`, `DEVELOPMENT.md`, `docs/PRD.md`, lalu commit `docs: verify phase 9c adaptive tuning`.

