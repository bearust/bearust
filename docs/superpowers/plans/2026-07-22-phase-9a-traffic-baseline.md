# Phase 9A Traffic Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menyediakan baseline traffic bounded per-host tanpa mengubah keputusan proxy.

**Architecture:** Tambahkan modul baseline yang membaca snapshot `AnalyticsCollector`, menghitung rolling windows 5m/1h/24h, dan menyimpan hasil process-local bounded. Control-plane API memakai authorization host scope yang sama dengan analytics Phase 8; dashboard menampilkan status `warming_up` dan statistik baseline.

**Tech Stack:** Rust, Tokio/RwLock, Axum, serde, React, Vitest.

## Global Constraints

- Data tidak boleh memuat IP mentah, URL lengkap, header, body, credential, token, atau secret.
- Collector dan query fail-open terhadap request path serta memiliki batas host/window/event.
- Default retention tetap 24 jam dan data hilang saat restart.
- Semua endpoint read-only harus menerapkan RBAC dan per-host scope.

### Task 1: Baseline domain and tests

**Files:** Create `src/baseline.rs`, `tests/baseline.rs`; Modify `src/lib.rs`.

- [ ] Tulis test untuk `warming_up`, rolling windows, out-of-order timestamps, bounded host eviction, dan percentile carry-over.
- [ ] Jalankan `cargo test --test baseline`; pastikan gagal karena tipe belum ada.
- [ ] Implementasikan `BaselineCollector`, `BaselineSnapshot`, `BaselineWindow`, dan `BaselineStatus` dengan API:

```rust
pub fn record(&self, snapshot: &AnalyticsSnapshot, now: DateTime<Utc>);
pub fn snapshot(&self, host_id: Option<i64>, from: DateTime<Utc>, to: DateTime<Utc>) -> BaselineSnapshot;
```

- [ ] Jalankan focused test hingga seluruh test lulus.
- [ ] Commit `feat: add bounded traffic baselines`.

### Task 2: API, RBAC, and realtime invalidation

**Files:** Modify `src/control_plane/mod.rs`, `src/control_plane/router.rs`, `src/cli.rs`; Create `tests/control_plane_baseline.rs`.

- [ ] Tulis test endpoint `GET /api/analytics/baseline` untuk admin, scoped viewer, invalid range, dan unknown host.
- [ ] Implementasikan DTO query bounded, `require_analytics_read`, serta SSE event `baseline.changed` tanpa payload metric.
- [ ] Hubungkan collector ke jalur analytics completion yang sudah ada.
- [ ] Jalankan `cargo test --test control_plane_baseline --test baseline`.
- [ ] Commit `feat: expose scoped traffic baselines`.

### Task 3: Dashboard and documentation

**Files:** Modify `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/realtime.ts`; Create `frontend/src/baseline.test.tsx`; Modify `README.md`, `DEVELOPMENT.md`, `docs/PRD.md`.

- [ ] Tambahkan API client dan panel baseline dengan loading, empty, error, `warming_up`, host filter, dan accessible labels.
- [ ] Refetch setelah `baseline.changed`, deduplicate event, dan jangan menampilkan data sensitif.
- [ ] Jalankan `cd frontend && npm test -- --run src/baseline.test.tsx src/realtime.test.tsx && npm run build`.
- [ ] Update status Phase 9A dan deferred scope.
- [ ] Commit `feat: add traffic baseline dashboard`.

### Task 4: Verification gate

- [ ] Jalankan `cargo +stable fmt --check`, `cargo +stable test --all-targets`, dan `git diff --check`.
- [ ] Catat hasil pada `docs/superpowers/reviews/phase-9a-final-review.md`.
- [ ] Commit `docs: verify phase 9a baseline`.

