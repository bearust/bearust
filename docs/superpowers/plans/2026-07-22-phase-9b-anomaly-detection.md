# Phase 9B Anomaly Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Mendeteksi penyimpangan traffic secara deterministik dalam mode monitor-only.

**Architecture:** Detector membaca baseline 9A, menghitung EWMA dan deviation score untuk empat rule awal, melakukan cooldown/deduplication bounded, lalu menyimpan anomaly record process-local dan mempublikasikan invalidation SSE.

**Tech Stack:** Rust, Tokio, Axum, serde, React, Vitest.

## Global Constraints

- Tidak ada blocking atau perubahan policy pada Phase 9B.
- Severity `info`, `warning`, `critical`; status `warming_up` tidak boleh menghasilkan critical.
- Record hanya berisi host ID, rule, severity, score, timestamps, dan safe summary.
- RBAC dan per-host scope wajib konsisten dengan Phase 4E/8.

### Task 1: Detector engine

**Files:** Create `src/anomaly.rs`, `tests/anomaly.rs`; Modify `src/lib.rs`.

- [ ] Tulis test spike request-rate, error-rate, latency regression, security-event spike, warming-up, cooldown, dedup, dan bounded retention.
- [ ] Jalankan `cargo test --test anomaly`; pastikan gagal.
- [ ] Implementasikan:

```rust
pub enum AnomalyRule { RequestRate, ErrorRate, Latency, SecurityEvents }
pub enum AnomalySeverity { Info, Warning, Critical }
pub struct AnomalyRecord { pub host_id: i64, pub rule: AnomalyRule, pub severity: AnomalySeverity, pub score: f64, pub observed_at: DateTime<Utc> }
pub fn evaluate(&self, baseline: &BaselineSnapshot, observed: &AnalyticsSnapshot, now: DateTime<Utc>) -> Vec<AnomalyRecord>;
```

- [ ] Pastikan floating-point NaN/inf ditolak dan semua hasil dibulatkan secara deterministik.
- [ ] Jalankan focused tests dan commit `feat: add deterministic anomaly detector`.

### Task 2: API, acknowledgement, and SSE

**Files:** Modify `src/control_plane/mod.rs`, `src/control_plane/router.rs`, `src/control_plane/realtime.rs`; Create `tests/control_plane_anomaly.rs`.

- [ ] Tulis test list/filter/pagination, RBAC scope, invalid query, dan acknowledge.
- [ ] Tambahkan `GET /api/analytics/anomalies` dan `POST /api/analytics/anomalies/{id}/ack` dengan audit redacted.
- [ ] Publikasikan `anomaly.changed` hanya sebagai invalidation event.
- [ ] Jalankan `cargo test --test control_plane_anomaly --test anomaly` dan commit `feat: expose scoped anomaly events`.

### Task 3: Dashboard

**Files:** Modify `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/realtime.ts`; Create `frontend/src/anomaly.test.tsx`.

- [ ] Tampilkan severity, rule, score, waktu, host, empty/loading/error state, dan tombol acknowledge yang disembunyikan bila permission tidak cukup.
- [ ] Refetch setelah `anomaly.changed` dengan deduplication.
- [ ] Jalankan `cd frontend && npm test -- --run src/anomaly.test.tsx src/realtime.test.tsx && npm run build`.
- [ ] Commit `feat: add anomaly dashboard`.

### Task 4: Verification gate

- [ ] Jalankan full Rust/frontend checks dan security review khusus redaction, cardinality, serta monitor-only.
- [ ] Simpan `docs/superpowers/reviews/phase-9b-final-review.md` dan commit `docs: verify phase 9b anomaly detection`.

