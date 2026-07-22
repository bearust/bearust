# Phase 9 Self-Learning Design

## Goal

Menambahkan kemampuan self-learning yang aman dan bertahap: membentuk baseline
traffic, mendeteksi anomali, lalu menyediakan adaptive tuning yang opt-in tanpa
mengganggu request path atau memblokir traffic valid secara default.

## Scope

Phase 9 dibagi menjadi tiga increment yang dapat dirilis dan diuji secara
independen:

1. **Phase 9A — Traffic Baseline**: agregasi bounded per-host untuk request
   rate, latency percentile, error rate, status class, dan security counters.
2. **Phase 9B — Anomaly Detection**: deteksi deviasi baseline menggunakan
   statistik deterministik dan menghasilkan event severity tanpa enforcement.
3. **Phase 9C — Adaptive Tuning**: rekomendasi dan perubahan policy yang
   dibatasi guardrail, opt-in per-host, dengan rollback dan audit lengkap.

## Design decisions

- Penyimpanan awal process-local bounded, mengikuti collector Phase 8. Data
  hilang saat restart dan tidak memakai Redis/database baru pada Phase 9.
- Retensi default 24 jam dengan bucket satu menit; jumlah host, anomaly event,
  dan rekomendasi memiliki batas konfigurasi keras.
- Collector fail-open dan non-blocking terhadap request path.
- 9A dan 9B selalu monitor-only. 9C default monitor-only dan enforcement harus
  diaktifkan eksplisit per-host oleh administrator.
- Tidak menyimpan IP mentah, URL lengkap, header, body, credential, token, atau
  secret. Dimensi utama adalah host ID, status class, latency bucket, dan jenis
  security decision.
- Perubahan otomatis tidak boleh melampaui delta rate-limit/WAF yang telah
  dikonfigurasi, memiliki cooldown, dan dapat di-rollback ke konfigurasi
  terakhir yang diketahui aman.

## Architecture

Collector Phase 8 menjadi sumber agregat. Modul baseline menghitung rolling
window dan statistik referensi dari snapshot collector. Modul anomaly membaca
baseline dan snapshot terbaru, lalu mengeluarkan anomaly record bounded melalui
API internal dan SSE invalidation. Modul adaptive tuning membaca anomaly score,
menghasilkan recommendation, dan bila enforcement diaktifkan menerapkan patch
policy atomik melalui service konfigurasi yang sudah ada. Setiap keputusan
direkam sebagai audit event redacted.

## Increment 9A — Traffic Baseline

### Deliverables

- Tipe baseline per-host dengan window 5 menit, 1 jam, dan 24 jam.
- Statistik request rate, bytes/request bila tersedia, error rate, latency
  p50/p95/p99, serta WAF/bot/rate-limit counters.
- Query API terautentikasi yang mengikuti RBAC host scope Phase 4E.
- Panel dashboard untuk baseline dan keadaan `warming_up` saat sampel belum
  mencukupi.
- Konfigurasi batas retensi dan cardinality tanpa mengubah default Phase 8.

### Acceptance criteria

- Snapshot baseline konsisten untuk timestamp out-of-order dan restart.
- Query scoped user tidak dapat melihat host yang tidak ditugaskan.
- Collector tetap fail-open dan bounded pada beban host maksimum.
- Unit, API, RBAC, dan frontend tests tersedia.

## Increment 9B — Anomaly Detection

### Deliverables

- Detector deterministik berbasis EWMA dan deviasi standar/absolute deviation.
- Rule awal: request-rate spike, error-rate spike, latency regression, dan
  security-event spike.
- Cooldown dan deduplikasi agar satu anomali tidak menghasilkan event tanpa
  batas.
- API daftar anomaly dengan filter host, severity, rule, dan rentang waktu.
- Dashboard anomaly panel, status acknowledged, dan SSE `anomaly.changed`.

### Acceptance criteria

- Baseline `warming_up` tidak menghasilkan anomaly critical.
- Noise rendah pada traffic stabil dan spike sintetis terdeteksi dalam satu
  evaluation window.
- Semua anomaly payload bebas dari data sensitif dan mematuhi RBAC.
- Detector tidak melakukan blocking atau mengubah policy.

## Increment 9C — Adaptive Tuning

### Deliverables

- Recommendation engine yang memetakan anomaly score ke perubahan policy
  terukur.
- Mode per-host: `monitor`, `recommend`, dan `enforce` dengan default
  `monitor`.
- Guardrail delta maksimum, cooldown, minimum confidence, dan emergency
  disable global.
- Apply/rollback atomik, optimistic version check, dan audit event.
- Dashboard recommendation history, alasan perubahan, dan kontrol rollback.

### Acceptance criteria

- Tidak ada perubahan policy pada mode `monitor` atau confidence rendah.
- Enforcement tidak pernah melewati batas delta atau cooldown.
- Konflik konfigurasi ditolak tanpa partial update.
- Rollback mengembalikan versi policy sebelumnya dan tercatat di audit.
- Stress/failure tests membuktikan request path tetap fail-open.

## Testing and operations

- Setiap increment memakai TDD dan focused Rust/frontend tests sebelum suite
  penuh.
- Jalankan `cargo +stable test --all-targets`, `cargo fmt --check`, dan
  frontend test/build sesuai baseline repo.
- Tambahkan metrik internal untuk evaluation count, anomaly count, recommendation
  count, apply/rollback failure, dan bounded-drop count.
- Dokumentasikan konfigurasi, reset saat restart, threat model, serta prosedur
  emergency disable sebelum 9C diaktifkan.

## Explicitly deferred

Durable long-term history, Redis/cross-node aggregation, replay lintas node,
per-route high-cardinality models, CAPTCHA/LLM decisions, dan plugin-based
detectors tetap berada di Phase 10–13.
