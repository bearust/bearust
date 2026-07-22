# Phase 9A Traffic Baseline Verification Review

## Summary

Phase 9A Traffic Baseline implementation is complete and verified. Bounded per-host traffic baseline collection, status evaluation (`warming_up` vs `ready`), rolling windows (5m, 1h, 24h), and RBAC host-scoped endpoints have been added without altering proxy path behavior or adding external persistence dependencies.

## Key Changes

1. **Backend Baseline Collector (`src/baseline.rs`, `src/lib.rs`)**:
   - Implemented `BaselineCollector`, `BaselineSnapshot`, `BaselineWindow`, and `BaselineStatus`.
   - Maintained bounded limits for hosts and minutely buckets to guarantee fail-open, zero memory growth overhead.
   - Handled out-of-order timestamps, eviction, and percentile averages.

2. **Control-Plane API & RBAC (`src/control_plane/mod.rs`, `tests/control_plane_baseline.rs`)**:
   - Exposed `GET /api/analytics/baseline` with `proxy_host_id` and `window` parameters.
   - Enforced host-level scoping using `require_analytics_read`.

3. **Frontend Dashboard (`frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/realtime.ts`, `frontend/src/baseline.test.tsx`)**:
   - Added baseline types and API methods.
   - Added `BaselineSection` UI with `warming_up` badge and metric cards.
   - Connected `baseline.changed` SSE invalidation event.

## Test & Verification Results

- `cargo +nightly test --test baseline`: 4 passed
- `cargo +nightly test --test control_plane_baseline`: 2 passed
- `npm test -- --run` & `npm run build`: 13 test suites (50 tests) passed, build clean.
