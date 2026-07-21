# Phase 4E final-fix report

## Findings addressed

- Proxy-host update and delete now return `404 Not Found` whenever scoped write authorization fails, including users who have read-only access. This prevents resource-existence disclosure through mutation status codes.
- `role_scopes_changed` audit details now contain only the role ID and read/write assignment counts. Host IDs and other scope details are excluded from audit payloads and realtime events remain redacted.
- Per-host assignment IDs are normalized by sorting and deduplicating. Duplicate permission entries and non-positive or unknown host IDs remain rejected.
- Removed the unused standalone host-scope deletion helper; host deletion continues to clean assignments transactionally.

## Verification evidence

```text
$ cd frontend && npm test -- --run
Test Files  8 passed (8)
Tests       38 passed (38)

$ npm run build
✓ built successfully

$ cd .. && git diff --check
# passed
```

The Rust toolchain (`cargo`) is not installed in this environment, so Rust tests could not be executed here.
