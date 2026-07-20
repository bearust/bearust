# Phase 4C Audit Log Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe, read-only audit-log API and dashboard viewer for all authenticated BeaRust roles.

**Architecture:** Keep audit writes in `control_plane::audit`, add focused query/DTO functions in the repository and a read-only Axum handler. The handler authenticates once, validates bound filters, and returns paginated redacted rows. The React dashboard consumes the endpoint through a typed API method and renders a self-contained Audit Log section.

**Tech Stack:** Rust, Axum, SQLx SQLite, Serde, Tokio tests, React, TypeScript, Vite, Vitest.

## Global Constraints

- Permit only authenticated `admin`, `operator`, and `viewer` sessions.
- Never select or serialize passwords, session hashes, setup tokens, private keys, provider credentials, request bodies, or raw SQL errors.
- Keep audit logs read-only; add no mutation or deletion endpoint.
- Use bound SQL parameters for every filter.
- Default to page 1 and 25 rows; accept only page sizes 1–100.
- Order by `created_at DESC, id DESC` for deterministic newest-first results.
- Preserve existing error-envelope and frontend error-sanitization conventions.

---

### Task 1: Define audit query DTOs and repository query

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Test: `tests/control_plane_audit.rs` (create)

**Interfaces:**
- Produce `AuditLogQuery { event: Option<String>, actor_id: Option<i64>, from: Option<String>, to: Option<String>, q: Option<String>, page: u32, page_size: u32 }`.
- Produce `AuditLogItem { id: i64, actor: String, event: String, details: String, created_at: String }` and `AuditLogPage { items: Vec<AuditLogItem>, page: u32, page_size: u32, total: i64 }`.
- Produce `repository::list_audit_logs(pool, &AuditLogQuery) -> Result<AuditLogPage, sqlx::Error>`.

- [ ] **Step 1: Write failing repository tests** that insert system, active-user, and deleted-user audit rows, then assert actor labels, newest-first ordering, total count, event/actor/time/text filters, and page boundaries.
- [ ] **Step 2: Run the focused test**

Run: `cargo test --test control_plane_audit repository_lists_filtered_paginated_rows`
Expected: FAIL because DTOs/query function do not exist.

- [ ] **Step 3: Add redacted DTOs and query implementation**

Use `LEFT JOIN users` and `COALESCE(users.email, CASE WHEN audit_logs.user_id IS NULL THEN 'system' ELSE 'deleted-user' END)`. Build the `WHERE` clauses from fixed filter branches and bind every value. Run a separate `COUNT(*)` with the same predicates, then apply `LIMIT ? OFFSET ?`.

- [ ] **Step 4: Run focused repository tests**

Run: `cargo test --test control_plane_audit repository_lists_filtered_paginated_rows`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/repository.rs tests/control_plane_audit.rs
git commit -m "feat: add paginated audit log repository queries"
```

### Task 2: Add authenticated audit-log API

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/models.rs` (request/query deserialization if needed)
- Test: `tests/control_plane_audit.rs`

**Interfaces:**
- Add route `GET /api/audit-logs`.
- Add handler `list_audit_logs(State(AppState), HeaderMap, Query<AuditLogParams>)`.

- [ ] **Step 1: Write failing HTTP contract tests** for unauthenticated `401`, admin/operator/viewer `200`, invalid page/page_size/date input `400`, and response absence of `password_hash`, `token_hash`, and secret fixtures.
- [ ] **Step 2: Run the focused API tests**

Run: `cargo test --test control_plane_audit audit_log_endpoint`
Expected: FAIL because the route and handler do not exist.

- [ ] **Step 3: Implement query parsing and handler**

Use `current(&state, &headers)` for authentication, parse defaults (`page=1`, `page_size=25`), reject page `< 1`, page size outside `1..=100`, negative actor ids, and malformed RFC3339 `from`/`to`. Return `invalid_input` using `user_error`; map repository failures to the existing sanitized `database_error` response.

- [ ] **Step 4: Run API tests and the existing control-plane suite**

Run: `cargo test --test control_plane_audit audit_log_endpoint && cargo test --test control_plane_users`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/mod.rs src/control_plane/models.rs tests/control_plane_audit.rs
git commit -m "feat: expose authenticated audit log api"
```

### Task 3: Add typed frontend API client and audit panel

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css` (only if existing stylesheet needs table/filter layout rules)
- Test: `frontend/src/audit.test.tsx` (create)

**Interfaces:**
- Add `AuditLogItem`, `AuditLogPage`, and `AuditLogQuery` types.
- Add `api.auditLogs(query: AuditLogQuery): Promise<AuditLogPage>` using URLSearchParams and the existing `request` helper.
- Add `AuditLogSection({ user }: { user: User })` rendered inside `Dashboard`.

- [ ] **Step 1: Write failing Vitest tests** for rendering for all roles, query serialization, event/text filters, next/previous pagination, empty state, and sanitized API errors.
- [ ] **Step 2: Run focused frontend tests**

Run: `npm test --prefix frontend -- --run src/audit.test.tsx`
Expected: FAIL because the API method and section do not exist.

- [ ] **Step 3: Implement API types/method and section**

Load page 1 on mount, reset to page 1 when filters change, disable pagination buttons at boundaries, show only the safe fields returned by the API, and pass errors through `sanitizeError`. Do not gate the component by role in the UI; backend authentication remains authoritative.

- [ ] **Step 4: Run focused tests and production build**

Run: `npm test --prefix frontend -- --run src/audit.test.tsx && npm run build --prefix frontend`
Expected: PASS and a successful Vite build.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api.ts frontend/src/App.tsx frontend/src/audit.test.tsx frontend/src/styles.css
git commit -m "feat: add audit log dashboard viewer"
```

### Task 4: Document the Phase 4C contract

**Files:**
- Modify: `README.md`
- Modify: `docs/PRD.md` (only the Phase 4 status/roadmap note if maintained there)

- [ ] **Step 1: Add API and UI documentation**

Document authentication, all supported filters, pagination limits, actor labels, redaction guarantees, and the explicit absence of delete/export operations.

- [ ] **Step 2: Run documentation checks**

Run: `git diff --check && rg -n "audit|Audit|page_size|deleted-user" README.md docs/PRD.md`
Expected: no whitespace errors and the new contract is discoverable.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/PRD.md
git commit -m "docs: document phase 4c audit log viewer"
```

### Task 5: Run the complete verification gate

**Files:**
- Verify all files changed by Tasks 1–4.

- [ ] **Step 1: Run Rust formatting and tests**

```bash
cargo fmt --all -- --check
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
```

Expected: formatting check and all Rust tests pass.

- [ ] **Step 2: Run frontend tests/build and diff checks**

```bash
npm test --prefix frontend -- --run
npm run build --prefix frontend
git diff --check
```

Expected: all frontend tests pass, production build succeeds, and no whitespace errors exist.

- [ ] **Step 3: Review the final diff for secret exposure and scope**

Run: `git diff origin/main...HEAD -- src/control_plane frontend/src README.md docs/PRD.md` and confirm the only new API is read-only audit viewing, every SQL predicate is bound, and no sensitive field is selected or rendered.

- [ ] **Step 4: Commit any verification-only fixes**

```bash
git add -A
git commit -m "test: verify phase 4c audit log viewer"
```
