# Phase 4B User Management & RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Menyediakan manajemen user admin-only dan penegakan RBAC yang konsisten untuk tiga role bawaan BeaRust.

**Architecture:** Pertahankan control plane Axum dan repository SQLx yang ada. Tambahkan status akun pada model/schema, operasi repository terisolasi, endpoint user yang memakai permission `UsersManage`, lalu integrasikan UI Users admin-only melalui API client React yang sudah ada.

**Tech Stack:** Rust 1.84.1, Axum, SQLx SQLite, Argon2, serde, React, TypeScript, Vite, Vitest.

## Global Constraints

- Role yang valid hanya `admin`, `operator`, dan `viewer`.
- Password hash, session hash, setup token, dan provider secret tidak boleh keluar dari backend.
- Admin terakhir tidak boleh dihapus, dinonaktifkan, atau diturunkan rolenya.
- User tidak boleh menghapus atau menonaktifkan dirinya sendiri.
- Permission tetap diputuskan oleh `control_plane::rbac::allowed`.
- Setiap mutasi user dan penolakan authorization dicatat sebagai audit event redacted.
- Tidak menambahkan scope permission per-host, SSO, atau audit viewer pada Phase 4B.

### Task 1: Account status model, migration, and repository operations

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `tests/control_plane_repository.rs`

**Interfaces:**
- `User` gains `disabled: bool`.
- Add `UserCreate`, `UserPatch`, and `UserSummary`-equivalent request/response types as appropriate for existing model conventions.
- Repository exposes `list_users`, `count_active_admins`, `update_user_role`, `set_user_disabled`, `delete_user`, `revoke_user_sessions`.
- `find_user` and `find_user_by_session` exclude disabled accounts from authentication.

- [ ] **Step 1: Write failing repository tests**

Add tests covering schema creation with existing users, default-enabled accounts, list responses without password hashes, role update, disable/delete, active-admin counting, and session revocation.

- [ ] **Step 2: Run the focused repository test and verify failure**

Run:

```bash
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_repository
```

Expected: FAIL because the status column and repository functions do not exist.

- [ ] **Step 3: Implement the migration and repository functions**

Add an idempotent `disabled INTEGER NOT NULL DEFAULT 0` migration, map it to `bool`, validate roles with `Role::parse`, use transactions for last-admin-sensitive mutations, and revoke all sessions for disabled/deleted users.

- [ ] **Step 4: Run focused tests and then the full backend suite**

Run the focused command above, then:

```bash
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
```

Expected: all repository and existing regression tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/repository.rs tests/control_plane_repository.rs
git commit -m "feat: add user lifecycle repository operations"
```

### Task 2: Admin-only user API and authorization invariants

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/audit.rs` if an event helper is needed
- Create or modify: `tests/control_plane_users.rs`

**Interfaces:**
- `GET /api/users` returns `Vec<User>` summaries.
- `POST /api/users` accepts `{email,password,role}` and returns a `User` summary.
- `PATCH /api/users/{id}` accepts optional `{role,disabled}` and returns the updated summary.
- `DELETE /api/users/{id}` returns `204`.

- [ ] **Step 1: Add failing API tests**

Test admin list/create/update/delete, operator/viewer `403`, invalid role/password, duplicate email, self-disable/self-delete, last-admin protection, disabled-login rejection, response secret redaction, and audit rows for success/denial.

- [ ] **Step 2: Run the focused API test and verify failure**

```bash
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_users
```

Expected: FAIL because the user routes are not registered.

- [ ] **Step 3: Implement handlers and routes**

Reuse `current`, `auth::token_hash`, existing Argon2 hashing, `ErrorEnvelope`, and `audit::record`. Check `Permission::UsersManage` before repository access. Return `invalid_input`, `forbidden`, `not_found`, and conflict errors using the existing response style. Apply the last-admin and self-mutation checks inside a repository transaction so concurrent requests cannot bypass them.

- [ ] **Step 4: Run focused and full backend tests**

Run the focused test, then `cargo test --locked`; expected result is zero failures.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/mod.rs src/control_plane/audit.rs tests/control_plane_users.rs
git commit -m "feat: add admin user management api"
```

### Task 3: Frontend API client and admin Users section

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/acme.test.tsx` or create `frontend/src/users.test.tsx`

**Interfaces:**
- `api.users()` returns `User[]`.
- `api.createUser({email,password,role})` returns `User`.
- `api.updateUser(id,{role?,disabled?})` returns `User`.
- `api.deleteUser(id)` returns `void`.

- [ ] **Step 1: Write failing client/UI tests**

Mock the four API calls and verify the Users section is absent for viewer/operator, visible for admin, renders user status, submits create form, updates role, and handles `403`/validation errors without exposing response internals.

- [ ] **Step 2: Run frontend tests and verify failure**

```bash
npm test --prefix frontend -- --run
```

Expected: new user tests fail because the API methods and section do not exist.

- [ ] **Step 3: Implement API methods and responsive UI**

Extend `User` with `disabled`, add API methods, and render an admin-only Users card in `Dashboard`. Include confirmation before disable/delete, disable destructive actions for the current account, and keep the backend as the security boundary.

- [ ] **Step 4: Run frontend tests and production build**

```bash
npm test --prefix frontend -- --run
npm run build --prefix frontend
```

Expected: all tests pass and Vite produces `frontend/dist`.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api.ts frontend/src/App.tsx frontend/src/styles.css frontend/src/users.test.tsx
git commit -m "feat: add admin user management ui"
```

### Task 4: Documentation, contract review, and completion verification

**Files:**
- Modify: `README.md`
- Modify: `docs/PRD.md` only if the Phase 4B status marker is maintained there
- Modify: `docs/superpowers/specs/2026-07-19-phase-4b-rbac-design.md` only for approved clarifications

- [ ] **Step 1: Document endpoints and role matrix**

Add request/response examples, setup-to-admin transition behavior, disabled-account behavior, and the distinction between Phase 4B and Phase 4C.

- [ ] **Step 2: Run all verification commands**

```bash
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
npm test --prefix frontend -- --run
npm run build --prefix frontend
git diff --check
```

Expected: all commands exit with status 0.

- [ ] **Step 3: Review completion criteria**

Confirm every item in the Phase 4B design document is covered by code and tests. Report any gap instead of marking Phase 4B complete.

- [ ] **Step 4: Commit documentation and final verification**

```bash
git add README.md docs/PRD.md docs/superpowers/specs/2026-07-19-phase-4b-rbac-design.md
git commit -m "docs: document phase 4b user management"
```

