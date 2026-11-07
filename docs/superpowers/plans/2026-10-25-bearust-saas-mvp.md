# Bearust SaaS MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a private `Bearust/saas` repository from template `01-go-next-template` containing a public marketing landing plus an admin dashboard for edge server/VM management (CRUD, per-VM quotas for tenant capacity and bandwidth, region assignment, basic monitoring).

**Architecture:** Single Go backend (Fiber + GORM + Postgres) serving JSON APIs plus a single Next.js App Router frontend. Public landing lives as public routes in the same frontend app; the admin dashboard reuses the template's server-actions + `backendFetch` + `revalidatePath` pattern. New `regions` and `edge_nodes` tables back the edge inventory; a scheduler/worker job polls node health endpoints and stores lightweight status snapshots for the monitoring view. No real VM provisioning or bandwidth enforcement in the MVP (control plane first).

**Tech Stack:** Go + Fiber + GORM + golang-migrate, Postgres, Next.js App Router server actions, shadcn/ui, Vitest, Playwright, Biome, Docker Compose.

## Global Constraints

- English for everything written into the repository: code, comments, docs, logs, commit messages, specs, plans. Only user-facing translation catalogs may contain other languages (template convention, enforced by `scripts/check_conventions.py`).
- Conventional Commits: `type(scope): summary`, imperative mood, lowercase start, no trailing period. Scope is the new app slug once initialized.
- Backend error responses use the template's shared error writer with SNAKE codes; new codes introduced by this plan: `REGION_NOT_FOUND`, `EDGE_NODE_NOT_FOUND`, `QUOTA_INVALID`, `REGION_IN_USE`.
- Quota fields (max tenants/users, bandwidth cap) are non-negative integers; negative or null means unset only where the task explicitly allows it.
- Auth: at least one login method stays enabled at all times (template startup fails otherwise). MVP enables password + at least one public OAuth provider; Unmer Gate SSO is remapped or disabled so public signup works.
- RBAC: edge write operations require admin/operator roles; viewer is read-only. Follow the existing role/permission seeder pattern.
- No changes to the `bearust` core repository and no production deploy in this plan. Domain wiring (`bearust.cloud`, `docs.bearust.cloud`) is config-only.
- Every task ends validated: relevant checks run and results reported as they are.

---

## File Map

New repository root (`../bearust-saas`, copied from `src/01-go-next-template`):

- Modify: `.env.example` — SaaS auth flags, `APP_URL`, seed defaults.
- Modify: `Makefile` — keep `dev`, `db-up`, `db-seed`, `test`; add edge seed step if seeders split.
- Modify: `src/backend/internal/auth/gate_roles.go` — public access mapping.
- Modify: `src/backend/database/seeders/role_seeder.go` — edge permissions on roles.
- Modify: `src/backend/database/seeders/permission_seeder.go` — add `regions.*`, `edge_nodes.*` permissions.
- Create: `src/backend/database/migrations/NNNNN_edge_inventory.up.sql` / `.down.sql` — `regions` + `edge_nodes` tables (next migration number at execution time).
- Create: `src/backend/internal/edge/` — models, service, handlers for regions and nodes, quota validation.
- Create: `src/frontend/src/app/(marketing)/page.tsx` — public landing (hero, features, pricing teaser, signup CTA).
- Create: `src/frontend/src/app/(marketing)/pricing/page.tsx` — public pricing page.
- Create: `src/frontend/src/app/(main)/dashboard/edge/` — node list, detail, form pages + `_components/`.
- Create: `src/frontend/src/app/(main)/dashboard/regions/` — minimal region management UI.
- Modify: `src/frontend/src/navigation/sidebar/sidebar-items.ts` — Edge and Regions entries.
- Create: `src/frontend/e2e/edge-nodes.spec.ts` — e2e coverage for the edge flow.

---

### Task 1: Scaffold the repository from template 01

Copy the template into its own repository and rename it in one pass. Independently verifiable via `git log` and a clean baseline test run.

**Files:**
- Create: `../bearust-saas/` from `boilerplate/src/01-go-next-template` (copy, then remove `e2e-artifacts`, `src/frontend/node_modules`, `src/frontend/.next`).
- Run: `scripts/init-project.py` with `NAME="Bearust SaaS"`, `SLUG=bearust-saas`, Go module `github.com/Bearust/saas/backend`.
- Create: private GitHub repository `Bearust/saas`, set as origin, push initial commit.

**Validation:** `git log` shows the init commit; working tree clean afterwards.

- [x] Copy template and run init-project rename
- [x] Create private `Bearust/saas` repo and push

### Task 2: Verify the template baseline

Prove the rename did not break the stack before adding features.

**Files:**
- Modify: `.env` (local only, from `.env.example` plus `make key-generate` output).

**Validation:** `make dev` serves the app, `make db-up` + `make db-seed` succeed, `make test` is green.

- [x] Bring up `make dev` with seeded database
- [x] Run `make test` green on the untouched baseline

### Task 3: Public landing in the same frontend

Marketing surface for `bearust.cloud` without a second app or deploy.

**Files:**
- Create: `src/frontend/src/app/(marketing)/page.tsx` — hero, feature grid, quick-start snippet, signup CTA.
- Create: `src/frontend/src/app/(marketing)/pricing/page.tsx` — free/pro/business tiers (static copy, no billing logic).
- Modify: public navigation/legal links to point at docs (`https://docs.bearust.cloud`) and GitHub.

**Validation:** `/` and `/pricing` render without login; dashboard routes still redirect anonymous users to login.

- [x] Build landing + pricing public routes
- [x] Verify anonymous access to landing, protected dashboard

### Task 4: Public SaaS authentication

Switch the template from internal SSO default to public self-signup.

**Files:**
- Modify: `.env.example` — `AUTH_PASSWORD_ENABLED=true`, public provider credentials documented, Gate flags off or remapped.
- Modify: `src/backend/internal/auth/gate_roles.go` — mapping that admits public users (or gate disabled path).
- Modify: `src/backend/database/seeders/role_seeder.go` — default customer-facing roles.

**Validation:** new user can register and log in with password; at least one public OAuth provider links to an existing account; unmapped SSO user sees the access-denied message; app refuses to boot with all methods disabled.

- [x] Enable password + public OAuth, remap/disable Gate
- [x] Test register, login, link/unlink, and no-auth boot refusal

### Task 5: Region and edge-node data model

Schema everything else builds on. Independently testable via migrate up/down and seeders.

**Files:**
- Create: `src/backend/database/migrations/NNNNN_edge_inventory.up.sql` / `.down.sql` — `regions` (code unique, name, provider, status) and `edge_nodes` (name, region FK, address, status, max_tenants, bandwidth_mbps cap, notes) plus indexes. Down migration fully reverses up.
- Modify: models file for the two new structs.
- Modify: seeders — 2 regions, 2 example nodes (1 active).

**Validation:** `db-up`/`db-down` round-trips cleanly; seeder suite passes; negative quotas rejected at validation layer.

- [x] Write and apply edge inventory migration
- [x] Seed regions + example nodes

### Task 6: Edge management API with RBAC

Admin/operator CRUD for regions and nodes; viewer read-only.

**Files:**
- Create: `src/backend/internal/edge/` — service (CRUD + quota validation), handlers, routes.
- Modify: `src/backend/database/seeders/permission_seeder.go` — `regions.read/manage`, `edge_nodes.read/manage`.
- Modify: role seeder — attach new permissions to admin/operator/viewer appropriately.

**Validation:** API tests cover create/read/update/delete, 404 codes (`REGION_NOT_FOUND`, `EDGE_NODE_NOT_FOUND`), 422 on invalid quota (`QUOTA_INVALID`), 403 for viewer writes, 409 deleting a region still referenced (`REGION_IN_USE`).

- [x] Implement regions + nodes CRUD with quota validation
- [x] Cover RBAC and error codes with API tests

### Task 7: Edge dashboard UI

Operator-facing inventory management reusing template patterns.

**Files:**
- Create: `src/frontend/src/app/(main)/dashboard/edge/` — list page with region filter + status badges, detail page, create/edit form (region select, quota inputs).
- Create: `src/frontend/src/app/(main)/dashboard/regions/` — minimal list/create UI.
- Modify: `src/frontend/src/navigation/sidebar/sidebar-items.ts` — Edge and Regions entries.
- Create: `src/frontend/e2e/edge-nodes.spec.ts` — create → edit quota → delete flow.

**Validation:** Vitest suites for new components pass; Playwright spec passes; `tsc`/lint clean per template checks.

- [x] Build edge list/detail/form pages with quota inputs
- [x] Add sidebar entries and e2e spec

### Task 8: Basic per-node monitoring

Lightweight status visibility, mock-tolerant at first.

**Files:**
- Create: scheduler/worker job polling each node's health endpoint on an interval; store snapshots (status, latency ms, checked-at).
- Modify: edge detail UI — status timeline/latest snapshot panel, clearly labeled sample data when the node has no agent yet.

**Validation:** worker test with stub endpoint records snapshots; detail page shows fresh check timestamp after a poll cycle.

- [x] Add polling job + snapshot storage
- [x] Show node status history in detail view

### Task 9: Domain and environment wiring (no deploy)

Prepare production config without performing the deploy.

**Files:**
- Modify: `.env.example` — `APP_URL=https://bearust.cloud`, `AUTH_CALLBACK_BASE` matching apex, documented `DOCS_SITE_URL=https://docs.bearust.cloud` note for the docs repo.
- Create/extend: deployment notes doc for apex vs docs subdomain split.

**Validation:** production compose config renders with the new values in dry-run; no deploy executed.

- [x] Document apex/docs domain split and production env

---

## Risks

- Template Gate SSO default conflicts with public signup; Task 4 is scheduled before any customer-facing work for this reason.
- Scope creep into real VM provisioning or data-plane bandwidth enforcement; explicitly deferred — this plan is control plane plus monitoring stub.
- Go module path `github.com/Bearust/saas/backend` assumes the organization name; confirm before running init-project (it refuses to run twice).
- Next migration number and seeder file layout must be read from the fresh copy at execution time, not assumed here.

## Open Questions

- None blocking. Seed regions default to 2 (1 active) unless changed at execution. Landing ships English-first; additional locales follow later.
