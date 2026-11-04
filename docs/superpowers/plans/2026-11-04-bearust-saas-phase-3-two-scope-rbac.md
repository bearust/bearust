# Bearust SaaS Phase 3: Two-Scope RBAC and Multi-Organization Membership

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate the platform (staff) scope from the organization (tenant) scope. Platform staff manage tenants and infrastructure through platform roles; each organization manages its own members and roles. Both scopes support custom roles. A user may belong to several organizations, and staff reach tenant data only through audited impersonation.

**Builds on:** `2026-11-01-bearust-saas-phase-2-tenant-self-service.md` (organizations, domains, pools, routes, certificates, `/app`, all delivered in `../bearust-saas`).

**Architecture:** One RBAC engine with two scopes. `permissions` and `roles` carry a `scope` (`platform` | `organization`). Platform roles are assigned per user; organization roles are assigned per (organization, user) membership. Every authorization check names its scope: `Authorize(user, permission, Platform)` or `Authorize(user, permission, Org(id))`. The organization id comes from the caller's membership (selected by an `X-Org-ID` header or the URL and validated against it), never from a request body. Tenant rows stay filtered by `org_id`; cross-org access stays 404.

**Tech Stack:** Same as Phase 2 (Go/Fiber/GORM/golang-migrate, Next.js server actions, shadcn/ui, Vitest, Playwright). No Bearust core changes.

## Facts the plan relies on (verified 2026-11-04)

- RBAC today is global: `roles` (with `rank`), `permissions`, `role_permissions`, `user_roles`; checks through `rbac.RequirePermission`; rank rules prevent assigning above one's own rank.
- Sign-up (`internal/auth/password_routes.go`) gives every user the global `Viewer` role and a personal organization (`org.CreatePersonal`).
- `organization_members.role` is a fixed `owner|member`; `/org/*` handlers check `owner` for writes.
- Seeded roles: Super Admin, Operator, Viewer, Employee, Student. Employee and Student exist only for the Unmer Gate role mapping (`internal/auth/gate_roles.go`); Unmer Gate is also an auth provider (`internal/auth/provider.go`, `AUTH_UNMER_*` config).
- Impersonation exists (`internal/auth/impersonate.go`, permission `users.impersonate`, rank-checked, banner in the dashboard) and works for any user.
- The frontend decides "staff" by guessing from permissions (`src/lib/tenant-access.ts`); `/auth/landing` routes staff to `/dashboard`, everyone else to `/app`.

## Decisions (2026-11-04)

- A user **may belong to several organizations**; `/app` gets an organization switcher.
- Staff access tenant data through **impersonation with audit** (no separate support-access grant).
- **Custom organization roles are available on every plan.**
- System organization roles: **Owner, Admin, Developer, Viewer**.
- System platform roles: **Super Admin, Platform Admin, Operator, Support, Billing, Viewer**; custom platform roles stay possible.
- **Remove Employee, Student, the Unmer Gate role mapping and the Unmer Gate provider.**
- Billing (Phase 4) is planned now; the `Billing` platform role and `org.billing.*` permissions are created here with no billing screens yet.

## Global Constraints

- All earlier global constraints apply (English in repo, Conventional Commits, SNAKE error codes, RBAC via seeders, at least one login method, cross-org access returns 404).
- A role holds permissions of its own scope only; enforced in the service and by a database trigger.
- Nobody grants a permission they do not hold, and nobody assigns or edits a role ranked at or above their own (platform) or outside their reach (organization: Owner is required to touch Owner).
- An organization always keeps at least one Owner; the last Owner cannot leave, be removed or be demoted.
- A user without a platform role is not staff, whatever else they hold. Sign-up assigns no platform role.
- Impersonation of a tenant user is audited on both sides: the platform audit log and the organization's audit log name the staff member; sessions expire after 60 minutes; Super Admins cannot be impersonated; `impersonate.staff` is Super Admin only.
- New error codes: `ORG_ROLE_NOT_FOUND`, `ORG_ROLE_IN_USE`, `ROLE_SCOPE_MISMATCH`, `LAST_OWNER`, `MEMBER_NOT_FOUND`, `INVITATION_NOT_FOUND`, `INVITATION_EXPIRED`, `ALREADY_MEMBER`, `ORG_REQUIRED`.

---

## Permission catalog

Platform scope:
- Tenants: `organizations.read`, `organizations.manage` (suspend, activate), `organizations.plan.manage`, `organizations.placements.manage`, `organizations.members.read`
- Infrastructure: `regions.read`, `regions.manage`, `edge_nodes.read`, `edge_nodes.manage`, `certificates.read`
- Access: `impersonate.tenant`, `impersonate.staff`
- System (existing, re-scoped): `dashboard.read`, `users.*`, `platform.roles.manage` (was `roles.*`), `permissions.read`, `settings.manage`, `queue.*`, `audit.read`, `ai.*`, `exports.*`
- Billing (used in Phase 4): `billing.read`, `billing.manage`, `plans.manage`

Organization scope:
- `org.read`, `org.settings.manage` (name, slug)
- `org.placements.manage`
- `org.domains.read`, `org.domains.manage`
- `org.pools.read`, `org.pools.manage`, `org.routes.read`, `org.routes.manage`
- `org.certificates.read`, `org.certificates.manage` (retry)
- `org.members.read`, `org.members.manage` (invite, remove, assign roles)
- `org.roles.manage`
- `org.audit.read`
- `org.billing.read`, `org.billing.manage` (used in Phase 4)
- `org.delete`

System organization roles:
- **Owner**: everything, including `org.delete` and Owner management.
- **Admin**: everything except `org.delete`, Owner management and `org.billing.manage`.
- **Developer**: read everything; manage placements, domains, pools, routes, certificates.
- **Viewer**: every `org.*.read`.

System platform roles:
- **Super Admin**: all platform permissions.
- **Platform Admin**: all except `platform.roles.manage`, `impersonate.staff` and managing Super Admins.
- **Operator**: regions, edge nodes, `certificates.read`, `organizations.read`, `organizations.placements.manage`.
- **Support**: `organizations.read`, `organizations.members.read`, `impersonate.tenant`, `audit.read`.
- **Billing**: `organizations.read`, `billing.*`, `plans.manage`, `organizations.plan.manage`.
- **Viewer**: every platform `*.read`, no impersonation.

---

## File Map

Bearust SaaS (`bearust-saas`):
- Create: migrations `000020_rbac_scopes`, `000021_org_membership_roles`, `000022_org_invitations`, `000023_drop_unmer_roles`.
- Modify: `internal/rbac/` — scoped `Authorize`, scope checks, organization role CRUD, rank/escalation rules per scope.
- Modify: `internal/org/` — memberships with roles, invitations, organization selection, per-permission checks instead of `owner`.
- Modify: `internal/domains/`, `internal/lbconfig/`, `internal/certs/`, `internal/org/handler.go` — `RequireOrgPermission`.
- Modify: `internal/auth/` — sign-up without platform role, impersonation of tenants with dual audit and expiry, remove Unmer Gate.
- Modify: `database/seeders/` — catalogs and system roles for both scopes.
- Create: `src/frontend/src/app/(main)/app/settings/` — members, invitations, roles.
- Modify: `src/frontend/src/app/(main)/app/` — organization switcher, permission-driven UI.
- Modify: `src/frontend/src/app/(main)/dashboard/` — organization detail (members and roles read-only, impersonate), platform roles screen limited to platform permissions.
- Modify: `docs/openapi.yaml`, README, `.env.example`, charts.

---

### Task 1: Scoped permissions and roles

**Files:** migration `000020_rbac_scopes`, `internal/rbac/`, seeders.

- Add `scope` to `permissions` and `roles` (default `platform` for existing rows), `org_id` (nullable) and `is_system` to `roles`. `CHECK (scope = 'platform' AND org_id IS NULL OR scope = 'organization')`. Unique `(org_id, name)` with `NULLS NOT DISTINCT` for system roles.
- Trigger on `role_permissions` refusing a permission whose scope differs from the role's.
- Rename `user_roles` to `platform_role_assignments` (view or rename + code change) and refuse organization-scope roles there.
- `rbac.Authorize(ctx, user, perm, scope)` with `scope` either `Platform` or `Org(id)`; keep `RequirePermission` as the platform shorthand.
- Seed both catalogs and the system roles listed above; Platform Admin, Support and Billing are new.

**Validation:** Postgres tests for the scope trigger and constraints; unit tests for `Authorize` over both scopes, including a platform permission never satisfying an organization check and vice versa.

- [ ] Schema, trigger, seeds
- [ ] Scoped `Authorize`

### Task 2: Organization memberships with roles

**Files:** migration `000021_org_membership_roles`, `internal/org/`, `internal/rbac/`.

- `organization_member_roles(org_id, user_id, role_id)`; a role must be a system organization role or a custom role of the same organization (enforced by a composite foreign key or trigger).
- Data migration: `owner` → Owner, `member` → Developer; drop `organization_members.role` after the code switch.
- Organization selection: `X-Org-ID` header (frontend sends the selected org); without it, the oldest membership. A non-member org id answers 404 `ORG_NOT_FOUND`.
- `GET /me/organizations` lists memberships with role names and the caller's effective organization permissions.
- Replace every `owner` check in `/org/*` with `RequireOrgPermission(perm)`; reads need the matching `*.read`.
- Last-owner rule in one place (`org.ensureOwnerRemains`).

**Validation:** handler tests per permission (allowed, denied 403, other org 404); Postgres test for the data migration; tests for the last-owner rule.

- [ ] Membership roles + migration
- [ ] Organization selection + `/me/organizations`
- [ ] Permission checks on every `/org/*` route

### Task 3: Members, invitations and custom organization roles

**Files:** migration `000022_org_invitations`, `internal/org/`, `internal/notify/` or mail templates.

- Invitations: `organization_invitations(id, org_id, email, role_ids, token_hash, invited_by, expires_at, accepted_at)`; mailed link valid 7 days; accepting requires being signed in with that email (or signing up with it); `ALREADY_MEMBER` when applicable.
- `GET/POST/DELETE /org/members`, `PUT /org/members/{user_id}/roles`, `GET/POST/DELETE /org/invitations`, `POST /invitations/{token}/accept`.
- `GET/POST/PUT/DELETE /org/roles` for custom roles; `GET /org/permissions` lists the organization catalog; system roles are read-only; deleting a role in use answers `ORG_ROLE_IN_USE`.
- Escalation rules: a member can only grant permissions they hold and can only assign roles whose permission set is a subset of theirs; only Owners touch Owner.

**Validation:** handler tests for escalation attempts (granting `org.delete` as Admin, assigning Owner as Admin, editing a system role), invitation expiry and email mismatch, role in use.

- [ ] Members and invitations
- [ ] Custom organization roles

### Task 4: Sign-up, staff identity, and Unmer Gate removal

**Files:** `internal/auth/password_routes.go`, OAuth/e2e user creation paths, `internal/auth/gate_roles.go`, `internal/auth/provider.go`, `internal/config/`, migration `000023_drop_unmer_roles`, seeders, `.env.example`, charts.

- Sign-up creates the personal organization with the user as Owner and assigns **no** platform role. Data migration: users whose only platform role is Viewer and who own an organization lose the platform Viewer role.
- `GET /me/permissions` returns `platform_permissions` and `is_staff` (has any platform role). The frontend uses `is_staff` instead of guessing (`tenant-access.ts` is removed).
- Remove the Unmer Gate provider, its config and role mapping; delete Employee and Student (reassign any holders to nothing, logged). At least one login method must remain enabled.

**Validation:** sign-up test (no platform role, Owner of a new org); migration test; config test that refuses to start with no login method; existing auth tests updated.

- [ ] Sign-up without platform role + data migration
- [ ] `is_staff` in the permission context
- [ ] Remove Unmer Gate, Employee, Student

### Task 5: Tenant impersonation with dual audit

**Files:** `internal/auth/impersonate.go`, `internal/activity/` (or audit), `internal/org/` (organization audit log).

- `impersonate.tenant` lets staff impersonate users who hold no platform role; `impersonate.staff` (Super Admin only) covers staff targets below the actor's rank; Super Admins are never targets.
- Sessions expire after 60 minutes regardless of refresh; every request made while impersonating is attributed to both identities.
- Organization audit log (`org_audit_events`) records "staff X started/stopped impersonating member Y" and every write made during the session; tenants read it at `GET /org/audit` (`org.audit.read`).
- Staff start impersonation from the organization detail page (choose a member).

**Validation:** tests for each target rule, expiry, dual attribution, and the organization audit entries.

- [ ] Target rules + expiry
- [ ] Organization audit log

### Task 6: Frontend

**Files:** `src/frontend/src/app/(main)/app/**`, `src/frontend/src/app/(main)/dashboard/**`, `src/lib/api/`, i18n.

- `/app`: organization switcher (stored in a cookie, sent as `X-Org-ID` by the backend proxy), UI driven by the effective organization permissions (hide or disable what the member cannot do), settings pages for members, invitations and roles (permission checklist grouped by area), audit log.
- Invitation accept page (`/invite/{token}`), including the sign-up path.
- `/dashboard`: only for `is_staff`; organizations list and detail (placements, members and their roles read-only, "Impersonate"); the Roles screen only lists and edits platform roles and platform permissions.
- `/auth/landing`: staff → `/dashboard`, everyone else → `/app`; a staff member who also belongs to organizations can switch from the account menu.

**Validation:** Vitest for permission-driven rendering and forms; Playwright `org-members.spec.ts` (Owner invites a member as Developer → member accepts → member cannot manage members → Owner creates a custom role with `org.members.read` and assigns it), `org-impersonation.spec.ts` (Support impersonates a tenant member, the tenant sees it in the audit log), existing specs updated (Viewer becomes a staff-only role).

- [ ] Switcher + permission-driven `/app`
- [ ] Members, invitations, roles, audit pages
- [ ] Staff organization detail + impersonation
- [ ] E2E

---

## Risks

- **Authorization regressions:** every `/org/*` handler changes its check. Mitigation: a table-driven test that walks every registered `/org` route with members of each system role and with a member of another organization.
- **Privilege escalation through custom roles:** the subset rule must hold for creation, edit and assignment; tested explicitly.
- **Data migration of existing users:** customers currently hold the platform Viewer role; the migration removes it only when the user owns an organization and has no other platform role, and logs every change.
- **Impersonation abuse:** limited by permission, target rules, 60-minute expiry and audit visible to the tenant.
- **Header-selected organization:** `X-Org-ID` is only a selector; membership is always re-checked server-side.
