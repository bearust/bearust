# Bearust SaaS Phase 2: Tenant Self-Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a signed-up customer create an organization, add and verify domains, and configure proxy routing and load balancing (hosts, upstream pools, routes, TLS) from the Bearust SaaS dashboard, with the configuration applied to the Bearust edge nodes assigned to them.

**Builds on:** `2026-10-25-bearust-saas-mvp.md` (regions, edge nodes, quotas, health checks, public signup — all delivered in `../bearust-saas`).

**Architecture:** The SaaS (Go + Postgres) is the single source of truth for tenant configuration. Each Bearust node stays single-tenant-unaware: the SaaS renders the *complete* desired state for a node (all tenants placed on it) and pushes it to the node's control API. Tenant isolation is enforced in the SaaS (ownership, quotas, domain verification), never in Bearust. A queue job per node performs the sync with a monotonically increasing generation, retries, and drift detection, reusing the template's queue + scheduler.

**Tech Stack:** Same as the MVP (Go/Fiber/GORM/golang-migrate, Next.js server actions, shadcn/ui, Vitest, Playwright). Bearust core (Rust) receives small, additive control-API changes in Task 2.

## Facts the plan relies on (verified 2026-11-01)

- Bearust control API lives on `127.0.0.1:81`, loopback-only, authenticated by **session cookie only** (`src/control_plane/auth.rs`); there is no machine/API-token auth yet.
- Relevant endpoints already exist: `/api/proxy-hosts` (`ProxyHost { name, domain, upstream_host, upstream_port, tls_mode, certificate_id, enabled }`), `/api/load-balancer` (`LoadBalancerConfigRequest { pools, routes }` mirroring the TOML model, plus a `generation` in the snapshot), `/api/certificates/acme`, `/api/certificates/{id}/status`, `/api/health`, `/api/cluster/status`.
- `DesiredConfig { proxy_hosts }` and `runtime_sync.rs` exist in the control plane; reuse them rather than inventing a parallel format.
- Bearust has no notion of tenants. SaaS currently assigns every signup the `Viewer` role and has no organization model.

## Global Constraints

- All MVP global constraints still apply (English in repo, Conventional Commits, SNAKE error codes, RBAC via seeders, at least one login method).
- New error codes: `ORG_NOT_FOUND`, `DOMAIN_NOT_FOUND`, `DOMAIN_TAKEN`, `DOMAIN_UNVERIFIED`, `POOL_NOT_FOUND`, `ROUTE_NOT_FOUND`, `QUOTA_EXCEEDED`, `NODE_CAPACITY_EXHAUSTED`, `SYNC_FAILED`.
- Every tenant-owned row carries `org_id`; every tenant query is scoped by the caller's org. Cross-org access returns 404, not 403.
- A domain must be verified before any route or certificate uses it. A domain is globally unique across orgs.
- Bearust core changes are additive and backward compatible; the open-source single-node dashboard must keep working unchanged.
- No billing and no production deploy in this phase. Plan limits are config/seed values, enforced in the SaaS.

---

## File Map

Bearust core (`bearust`):
- Modify: `src/control_plane/auth.rs` — accept scoped API tokens (`Authorization: Bearer`).
- Modify: `src/control_plane/mod.rs`, `models.rs`, `repository.rs` — token CRUD + a bulk desired-state apply endpoint.
- Modify: `DEPLOY.md` — exposing the control API to a managing plane over a private network.

Bearust SaaS (`bearust-saas`):
- Create: migrations `000015_organizations`, `000016_domains`, `000017_lb_config`, `000018_node_sync`.
- Create: `src/backend/internal/org/` — organizations, membership, plan limits, node placement.
- Create: `src/backend/internal/domains/` — domain CRUD, DNS TXT verification job.
- Create: `src/backend/internal/lbconfig/` — pools, backends, routes, proxy hosts, validation.
- Create: `src/backend/internal/nodesync/` — desired-state renderer, Bearust client, sync job, drift check.
- Create: `src/frontend/src/app/(main)/app/` — tenant area: overview, domains, hosts/routes, pools, certificates, sync status.
- Modify: sidebar + post-login redirect (tenants land in `/app`, staff in `/dashboard`).
- Modify: `src/frontend/src/app/(main)/dashboard/edge/` — admin view of tenants per node and sync status.
- Create: `src/frontend/e2e/tenant-*.spec.ts`.

---

### Task 1: Organizations, membership, and placement

Every signup gets a personal organization; tenants are placed on edge nodes within quota.

**Files:** migration `000015_organizations` (`organizations`, `organization_members` with role `owner|member`, `plans`, `org_node_placements`), `internal/org/`, signup hook in `internal/auth/password_routes.go`.

- Placement: per region the org enables, choose an `active` node with `count(placements) < max_tenants`; return `NODE_CAPACITY_EXHAUSTED` otherwise. An org may span several regions (one node per region in this phase); the number of regions is a plan limit (`free`: 1).
- Each org gets a unique `slug` (DNS label rules, reserved words blocked: `www`, `api`, `docs`, `app`, `admin`, …) used for its free subdomain.
- Plans seed: `free` (1 domain, 1 pool, 3 backends), `pro`, `business` — limits only, no billing.

**Validation:** Go tests for signup → org created, placement respects `max_tenants`, cross-org reads return 404.

- [x] Migration + models + placement service
- [x] Signup creates org; tests for quota and isolation

### Task 2: Machine access to Bearust nodes (bearust core)

The SaaS must call a node's control API without a browser session.

**Files:** `bearust/src/control_plane/{auth.rs,mod.rs,models.rs,repository.rs}`, `DEPLOY.md`.

- Add hashed API tokens with a scope (`config:write`, `read`), created from the dashboard/CLI, shown once, revocable, audited.
- Add `PUT /api/desired-state` taking `{ generation, proxy_hosts, pools, routes, certificates (PEM chain + key), acme_challenges }`: validates the whole document, applies atomically (reuse `runtime_sync.rs` + the `/api/load-balancer` path), rejects stale generations with 409, returns the applied generation.
- Keep the API loopback by default; document binding to a private interface (WireGuard/VPC) for managed nodes. Never expose it publicly.

**Validation:** `cargo test` for token auth, scope denial, stale-generation 409, atomic rollback on invalid input; existing dashboard tests unchanged.

- [x] API tokens with scopes + audit
- [x] Atomic desired-state endpoint with generation check

**Delivered (2026-11-01):** `migrations/0027_api_tokens_desired_state.sql`, `src/control_plane/machine_api.rs`, `tests/control_plane_machine_api.rs`, DEPLOY.md "Managed nodes". Deviations: the document carries `pools` and `routes` only (tenant hosts render straight to pools/routes, so no `proxy_hosts`); `certificates` and `acme_challenges` are added in Task 6 where they are first needed. Dashboard-created `proxy-host-*` pools/routes are preserved and reserved. Tokens are created over the API from a session; a dashboard/CLI screen is a follow-up.

### Task 3: Domains and DNS verification

**Files:** migration `000016_domains` (`domains`: `org_id`, `name` unique, `status pending|verified|failed`, `verification_token`, `verified_at`), `internal/domains/`, scheduled job.

- Verification via TXT record `_bearust-verify.<domain>`; a scheduler job re-checks pending domains with backoff and expires after 7 days.
- Also show the CNAME target the customer must point at: `<slug>.bearust.cloud`.
- Free subdomain: every org automatically owns `<slug>.bearust.cloud`, created already `verified` (platform-owned zone, no TXT check) and not counted against the domain quota. Its DNS records (one A/AAAA per placed node, or a geo/latency record per region) are managed by the SaaS through the `bearust.cloud` DNS provider API behind a `DNSProvider` interface; pick the provider in this task and keep a fake for tests.

**Validation:** unit tests with a fake resolver; quota `QUOTA_EXCEEDED` on plan limit; `DOMAIN_TAKEN` across orgs.

- [x] Domain CRUD + TXT verification job
- [x] Tests for uniqueness, quota, expiry

**Delivered (2026-11-01):** DNS provider is Cloudflare (`DNS_PROVIDER=cloudflare`, zone-scoped token), behind a `Zone` interface with a no-op default for development. Platform hostnames get A records only for nodes whose `address` is a public IPv4; nodes with private addresses are skipped (a separate public-IP field may be needed later).

### Task 4: Routing and load-balancer configuration

**Files:** migration `000017_lb_config` (`pools`, `pool_backends`, `routes`, `proxy_hosts`, all `org_id`-scoped), `internal/lbconfig/`.

- Model mirrors Bearust's `PoolConfig`/`RouteConfig`: pool algorithm (round robin, least connections, weighted…; take the exact list from `crate::config`), backend host/port/weight, health check path/interval, route host + path prefix → pool, proxy host with TLS mode.
- Validate in the SaaS before saving: route hosts must be verified domains of the same org; backends cannot target private/loopback ranges or edge-node addresses (SSRF guard); plan limits.
- Every write bumps the org's config revision and enqueues a sync for the org's nodes.

**Validation:** table-driven validation tests, SSRF guard tests, RBAC (`owner` writes, `member` read-only).

- [x] Schema + CRUD API with validation
- [x] SSRF, ownership, and quota tests

**Delivered (2026-11-01):** `pools`, `pool_backends`, `routes`, `organizations.config_revision`. Backends are IP literals only (Bearust dials `SocketAddr`), which also rules out DNS rebinding. Routes reference `domain_id`, so platform hostnames follow slug changes. There is no separate `proxy_hosts` table: a route is the host entry, and its TLS mode moves to Task 6. The `plugin` algorithm is not offered to tenants.

### Task 5: Node sync engine

**Files:** migration `000018_node_sync` (`node_credentials` encrypted token per node, `node_sync_states`: desired generation, applied generation, last error, last synced), `internal/nodesync/`.

- Renderer: build one document per node from every org placed on it; deterministic ordering so identical input yields identical output (hash stored to skip no-op syncs).
- Job `nodesync.apply` per node, deduplicated, retried with backoff; on success records applied generation; on failure `SYNC_FAILED` with the node's error message.
- Scheduler job for drift: compare node-reported generation with desired; re-enqueue on mismatch.
- Admin dashboard: per-node sync status and "resync now"; node credential entry on the edge node form.

**Validation:** renderer golden tests; job tests against an `httptest` fake Bearust; one manual run against a local Bearust from `bearust/docker-compose.dev.yml`.

- [x] Renderer + client + sync job
- [x] Drift check, admin status view, local end-to-end run

**Delivered (2026-11-01):** credentials live on `edge_nodes` (`control_url`, `api_token_ciphertext`, AES-256-GCM with `SECRETS_KEY`) instead of a separate `node_credentials` table. The reconcile job applies nodes in-line every minute rather than one queued job per node; a failed node is retried on the next run. Config changes therefore reach nodes within about a minute; an immediate push on save can be added later. The admin "status view" is the API (`GET/POST /edge-nodes/{id}/sync`); its dashboard screen belongs to Task 7. End-to-end run: `TestLiveBearustSync` against a local `bearust serve` with a write token passed.

### Task 6: Certificates (central issuance)

Orgs may span regions, so one node cannot complete HTTP-01 for a hostname served by several nodes. Certificates are issued centrally in the SaaS and pushed to nodes as part of desired state.

- Free subdomains: one wildcard `*.bearust.cloud` certificate via ACME DNS-01 using the `DNSProvider` from Task 3, renewed by a scheduler job.
- Customer domains: ACME DNS-01 is not possible on zones the SaaS does not control, so use HTTP-01 with a shared challenge: the SaaS stores the token, and every node answers `/.well-known/acme-challenge/*` for that host from desired state (Bearust core addition in Task 2: a `acme_challenges` field in the desired-state document).
- Private keys encrypted at rest in Postgres; pushed only to nodes where the org is placed.
- Renewal job 30 days before expiry; failures surface in the tenant UI and admin node view.

**Validation:** issuance and renewal tests against Pebble (local ACME test server) in Docker; desired-state golden tests include certificates and challenges.

- [ ] Central ACME client (DNS-01 wildcard + shared HTTP-01)
- [ ] Renewal job + tenant certificate status UI

### Task 7: Tenant dashboard

**Files:** `src/frontend/src/app/(main)/app/**`, navigation, post-login redirect.

- Pages: overview (placement region, plan usage, sync status), domains (add, DNS instructions, verify state), proxy hosts/routes, pools/backends, certificates.
- Show "pending apply / applied / failed" per change from `node_sync_states`.

**Validation:** Vitest for forms and actions; Playwright `tenant-onboarding.spec.ts` (signup → domain (verification stubbed in E2E) → pool → route → applied against a fake node).

- [ ] Tenant pages + server actions
- [ ] E2E onboarding flow

### Task 8: Tenant visibility (basic)

- Per-tenant request counts and status codes from node analytics (`/api/analytics/summary`, `/api/analytics/timeseries`), filtered by the tenant's domains in the SaaS. If node analytics cannot filter by host, record that as a Bearust follow-up and ship only sync/health status.

**Validation:** client tests with fixture responses; empty state when data is unavailable.

- [ ] Host-filtered analytics or documented follow-up

---

## Risks

- **Control API exposure:** pushing config across the network turns a loopback-only API into a remote one. Mitigation: scoped tokens, private network only, per-node credentials encrypted at rest, audit on both sides.
- **Blast radius:** one bad document can break every tenant on a node. Mitigation: SaaS-side validation, Bearust-side atomic apply with rollback, generation guard.
- **Noisy neighbours:** no per-tenant bandwidth/rate enforcement on the data plane yet; per-host rate limits in Bearust are the first lever, true bandwidth enforcement stays out of scope.
- **SSRF via backends:** customers choosing upstream addresses is the main abuse path; the guard in Task 4 is mandatory.
- **Central certificate keys:** the SaaS database now holds every tenant's private keys; encryption at rest with a key outside the database is mandatory.
- **Free subdomain abuse:** free `<slug>.bearust.cloud` hosts are a phishing magnet; reserved/lookalike slug blocking plus an admin suspend switch are part of Task 1/3.

## Decisions (2026-11-01)

- Sync direction: **push** (SaaS → node control API).
- Every org gets a free subdomain **`<slug>.bearust.cloud`**.
- An org **may span multiple regions** in this phase (one node per region; region count is a plan limit).
