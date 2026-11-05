# Bearust SaaS Phase 5: Usage Metering and Free-Tier Guardrails

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the cost of free (and every) plan bounded: meter traffic per tenant, enforce monthly quotas and per-host rate limits, keep Free tenants on dedicated nodes, and reclaim inactive Free organizations. **The Free plan must not be opened to the public before this phase is delivered.**

**Builds on:** Phase 2 (desired state, nodes, placements), Phase 3 (scopes, one Free organization per user), Phase 4 (plans with quotas, trial). Tasks 1–2 only depend on Phase 2 and may start earlier.

**Architecture:** Bearust meters requests and bytes per host on the data plane and exposes counters to a read-scope API token. The SaaS polls every node, stores usage per organization per hour, compares it with the plan's quotas, and acts through the desired-state document: per-host rate limits are rendered into routes, and a paused organization's routes are rendered as a "paused" response instead of its pools. Nodes carry a tier; placement keeps Free and trial organizations on Free nodes.

**Tech Stack:** Same as earlier phases; Bearust core (Rust) gains metering and per-route limits.

## Decisions (2026-11-04)

- Free plan defaults (staff-editable per plan): 1 Free organization per user, 1 region on a Free node, platform subdomain only (**no custom domains on Free**), 1 pool / 2 backends, **10 GB bandwidth and 1 million requests per month**, **20 requests/second per host**, request body limit, paused after **30 days without traffic** (warning 7 days before), configuration deleted **90 days after pausing**.
- **Quota exhausted → routes paused** (HTTP 503 with a Bearust page linking to upgrade) until the next billing month or an upgrade; the owner is emailed at 80% and 100%.
- 14-day Pro trial (Phase 4) runs on Free nodes.

## Global Constraints

- All earlier constraints apply.
- Metering never blocks the data plane: counters are in memory, bounded, and flushed; a SaaS outage loses at most one polling interval of precision, never traffic.
- Usage counts what leaves the edge (response bytes) plus request bytes, per host; health checks and ACME challenges are excluded.
- Enforcement is deterministic and explainable: the tenant sees current usage, the quota, and why a route is paused.
- New error codes: `QUOTA_BANDWIDTH_EXCEEDED`, `QUOTA_REQUESTS_EXCEEDED`, `ORG_PAUSED`, `FREE_NODE_CAPACITY_EXHAUSTED`, `CUSTOM_DOMAIN_REQUIRES_PAID_PLAN`.

---

## File Map

Bearust core (`bearust`):
- Modify: `src/analytics.rs` (or a new `src/metering.rs`) — per-host counters (requests, bytes in, bytes out, status classes), bounded host cardinality.
- Modify: `src/control_plane/machine_api.rs` — `GET /api/usage?since=<cursor>` for read-scope tokens; desired-state routes gain `rate_limit` and `paused`.
- Modify: proxy request path — per-route token-bucket rate limit, body size limit, paused response.

Bearust SaaS (`bearust-saas`):
- Create: migrations `000027_node_tiers`, `000028_usage`.
- Create: `internal/usage/` — poller job, hourly rollups per organization, quota evaluation, pause/resume, notifications.
- Modify: `internal/org/` placement (tier rule), `internal/domains/` (custom domains need a paid plan), `internal/nodesync/` (render rate limits and paused routes).
- Create: `internal/lifecycle/` — inactivity pause and deletion jobs.
- Modify: frontend `/app` (usage meters, paused banner), `/dashboard` (node tier, usage per organization, overrides).

---

### Task 1: Per-host metering in Bearust

- Counters per host (from the matched route): requests, bytes in, bytes out, 2xx/3xx/4xx/5xx; monotonic since process start plus a per-boot id so the SaaS can detect resets.
- `GET /api/usage` (read-scope API token) returns counters per host with the boot id; bounded to the hosts in the desired state.
- This also unblocks the Phase 2 Task 8 follow-up (per-domain analytics for tenants).

**Validation:** cargo tests for counting, exclusions (health checks, ACME), bounded cardinality, reset detection; existing analytics tests unchanged.

- [x] Counters + usage endpoint (bearust#1: `src/metering.rs`, `GET /api/usage` needs `ProxyHostsRead`; health checks are outbound probes, so only ACME challenges and unmatched requests are excluded; bytes are body bytes)

### Task 2: Per-route rate limit, body limit and paused routes

- Desired-state routes gain `rate_limit: {requests_per_second, burst}`, `max_body_bytes`, and `paused: bool`; paused routes answer 503 with a small branded page and `Retry-After`.
- Validation in the desired-state apply; omitted fields keep today's behaviour (unlimited, not paused).

**Validation:** cargo tests for the token bucket, body limit and paused response; machine API tests for the new fields.

- [x] Rate limit + body limit (bearust#2: one shared bucket per route, 429 with Retry-After; Content-Length over the limit gets 413 before the backend, streamed bodies are cut off with 413 once they pass it; buckets refill to full on every config apply)
- [x] Paused routes (bearust#3: 503 HTML page with `Retry-After: 3600`, checked before the rate limit so paused routes never touch their pool; the page tells visitors the owner can resume or upgrade from the Bearust dashboard but carries no per-tenant link)

### Task 3: Usage collection and quotas in the SaaS

- `usage.poll` job (every minute): read `/api/usage` from each managed node, compute deltas with boot-id reset handling, map hosts to organizations, store `usage_hourly(org_id, hour, requests, bytes_in, bytes_out, status counts)`.
- Billing month follows the subscription period (calendar month for Free).
- Quota evaluation after each poll: at 80% email the owners; at 100% mark the organization `paused_reason = quota` and resync its nodes; resume automatically at the next period or on upgrade.
- Plan quotas: `max_bandwidth_bytes_month`, `max_requests_month`, `rate_limit_rps`, `max_body_bytes` on `plans` (null = unlimited), rendered into each route.

**Validation:** delta and reset tests; Postgres rollup tests; quota threshold tests with a fake clock; render tests for limits and paused routes.

- [x] Poller + rollups
- [x] Quota evaluation, pause/resume, notifications
- [x] Limits rendered into desired state

### Task 4: Node tiers and Free placement

- `edge_nodes.tier` (`free` | `paid`); Free and trialing organizations are placed only on `free` nodes, paid organizations only on `paid` nodes; upgrading or downgrading moves the placement (new node first, then the old one is dropped after the next successful sync).
- When no Free node has capacity: `FREE_NODE_CAPACITY_EXHAUSTED` with an upgrade prompt.
- Custom domains require a paid plan (`CUSTOM_DOMAIN_REQUIRES_PAID_PLAN`); on downgrade to Free, custom-domain routes are paused (not deleted) and certificates stop renewing.

**Validation:** placement tests per tier; move-on-plan-change test; domain gating tests.

- [x] Tiers + placement (saas#36: `tier` column edited into 000014, default `free`; the seeder adds a paid node edge-sin-02; free-tier capacity error carries `details.upgrade`; moving placements on plan change is saas#42)
- [x] Custom domain gating

### Task 5: Inactivity lifecycle

- `lifecycle.inactive` job (daily): Free organizations with zero requests for 23 days get a warning email; at 30 days they are paused (`paused_reason = inactive`); any sign-in plus "Resume" un-pauses.
- 90 days after pausing, the organization's configuration (routes, pools, domains, certificates) is deleted after a final email; the organization and its members remain.

**Validation:** job tests with a fake clock for warning, pause, resume and deletion.

- [x] Warning, pause, resume
- [x] Deletion

### Task 6: Frontend

- `/app`: usage meters (bandwidth, requests) with the period and quota; paused banner with the reason and an upgrade or resume action.
- `/dashboard`: node tier on the node form; usage per organization; staff override to lift a pause or grant a temporary quota boost (audited).

**Validation:** Vitest for meters and banners; Playwright `quota-pause.spec.ts` with a fake node reporting usage over quota → routes paused → upgrade (fake gateway) → resumed.

- [x] Tenant usage + paused banner
- [x] Staff views and overrides
- [x] E2E

---

## Progress (2026-11-05)

- Usage tables live in `000022_usage`; organization pause/boost fields and the placement retire pointer were edited into `000015_organizations` in place.
- `usage.poll` rolls cumulative per-boot node counters into `usage_hourly`; `lifecycle.inactive` handles the 23/30/90-day lifecycle.
- Plan limits and paused state are rendered into every route; Free custom-domain routes are paused and custom-domain certificate renewal skips them.
- Placement moves use the new node first and drop the old placement after that node acknowledges the desired state.
- Admin overrides and tenant resume are audited; `/dashboard/usage` and `/app` expose the meters and pause banner.
- E2E `quota-pause.spec.ts` passes against a fake node and the fake gateway.

### Review fixes (2026-11-05)

- Poll cursors lock inside the ingest transaction, a poll where every node fails returns an error, and host ownership comes from the same render that builds routes.
- The quota event is recorded in the pause transaction; pause/resume updates are conditional, inactivity wins over quota, and a staff lift holds until the period end. A scheduled pass resumes idle quota pauses at the boundary.
- `GET /usage` exposes `exceeded_quotas`; tenant resume of a quota pause returns `QUOTA_REQUESTS_EXCEEDED`/`QUOTA_BANDWIDTH_EXCEEDED`; paused configuration writes return `ORG_PAUSED` with the reason.
- The final deletion warning is sent at day 83 and deletion waits seven days after it; Free platform certificates keep renewing while custom certificates are skipped.

## Risks

- **Polling gaps:** a node unreachable for a while delays enforcement; counters are cumulative, so the next poll catches up and enforcement applies late, not never.
- **Shared-node noise:** rate limits bound per-host load, but a Free node can still saturate; capacity planning on Free nodes is an operations task (alert on node bandwidth).
- **False pauses:** wrong host-to-organization mapping would pause the wrong tenant; mapping uses the same render that builds routes, and every pause is audited and reversible by staff.
- **Abuse via many accounts:** limited by one Free organization per user, captcha, disposable-email blocking, and Free-node capacity; phishing reports lead to suspension.
