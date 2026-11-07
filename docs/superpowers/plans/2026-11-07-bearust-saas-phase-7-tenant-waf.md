# Bearust SaaS Phase 7: Per-Tenant WAF

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each organization protect its own hosts with Bearust's WAF from `/app`: choose monitor or block mode, turn the built-in signatures and the OWASP CRS on or off, add a few custom rules, and see what was logged or blocked. A tenant's WAF settings never affect another tenant on the same node.

**Builds on:** Phase 2 (desired state, routes, `nodesync`), Phase 4 (plans and entitlements), Phase 5 (per-node usage polling with a read-scope token).

**Architecture:** WAF policy becomes part of the desired-state document, attached to routes. The SaaS stores one policy per organization (with optional per-host overrides) and renders it into every route of that organization, the same way Phase 5 renders `rate_limit` and `max_body_bytes`. Bearust evaluates the policy of the matched route instead of one node-wide snapshot. The node-wide WAF stays for standalone (non-managed) Bearust and is ignored for managed routes. WAF events are counted per host on the node and read by the existing usage poller; a bounded, redacted sample of recent events is exposed for the tenant's event list.

**Tech Stack:** Same as earlier phases. Bearust core (Rust) gains per-route WAF policy and per-host WAF counters.

## Facts the plan relies on (verified 2026-11-07)

- Bearust's WAF is node-wide: `WafStore` holds one `ArcSwap<WafSnapshot>` with `{ mode: WafMode (MonitorOnly | Block), rules: Vec<CompiledRule>, seclang: Option<Arc<SecLangRuntime>> }` (`src/waf.rs`, `src/waf_store.rs`). The proxy evaluates that single snapshot for every request (`src/proxy.rs`).
- Rule actions include `WafAction::Inherit`, resolved from the snapshot's mode (`src/waf.rs` ~545).
- Compiling the OWASP CRS is slow; `seclang_runtime` reuses the previous runtime when settings are unchanged.
- `DesiredStateRequest { generation, pools, routes, certificates, acme_challenges }` (`src/control_plane/models.rs:704`) uses `crate::config::RouteConfig`, which already carries per-route `rate_limit`, `max_body_bytes` and `paused` rendered by the SaaS (`internal/nodesync/render.go`).
- The SaaS has no WAF code today (backend or frontend).

## Decisions (confirmed 2026-11-07)

- **Policy scope:** one policy per organization, with per-host overrides of mode only. Per-path policies are out of scope.
- **Custom rules:** structured matchers only (field, operator, value, action), reusing Bearust's bounded `regex` engine, at most 20 per organization. **No raw SecLang from tenants**: it is unbounded to compile and evaluate on a shared node.
- **CRS:** shared compiled ruleset per node, keyed by paranoia level (1–2 allowed for tenants), so N tenants do not mean N compilations.
- **Plans:** Free gets the built-in signatures in monitor mode only; paid plans get block mode, CRS and custom rules. Limits are plan fields staff can edit.
- **Default for new organizations:** built-ins on, monitor mode.

## Global Constraints

- All earlier constraints apply.
- Isolation: a policy rendered for one organization's routes can never change evaluation for another organization's routes. Tested in core and in the SaaS render.
- The data plane never waits on the SaaS. A node without a policy for a managed route treats it as WAF off, never as the node-wide WAF.
- Event samples are redacted (no bodies, no cookies or auth headers, query values truncated) and bounded per host.
- New error codes: `WAF_RULE_INVALID`, `WAF_RULE_LIMIT_EXCEEDED`, `WAF_FEATURE_REQUIRES_PAID_PLAN`.

---

## Task 1: Per-route WAF policy in Bearust core

- [x] Add `waf: Option<RouteWafPolicy>` to `RouteConfig` (`mode`, `builtins` enabled set, `crs: Option<{ paranoia }>`, `rules: Vec<WafRule>`), serde-defaulted so old documents still apply.
- [x] Compile route policies when the desired state is applied; cache compiled CRS runtimes per paranoia level and reuse them across routes and generations.
- [x] Proxy: for managed routes evaluate the matched route's compiled policy; keep the node-wide snapshot for non-managed routes.
- [x] Reject invalid policies in `PUT /api/desired-state` with a per-route error instead of applying a partial document.
- [x] Tests: two routes with different modes on one node, the same attack is blocked on one and logged on the other; CRS compiled once for many routes; old documents without `waf` still apply.

Deviations (2026-11-07):

- A route **without** `waf` still uses the node-wide WAF, so standalone Bearust and existing documents keep their behaviour. "Never the node-wide WAF for managed routes" is therefore enforced by the SaaS sending `waf` on every route it renders (Task 4), not by the node.
- Route policies work even when the node has no `WafStore`; detections are still traced and, when a store exists, written to the node audit log. Per-host counters come in Task 2.
- The HTTP/3 listener and the HTTP/3 upstream path also evaluate the route's policy, so isolation holds on every protocol.
- Built-in signatures get fixed negative rule ids (`sqli` -1, `xss` -2, `path_traversal` -3, `command_injection` -4); custom rule ids must be positive. The CRS inbound anomaly threshold is fixed at 5 (CRS default).
- In block mode the existing semantic SQLi scoring can block even when the `sqli` built-in is off (unchanged evaluator behaviour). The tenant UI should say so.
- Wire format: `{"mode":"block"|"monitor-only","builtins":[...],"crs":{"paranoia_level":1},"rules":[{"id":1,"category":"...","field":"any|method|path|query|headers|body","pattern":"...","action":"inherit|allow|log|block"}]}`.
- `http3::tests::upstream_clients_follow_changed_connect_timeouts` is timing-flaky on this machine before and after the change (2 of 5 baseline runs failed); not a regression.

## Task 2: Per-host WAF counters and event sample in Bearust core

- [ ] Count `waf_logged` and `waf_blocked` per host alongside the Phase 5 metering counters.
- [ ] Keep a bounded ring of recent redacted events per host (rule id, category, action, method, path, client IP, time).
- [ ] Expose both through the read-scope token API used by the usage poller.

## Task 3: SaaS data model and API

- [ ] Tables `waf_policies` (org-owned, mode, builtins, crs paranoia) and `waf_rules` (org-owned, structured matcher, action), plus `waf_host_overrides`; edit the owning migration in place (pre-production rule).
- [ ] Plan fields: `waf_block_mode`, `waf_crs`, `waf_custom_rules_max`.
- [ ] `/org/waf` endpoints (get/update policy, CRUD rules, host overrides) behind new org permissions `org.waf.read` / `org.waf.manage`, seeded into the default organization roles.
- [ ] Validate matchers with the same limits Bearust enforces, so invalid rules fail in the SaaS, not on the node.

## Task 4: Render and sync

- [ ] `nodesync.Render` attaches the organization's policy (with host overrides) to each of its routes.
- [ ] Downgrade to a plan without block mode or CRS renders the allowed subset and records why in the policy status.
- [ ] Tests: render isolation between two organizations on one node; hash changes when a policy changes; suspended or paused organizations unaffected.

## Task 5: Tenant UI in `/app`

- [ ] `/app/waf`: mode toggle, built-in signature list, CRS switch with paranoia level, custom rules editor, host overrides.
- [ ] Event list and logged/blocked counters per host from the usage poller.
- [ ] Plan-gated controls show the upgrade path instead of failing.
- [ ] EN/ID messages; e2e spec covering enable block mode, add a rule, see a blocked request.

## Task 6: Staff view and docs

- [ ] `/dashboard`: per-node WAF compile status and errors; per-organization policy visible during impersonation only.
- [ ] Customer docs page and README feature list; landing page mentions WAF once it ships.

## Acceptance

- [ ] On a node shared by two organizations, enabling block mode for one does not change responses for the other (e2e against a real Bearust node).
- [ ] A node restart reapplies the last policy without the SaaS.
- [ ] All checks green: `go test ./...`, `make test-pg`, `make lint-go`, frontend typecheck/vitest/lint:api, `cargo test` in core.
