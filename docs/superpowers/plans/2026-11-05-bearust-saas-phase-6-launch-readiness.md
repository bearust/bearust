# Bearust SaaS Phase 6: Launch Readiness (Closed Beta)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Bearust Cloud for real as an invite-only closed beta: a deployed control plane with backups and alerting, managed edge nodes that are easy to add and update, gated sign-ups, complimentary paid plans instead of real charges, the two launch gateways verified in sandbox, and a way to report abuse.

**Builds on:** Phases 2–5 (tenant self-service, RBAC, billing, usage limits). Phase 5's rule holds: the Free plan is not opened to the public in this phase.

**Architecture:** Three kinds of machines. The **control plane** (Go backend, Next.js frontend, Postgres) runs on one VPS as a one-node Docker Swarm stack and never carries tenant traffic. **Edge nodes** are separate VMs running Bearust core with public ports 80/443; the control plane drives them over their admin API (desired state, usage) and writes `<slug>.bearust.cloud` A records in Cloudflare. **CI/CD** on GitHub Actions builds images to GHCR for both the SaaS and Bearust core.

**Tech Stack:** Same as earlier phases, plus GitHub Actions, GHCR, Docker Swarm, cloud-init, Cloudflare (DNS, R2), Telegram Bot API.

## Decisions (2026-11-05)

- **Launch shape:** closed beta by staff invitation; public sign-up closed by a setting. Exit to public when: 30 days without a major incident, Dodo and Xendit sandbox checks pass, and the tax decision is made. Paid plans open first; Free follows once Free-node capacity and abuse handling have proven themselves.
- **Control plane:** one VPS in Singapore, Docker Swarm (ADR saas/0001). Postgres backed up daily to Cloudflare R2, keeping 7 daily and 4 weekly; restore tested before the beta opens and monthly after.
- **Edge:** region `sin-1` with one `free` node and one `paid` node, each its own VM. Provisioned by cloud-init from a Bearust image on GHCR. The node admin API is reachable only from the control plane IP (firewall), over HTTPS with a `brt_` token. WireGuard is a later option.
- **CI/CD:** GitHub Actions (lint + test on PRs; build to GHCR on `main`/tags; deploy over SSH with `docker stack deploy`, migrations as an explicit step before rollout). `gitlab-ci/` is removed.
- **Migrations:** unchanged up to `000022`; append-only from the first production deploy (ADR saas/0003).
- **Billing:** Dodo Payments (MoR) and Xendit enabled, the rest disabled (ADR saas/0002). No real charges during the beta: staff grant complimentary subscriptions (default 90 days, editable per grant; owner emailed 7 days before the end; on expiry the organization falls back to Free through the cancel-at-period-end path, including the tier move). Coupons are a follow-up. Tax consultation runs in parallel.
- **Monitoring:** external uptime checks for the control plane and every node, error tracking (existing `errtrack`), critical alerts to Telegram (node down, backup failed, failed jobs, Free-node bandwidth), daily digest by email.
- **Abuse:** an `abuse@` mailbox and a public report page that opens a staff ticket; staff use the existing suspend action. No automated detection yet.
- **No fixed date:** the beta opens when deploy, backups and monitoring are in place; payments and Free follow.

## Global Constraints

- All earlier constraints apply. Secrets never land in the repo, images or logs; production secrets are Docker secrets or CI secrets.
- Every human-only step (buying VMs, DNS/registrar access, provider dashboards, credentials) is captured in a runbook or a generated wizard script, not re-explained to agents.
- New error code: `SIGNUPS_CLOSED`.

---

## File Map

Bearust SaaS (`bearust-saas`):
- Create: `.github/workflows/` (ci, build, deploy); delete `gitlab-ci/`.
- Modify: `docker-stack.yml`, `Dockerfile.prd`, `docs/deployment/bearust-cloud.md` (production runbook), README.
- Create: `scripts/backup/` (pg_dump to R2 with retention, restore check).
- Modify: `internal/auth` (signups closed), `internal/settings`, `internal/org` invitations (invite-to-sign-up), `internal/billing` (complimentary grants), `internal/notify` (Telegram channel, daily digest), new `internal/abuse` (reports).
- Modify: frontend `/dashboard` (sign-up setting, staff invitations, grants, abuse queue), public report page, `/app` (complimentary plan state).

Bearust core (`bearust`):
- Create: `.github/workflows/` image build to GHCR (if not present), `deploy/edge/cloud-init.yaml`, edge node runbook in `DEPLOY.md`.

---

### Task 1: Closed sign-ups and staff invitations

- A platform setting `signups_open` (default closed in production). With it closed, sign-up and first OAuth/magic-link sign-in answer `SIGNUPS_CLOSED`, except for an email holding a valid invitation.
- Staff invite beta users by email from the dashboard; the email carries a sign-up link. Existing organization invitations also allow sign-up for their invitee.

**Validation:** Go tests for each sign-in path with sign-ups closed/open and with/without invitation; Vitest for the setting and invite form; Playwright: invited user signs up, uninvited user is refused.

- [x] Setting + enforcement
- [x] Staff beta invitations

### Task 2: Complimentary subscriptions

- Staff grant a paid plan to an organization without a gateway: plan, end date (default 90 days), reason; audited. The organization is treated as paid (entitlements, `paid` node tier, placement move).
- 7 days before the end the owners are emailed; at the end the organization follows the cancel-at-period-end path to Free (including the tier move). Staff can extend or revoke.

**Validation:** fake-clock tests for grant, reminder, expiry and extension; placement-move test; Vitest for the staff form and the tenant plan badge.

- [x] Grant, extend, revoke
- [x] Reminder and expiry

### Task 3: Launch gateways

- Only Dodo and Xendit are enabled in production configuration; the staff console hides or marks the others as disabled.
- Sandbox runbook: create sandbox accounts, set credentials, run the sandbox tests (`checkout`, webhook verification, refund) and record the results in the plan.

**Validation:** config tests that disabled gateways cannot be selected; sandbox test run recorded (human supplies credentials).

- [x] Gateway enablement
- [x] Sandbox verification recorded (bearust/saas#53: Xendit and Dodo, 2026-11-07)

### Task 4: CI/CD on GitHub Actions

- PR workflow: Go lint/test (incl. Postgres service), frontend typecheck/vitest/lint:api, Playwright on the compose stack (known flaky/baseline specs as documented in CLAUDE.md).
- Build workflow: images to GHCR tagged with the commit SHA and `latest` on `main`.
- Deploy workflow (manual or tag): SSH to the control VPS, run migrations as a one-off task, then `docker stack deploy` with the new tag; rollback documented.
- Remove `gitlab-ci/`. Bearust core gets an image build to GHCR.

**Validation:** workflows green on a PR and on `main`; a dry-run deploy to the VPS.

- [x] CI workflow
- [x] Image builds (SaaS + Bearust core)
- [x] Deploy workflow + rollback runbook

### Task 5: Control plane deployment and backups

- Production `docker-stack.yml`: Docker secrets, health checks, rolling update with rollback, TLS at the edge of the stack for `bearust.cloud`.
- Backups: daily `pg_dump` to R2 with 7 daily / 4 weekly retention; a restore script that loads the latest dump into a scratch database and runs a smoke query. Restore tested before the beta, then monthly.
- First production deploy; afterwards switch the repo rule to append-only migrations (CLAUDE.md, AGENTS.md, agent memory).

**Validation:** stack deploys and rolls back on a failing health check; backup and restore run end to end; documented in `docs/deployment/bearust-cloud.md`.

- [ ] Production stack
- [ ] Backups + restore test
- [ ] First deploy + migration rule switch

### Task 6: Edge node provisioning

- `cloud-init` for an edge VM: Docker, the Bearust image from GHCR, data volume, firewall (80/443 public; admin port only from the control plane IP), TLS for the admin API.
- Runbook: create the admin user and `brt_` write token, register the node in the dashboard (region, tier, address, control URL, token), verify sync and usage polling.
- Update procedure: roll a new Bearust version node by node, checking sync after each.

**Validation:** a fresh VM reaches "synced" in the dashboard from the script plus runbook alone; an update rolls without dropping traffic on the other node.

- [x] cloud-init + firewall
- [x] Registration runbook
- [x] Update procedure

### Task 7: Monitoring and alerting

- External uptime checks for `bearust.cloud` and each node's public port.
- Telegram channel in `internal/notify` for critical alerts: node down (existing health checks), backup failed, jobs failing repeatedly, Free-node bandwidth above a threshold. Daily email digest of the same signals.
- Error tracking enabled in production.

**Validation:** Go tests for alert rules and the Telegram sender (fake HTTP); a fired test alert received in Telegram.

- [x] Telegram + rules
- [x] Daily digest
- [x] Uptime checks configured (bearust/saas#61, confirmed by the owner 2026-11-08)

### Task 8: Abuse reporting

- Public `/abuse` page (captcha-protected) to report a hostname; creates a staff ticket with the resolved organization. `abuse@` mailbox documented.
- Staff queue in the dashboard: view, link to the organization, suspend (existing action), close; audited.

**Validation:** Go tests for report creation and host→organization resolution; Vitest for the form and queue; Playwright: report → staff sees it → suspend.

- [x] Report page + tickets
- [x] Staff queue

### Task 9: Beta launch checklist

- Checklist in `docs/deployment/bearust-cloud.md`: DNS, secrets, gateways, backups and restore test, alerts firing, nodes synced, sign-ups closed, first beta invitations sent.
- Exit-criteria tracking for moving to public paid plans.

- [ ] Checklist complete and beta opened

---

## Progress (2026-11-07)

- Closed sign-ups use the `signups.open` setting with a staff beta-invitation table (migration `000023`); every new-user sign-in path is covered.
- Complimentary grants extend the existing subscription model and reuse the cancel-at-period-end expiry/tier-move path; the owning `000020_billing_core` migration was edited in place instead of adding `000024`, per the pre-production rule.
- Launch gateways are limited by `BILLING_LAUNCH_GATEWAYS` (Dodo and Xendit by default in production), enforced for checkout, webhooks and staff edits.
- Alerting adds `internal/alerts` (migration `000025`) with a Telegram sender, deduplicated incidents, a backup-failure ingest endpoint and the daily staff digest.
- Abuse reporting adds `internal/abuse` (migration `000026`), the public captcha-protected `/abuse` page and the staff queue with audited suspension.
- CI moved to GitHub Actions (PR CI, GHCR builds, deploy/rollback) and `gitlab-ci/` is gone.
- Bearust edge provisioning adds `deploy/edge/cloud-init.yaml` and the DEPLOY.md runbook.
- E2E added `signups.spec.ts` and `abuse.spec.ts`; both pass along with the existing billing, quota and onboarding specs.

Remaining human-only work: run the workflows on GitHub, dry-run the deploy, verify the cloud-init on a throwaway VM, run the Dodo/Xendit sandbox checks, fire a real Telegram alert, configure uptime checks, and complete the launch checklist (Tasks 5 and 9).

## Risks

- **Single control-plane VPS:** an outage stops the dashboard and syncs but not tenant traffic (nodes keep their last desired state). Backups bound data loss to one day; restore is rehearsed.
- **Admin API exposure:** a firewall mistake would expose the node admin port; the token and HTTPS still protect it, and the runbook verifies the rule from outside.
- **Two nodes only:** losing the Free node pauses all beta Free tenants' traffic; acceptable for a beta, alert is immediate.
- **Tax:** no real charges until the consultation concludes; complimentary grants keep the beta useful meanwhile.
