# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: DevOps/SRE and platform engineers at small-to-medium organizations who
run self-hosted infrastructure and need a reverse proxy, load balancer, and WAF
they can trust without a dedicated security team. Also serves self-hosted
homelab enthusiasts (want easy install, intuitive GUI), small/medium businesses
(want an affordable alternative to F5/Nginx Plus), institutions such as
education and government (need self-hosted data control, WAF protection, RBAC
for multiple admins), and plugin developers/contributors (want a documented
WASM SDK and open contribution process). The dashboard's visual register
targets the DevOps/SRE/institutional audience first — it should read as
trustworthy, professional infrastructure tooling in the vein of Grafana,
Datadog, or Linear — while remaining approachable enough for a homelab
operator setting it up for the first time.

## Product Purpose

BeaRust combines a reverse proxy, load balancer, and Web Application Firewall
into a single self-hosted platform, with a full management GUI and RBAC so a
small team (or a single operator) can run production-grade edge infrastructure
without stitching together several separate tools. The dashboard is the
primary way operators configure proxy hosts/certificates, tune WAF and bot
protection, manage users/roles, and monitor traffic/security analytics across
one or many nodes.

## Positioning

All-in-one: proxy + load balancer + WAF + management GUI + RBAC in one
product, drawing security/LB depth from Nginx Plus/F5/SafeLine WAF and
ease-of-use from Nginx Proxy Manager's GUI-first, single-command Docker
install. Differentiators a competitor can't casually copy: a WASM-sandboxed
plugin system (extensibility without compromising core-process security),
free multi-node HA clustering (competitors lock this behind paid tiers or
omit it), and an optional LLM-based AI advisor layered on top of always-on
statistical self-learning. Implemented in Rust for performance and memory
safety, positioned against Nginx Proxy Manager (Node.js), SafeLine WAF
(Tengine/Go), and commercial F5/Nginx Plus.

## Operating Context

An operator self-hosts BeaRust (single Docker Compose command, SQLite by
default, external MySQL/PostgreSQL optional) and manages it entirely through
this dashboard: proxy host CRUD, TLS/Let's Encrypt certificates, WAF rules and
mode (signature + semantic detection), bot protection policy and challenge
review, adaptive rate limiting, RBAC (built-in admin/operator/viewer roles
plus custom per-resource-scoped roles), an audit log, realtime updates (SSE)
instead of polling, a Prometheus-compatible analytics/metrics view, a plugin
manager (install/enable/disable/inspect WASM plugins and their trust status),
and — for larger deployments — multi-node cluster status and HA operations
guidance. The dashboard is used both for initial setup (a first-run wizard)
and ongoing day-to-day operation.

## Capabilities and Constraints

- React + TypeScript + Vite, Tailwind CSS v4 with a semantic design-token
  layer already in place (`frontend/src/styles.css`), consumed by a small set
  of shared primitives (`frontend/src/ui.tsx`: Button, Card, Field,
  SelectField, TextareaField, Alert, ThemeSelect, LanguageSelect).
- Full i18n via react-i18next across three shipped locales (English default,
  Indonesian, Japanese) — nearly every user-facing string is translated
  today; this must not regress.
- Light/dark/system theme support is already implemented and must be
  preserved and extended consistently to any new visual work.
- Accessibility is a real product requirement (RBAC serves institutional/
  government users who need it, and the existing primitives already carry
  focus rings and aria attributes) — not just a nice-to-have.
- The current implementation lives almost entirely in one file,
  `frontend/src/App.tsx` (~3,081 lines, ~15+ dashboard sections defined
  inline: Setup, Login, AcmeWizard, CertificateTable, UsersSection,
  RolesSection, WafSection, BotProtectionSection, RateLimitSection,
  AnalyticsSection, BaselineSection, AnomalySection, AdaptiveTuningSection,
  BotChallengePage, Dashboard shell, AppContent, AuditLogSection). This is a
  known structural constraint, not a deliberate architecture choice.
- Vitest unit tests exist per section (e.g. `waf.test.tsx`, `users.test.tsx`,
  `roles.test.tsx`) plus Playwright e2e tests; these encode real product
  behavior and must keep passing.

## Brand Commitments

The amber/gold accent color (`#d99906` light, same hue adjusted for dark
mode) is an established brand color and must be preserved as the primary
accent/action color across any redesign. No other binding visual identity
(logo, typography, illustration style) exists yet — those are open for this
design pass to establish.

## Evidence on Hand

No product screenshots, customer testimonials, case studies, or press exist
yet — this redesign work must not fabricate any. The existing running
dashboard (buildable via `npm run dev` in `frontend/`) is the only visual
evidence on hand.

## Product Principles

- Trustworthy over trendy: this is security/infrastructure tooling institutions
  and SREs run in production — the design should read as competent and
  serious, never gimmicky or decorative for its own sake.
- Scanability and consistency outrank novelty on every operational screen —
  operators are completing tasks (configuring a proxy host, reviewing a WAF
  block, granting a role), not browsing.
- Accessibility and internationalization are load-bearing, not optional
  polish — every visual decision must survive translation into three
  languages and both light/dark themes.
- Approachable at the edges (first-run setup, empty states, onboarding),
  precise at the core (data-dense operational views).

## Accessibility & Inclusion

WCAG AA-level expectations apply given the institutional/government persona
in the target users; the existing focus-ring and aria-attribute conventions
in `frontend/src/ui.tsx` are the accessibility baseline to preserve and
extend, not replace.
