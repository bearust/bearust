# Frontend Rebuild — shadcn-admin Architecture Migration

## Goal

Rebuild the Bearust management UI on the architecture of the
[shadcn-admin](https://github.com/satnaing/shadcn-admin) template —
TanStack Router, TanStack Query, Zustand, and shadcn/ui (Radix + CVA +
Tailwind) — replacing the current router-less, single-file (`App.tsx`,
3337 lines) implementation, without changing any backend behavior,
API contract, or product feature.

This is the third frontend visual/structural pass in this project's
history. Two prior passes (a flat "instrument panel" system, then a
Material Design reskin) kept the existing router-less architecture and
only changed presentation; the user rejected both and asked instead to
adopt a concrete, proven open-source template's actual architecture,
not just its look.

## Scope

In scope: routing, auth-guard, layout/navigation shell, data-fetching
layer, and UI component system for every existing screen — Setup,
Login, Bot Challenge, Proxy Hosts (+ ACME wizard, certificate list),
WAF, Bot Protection, Rate Limit, Analytics, Baseline, Anomalies,
Adaptive Tuning, Users, Roles, Audit Log, AI Advisor. Also in scope:
porting all 24 Vitest files and 2 Playwright specs to work under the
new router, and a shadcn/ui-based command palette (Ctrl+K).

Out of scope: any backend/API change (`api.ts`'s surface is frozen —
see Data layer below), any change to i18n copy or key names (en/id/ja
catalogs carry over verbatim), any new product feature, and every
demo-only piece of the shadcn-admin template that has no Bearust
equivalent (tasks, chats, apps gallery, multi-team switcher, Clerk
auth pages). Font choice (currently Roboto/Roboto Mono, from the prior
Material pass) is not reconsidered here.

## Layering

Four layers replace the current single `App.tsx`:

- **`routes/`** (TanStack Router, file-based) — thin composition only:
  each route file wires a feature's page component into the URL tree,
  no business logic.
- **`features/<name>/`** — one directory per product area (mirrors
  today's exported `*Section` components): `index.tsx` (page),
  `components/*.tsx` (dialogs, tables, forms), `hooks.ts` (query/
  mutation hooks for that resource).
- **`stores/`** — Zustand; one store for now (`auth-store.ts`).
- **`components/ui/`** — shadcn/ui primitives (Radix UI primitives +
  `class-variance-authority` + Tailwind), generated/hand-ported from
  the reference template, not hand-rolled per project like the
  current `ui.tsx`.

`api.ts`, `theme.tsx`, `i18n.ts`, and `realtime.ts` are framework-
agnostic today and move over unchanged — no rewrite, no reformatting
beyond relocation if needed for the `@/` import alias.

## Routing and auth

`src/routes/_authenticated/route.tsx` is the guard for every
authenticated screen. Its `beforeLoad` awaits a TanStack Query
`['me']` query (via `queryClient.ensureQueryData`) rather than a
one-shot `api.me()` call — this makes the guard reactive: the existing
realtime SSE event `sessions.changed` (already wired in `realtime.ts`)
calls `queryClient.invalidateQueries(['me'])`, so a session revoked by
another admin (or expired) re-runs the guard on the next navigation
without a page reload. `api.status()` (setup-initialized check) is a
separate, unauthenticated route-level check redirecting to `/setup`
when the backend has no admin yet.

The resolved user is mirrored into `stores/auth-store.ts` (Zustand)
for synchronous reads in components that need it outside a query
context (e.g. the sidebar's RBAC-gated nav-item filter) — the query
result is the source of truth, the store is a read cache of it, kept
in sync by a query-success effect, matching the shape (not the
content) of shadcn-admin's own `auth-store.ts`.

Navigation: `/setup`, `/login`, `/bot-challenge` are public routes.
`_authenticated/` holds `index` (Proxy Hosts, default landing route,
preserving today's priority — it's Bearust's actual core mechanism),
`ai-advisor`, `security` (single route, tabbed — WAF / Bot Protection
/ Rate Limit, replacing today's three-section "Security" nav group;
chosen over three separate routes to keep the sidebar at 6 items),
`analytics` (with Baseline/Anomaly/Adaptive Tuning as sections or
tabs within it — exact sub-structure decided during Phase 2 porting,
not a routing concern), `users`, `roles` (or merged into `users` if
Phase 2 porting finds that cleaner — RBAC gates both to admins today),
`audit-log`.

## Data layer

Every one of the 13 backend resources (`hosts`, `certificates`,
`users`, `roles`, `waf`, `bot`, `rate-limit`, `analytics`, `baseline`,
`anomalies`, `adaptive-tuning`, `audit-logs`, `ai-advisor`) gets a
`features/<name>/hooks.ts` exporting its query/mutation hooks (e.g.
`useHosts()`, `useCreateHost()`, `useDeleteHost()`), each a thin
TanStack Query wrapper around the existing, unchanged `api.ts`
function. Query keys are named consistently per resource (`['hosts']`,
`['waf', 'rules']`, `['audit-logs', queryParams]`) so realtime
invalidation and manual invalidation after a mutation can't drift out
of sync with each other.

Centralizing hooks here (rather than inlining `useQuery`/`useMutation`
per component) was chosen over the alternative specifically because
Bearust has real, no-mock backend data on every one of 13 resources
(unlike most of the template's own demo features, which use static
fake data) — a single, named, testable hook per resource keeps 13
query-key namespaces from drifting, and gives the SSE realtime wiring
(`realtime.ts`'s `EVENT_LOADERS`) one unambiguous invalidation target
per event type.

`realtime.ts` itself does not change — only its call sites do: each
named loader (`hosts`, `certificates`, `waf`, etc.) becomes
`() => queryClient.invalidateQueries({ queryKey: [...] })` instead of
today's local `setState` callback, wired once in the `_authenticated`
layout.

Mutation feedback: a successful create/update/delete shows a `sonner`
toast (e.g. "Proxy host deleted"). Form-level validation errors (e.g.
ACME wizard's hostname validation, a WAF rule's malformed matcher)
stay as inline `Alert`-equivalent messages next to the field/form,
since those need to stay visible and readable, not disappear after a
toast timeout.

## UI component system

shadcn/ui primitives replace the hand-rolled `ui.tsx`: `Button`,
`Card`, `Input` + `Label` + `Form` (the last built on
`react-hook-form` + `zod`, used for every multi-field form — ACME
wizard, role/scope editor, WAF/Bot/Rate-Limit config editors), `Table`,
`DropdownMenu`, `Dialog`/`AlertDialog` (destructive confirmations,
replacing today's `window.confirm`), `Tabs` (Security page), `Sidebar`
(collapsible, from the reference template's 728-line primitive),
`Command` (the Ctrl+K palette).

Icons move to `lucide-react` throughout, retiring the current
hand-authored `icons.tsx` — this keeps one icon system consistent with
every shadcn/ui component that already ships its own lucide icons
internally (dialogs' close button, dropdown chevrons, etc.), rather
than mixing two icon grammars.

Data tables: `@tanstack/react-table` (sorting, and Audit Log's
existing filter/pagination re-expressed in its model) is used only for
Proxy Hosts, Users, and Audit Log — the three tables where sorting/
filtering materially helps. Every other table (WAF rules, trusted
crawlers, roles, recommendations) uses the shadcn/ui `Table` primitive
without the TanStack Table layer, to keep the migration bounded rather
than mechanically maximal.

Command palette: a root-level `Command` dialog (Ctrl+K) listing the 6
nav destinations plus a small set of common quick actions (e.g. "New
proxy host"); the exact quick-action list is refined during Phase 2
once each feature's primary action is ported, not fixed here.

## Testing

`src/test-utils/render-route.tsx` — one shared helper providing a
memory-history TanStack Router instance plus a test `QueryClient`,
used by every ported test file in place of today's bare
`createRoot(...).render(<App/>)`. `api` continues to be mocked the
same way it is today (`vi.spyOn(api, 'xxx')`); nothing about the
mocking strategy changes, only what's rendered around the component
under test.

Test files are ported one-for-one alongside their feature in Phase 2
of the implementation plan (e.g. `users.test.tsx` updates in the same
step as `UsersSection`'s port), not as a separate pass at the end —
this was an explicit decision to avoid a long stretch where the whole
suite is red with no clear per-feature signal.

Files that test framework-agnostic modules unaffected by this
migration (`i18n.test.ts`, `locales.test.ts`, `catalog-keys.test.ts`,
`localization-review.test.tsx`, `theme.test.tsx`, `realtime.test.tsx`,
`formatting.test.tsx`) need little or no change. The 2 Playwright
specs (`e2e/ai-advisor.spec.ts`, `e2e/responsive.spec.ts`) drive a
real browser against real URLs and need only selector updates for the
new markup, not structural rework.

## Verification

- `npx tsc --noEmit`, `npx vitest run`, `npm run build` after every
  phase of the implementation plan — never let more than one
  feature's worth of breakage accumulate across phases.
- `detect.mjs` (Impeccable's mechanical anti-pattern scanner) on every
  changed UI file.
- A manual Playwright screenshot pass (dark/light, desktop/mobile)
  against a real running `bearust serve` backend before any phase is
  declared done — both prior redesign passes shipped real bugs this
  step caught, and it must not be skipped this time either.
- A full manual click-through — setup → login → every nav
  destination → mobile drawer → command palette → sign out — on a
  real browser before the migration as a whole is considered done.
