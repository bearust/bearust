# Design

<!-- impeccable:design-schema 1 -->

## World

**“BeaRust shadcn-admin”** — a calm, dense control-plane UI built on the
layout and component grammar of [satnaing/shadcn-admin]. The application
uses a persistent grouped sidebar, inset content surface, compact sticky
header, command navigation, restrained cards, data tables, tabs, and Radix
primitives. BeaRust’s amber security accent replaces the template’s default
brand color while the structure remains recognizably shadcn-admin.

The shell supports two deliberate data modes: demo mode keeps the visual
review environment deterministic, while API mode reads and mutates the live
control-plane resources. Live screens expose their connection state and keep
loading, empty, permission, and error states visible rather than silently
falling back to fabricated operational data.

## Palette

The palette is restrained: neutral surfaces, readable dark-mode contrast, and
one amber action color. Tokens live in `frontend/src/styles/theme.css`.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--background` | `#f2f3f5` | `#111318` | App ground |
| `--card` | `#ffffff` | `#1a1d24` | Cards and inset surfaces |
| `--muted` | `#eceef1` | `#232730` | Secondary surfaces and controls |
| `--border` | `#e1e3e8` | `#2b303a` | Dividers and outlines |
| `--foreground` | `#1c2128` | `#e9eaec` | Primary text |
| `--muted-foreground` | `#626975` | `#9aa1ac` | Supporting text |
| `--primary` | `#b87d05` | `#f5a524` | Brand, actions, focus |
| `--destructive` | `#d32f2f` | `#ef5350` | Destructive and blocked states |

Status colors are expressed through `StatusBadge`: emerald for healthy,
amber for review, red for blocked, and blue-toned information where needed.
Light and dark mode are controlled through `data-theme` and the existing
`ThemeProvider`; no CDN font or remote visual asset is required.

## Type

- Roboto 400–700 is the body and display voice, matching the existing
  self-hosted project font policy.
- Roboto Mono is reserved for domains, upstream targets, and numeric data.
- Headings are compact and bold; labels and navigation use sentence case and
  medium weight.
- Page titles use `PageHeader`; repeated values use `MetricCard` with
  tabular numerals and small trend context.

## Components

- **Shell:** `SidebarProvider`, `AppSidebar`, `NavGroup`, `Header`, `TopNav`,
  `Search`, `ThemeSwitch`, `ProfileDropdown`, and
  `CommandPalette` establish the upstream template behavior.
- **Surfaces:** upstream-compatible `Card`, `Tabs`, `Table`, `Badge`,
  `Dialog`, `DropdownMenu`, `Sheet`, `Tooltip`, and `Sidebar` primitives are
  reused before creating feature-specific components.
- **Feature grammar:** `PageHeader`, `MetricCard`, and `StatusBadge` provide
  consistent page composition across dashboard, proxy hosts, security,
  analytics, users, audit log, AI advisor, settings, cluster, and plugins.
- **Interaction states:** buttons, menu items, tabs, dialogs, search,
  filters, toggles, theme selection, API mutations, and
  approval actions all have visible state changes.
- **Navigation:** grouped sidebar sections are General, Protection, and
  Administration. Security expands into WAF, bot protection, and rate
  limiting routes; mobile switches to the template’s off-canvas sidebar.

## Layout

Desktop uses a collapsible left sidebar and an inset, max-width content
surface. The header keeps section navigation, command search, theme, and
account controls in one compact row. Mobile keeps the header controls usable
and moves the sidebar off-canvas;
tables and dense content may scroll inside their own bounded regions but the
document itself must not overflow horizontally.

The authenticated landing route is the real dashboard at `/`, not a
placeholder. Auth routes use the same visual language through
`features/auth/auth-layout`, with a responsive security message panel and a
template-style sign-in card.

## Deferred

- Extend the API-backed shell with any future backend capabilities that are
  added to the PRD (for example plugin registry distribution or additional
  deployment controls).
- Add screenshot baselines if the team wants visual regression diffs in CI;
  this pass stores review screenshots in `.impeccable/review/`.

[satnaing/shadcn-admin]: https://github.com/satnaing/shadcn-admin
