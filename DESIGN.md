# Design

<!-- impeccable:design-schema 1 -->

## World

**"Material Admin"** — an elevation-based Material Design admin
dashboard: raised paper cards on a grey (light) or near-black (dark)
ground, soft shadows, rounded corners, filled contained buttons, and
outlined form controls, in Material's own Roboto voice.

This replaces the prior "Signal Board" world (a flat, hairline-ruled
instrument-panel grammar) by direct brief pin, not the roll-and-fuse
process: the user explicitly named a reference ("React Material Admin
Dashboard"), and a user- or brief-pinned direction always beats the
roll. BeaRust's amber (`#d99906`-family) carries over as the primary
Material color role, standing in for the blue/indigo a generic Material
admin template would default to — the one deliberate brand commitment
preserved across the replacement.

## Palette

**Restrained** strategy carried over: neutrals plus the one committed
amber accent, now expressed as Material's elevation surfaces rather
than flat panels.

Both registers are complete, hand-tuned renditions, not a mechanical
inversion of one another.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--color-page` | `#111318` | `#f2f3f5` | App ground |
| `--color-surface` / `--color-panel` | `#1a1d24` | `#ffffff` | Card/paper fill |
| `--color-surface-muted` | `#232730` | `#eceef1` | Table header, tonal hover |
| `--color-border` | `#2b303a` | `#e1e3e8` | Hairline dividers |
| `--color-border-strong` | `#3c4250` | `#c7cbd3` | Input borders, emphasis |
| `--color-foreground` | `#e9eaec` | `#1c2128` | Primary text |
| `--color-muted` | `#9aa1ac` | `#626975` | Secondary text, labels |
| `--color-action` / `--color-brand` | `#f5a524` | `#b87d05` | Primary Material color — brand, buttons, active nav, focus ring |
| `--color-focus` | same as action | same as action | Material convention: focus uses the primary color directly |
| `--color-success` | `#4caf50` | `#1e8a4c` | Healthy / active / enforced |
| `--color-warning` | `#f5a524` | `#b87d05` | Monitor-only / degraded — shares the accent hue |
| `--color-danger` | `#ef5350` | `#d32f2f` | Blocked / disabled / critical |
| `--color-info` | `#42a5f5` | `#1565c0` | Neutral informational status — Material blue, the one place blue appears |

Elevation tokens: `--shadow-1` (resting card), `--shadow-2` (hover/
raised), `--shadow-appbar` (top bar) — real offset-and-blur shadows,
tuned separately per theme since dark-mode shadows need more opacity to
read against a near-black ground than light-mode shadows need against
white. `--radius-card` (12px) and `--radius-control` (8px) replace the
old system's sharp `rounded-sm` corners everywhere.

## Type

- **Display and body** (`--font-display`, `--font-body`): Roboto
  400–700. Material's own typeface, used for both headings and body —
  unlike the prior world, there is no separate structural display face;
  Material dashboards read as one consistent voice.
- **Mono** (`--font-mono`): Roboto Mono 400–500. Data, numeric
  readouts, WAF TOML/JSON — measurement and code, not a costume.
- Self-hosted via `@fontsource/*` (Latin + Latin Extended subsets only
  — BeaRust ships en/id/ja locales, and ja's kanji/kana fall back to
  the platform's own CJK font regardless). Deliberately not a Google
  Fonts CDN link: BeaRust targets self-hosted, institutional, and
  air-gapped deployments.
- Labels, table headers, and nav items are sentence case, medium
  weight — Material's own convention, replacing the prior world's
  uppercase tracked mono labels everywhere except genuine data cells.

## Components

- **`Panel`** (`ui.tsx` — `Card` is a deprecated alias): a Material
  elevated card — `--radius-card` corners, `--shadow-1`, a paper fill.
  An optional `label` renders as a card-header title (sentence case,
  medium weight) with `actions` right-aligned in the same strip.
- **`StatusLamp`**: a small flat status dot, no glow (a zero-offset
  colored halo is decoration, not depth — dropped from the prior
  world's "lit lamp" treatment). Always paired with a label.
- **`StatusBadge`**: a Material filled tonal chip — rounded-full,
  colored surface tint plus colored text, with the lamp dot inside.
  Used for realtime status, WAF/rate-limit/bot-protection mode, backend
  TLS mode, user state, anomaly severity, tuning mode, AI advisor
  status.
- **Tables**: global `table`/`thead th`/`tbody tr`/`tbody td` rules in
  `styles.css` give every table a Material data-table treatment —
  sentence-case medium-weight headers on a tonal `surface-muted`
  header row, hairline dividers, row hover tint.
- **Buttons**: `primary` is a Material contained button (filled amber,
  `--shadow-1` resting / `--shadow-2` on hover, a slight press-scale
  standing in for a ripple); `secondary` is outlined; `danger` is an
  outlined error button, so a destructive action reads as available,
  not alarming, until pressed.
- **Form fields**: outlined Material-style inputs — `--radius-control`
  corners, a border that darkens on hover and picks up the focus color
  on focus. Labels are small sentence-case text above the field, a
  deliberate simplification of Material's animated floating label
  (disclosed, not hidden).
- **Nested cards stay banned** (craft floor, world-independent):
  list-shaped content (certificates, AI advisor results) is a
  hairline-divided `<ul>`/`<li>` list, not a grid of mini-cards.
- **Navigation**: sidebar items are rounded-full pills; the active item
  gets a tonal amber fill (`bg-action/12`) and amber icon/text, in
  place of the prior world's lamp-dot active indicator — Material's
  own selected-nav-item convention, and it sidesteps the craft floor's
  ban on colored left/right borders as an active-state signal.
- **Checkboxes/radios**: themed from the palette, unchanged in
  mechanism from the prior world (still not the browser default).

## Layout

Unchanged from the prior pass's structural decision, now re-skinned: a
persistent left navigation drawer (six grouped nav items — Proxy Hosts,
AI Advisor, Security, Analytics, Users & Roles, Audit Log — collapsing
to an off-canvas drawer on mobile) plus a content column with a sticky
elevated AppBar (solid paper fill, `--shadow-appbar`, no
backdrop-blur/translucency — Material app bars are opaque, not glass)
holding the active section's title, the realtime badge, and an account
menu dropdown. Proxy Hosts remains the default landing view, ahead of
optional/secondary sections, so the first viewport still proves the
product's actual job. All sections stay mounted at all times (CSS
`hidden`, never unmounted) so SSE realtime wiring never drops.

## Deferred

- A named signature motion beyond the elevation-on-hover convention
  (`.elevate` utility, `--shadow-1` → `--shadow-2` on hover, press
  scale) — not yet wired to every interactive surface, only buttons;
  a future pass could extend it to clickable table rows.
- A live URL-based Puppeteer detector pass (not installed this
  session); the static source-file detector (`detect.mjs`) ran clean,
  and the system was verified visually instead — dark and light,
  desktop and mobile, against a real running backend with seeded data.
- A true Material floating-label text field (the animated label that
  shrinks into the border on focus) — the current fields use a
  simplified static label-above-field pattern instead, by explicit
  user choice to stay on the existing Tailwind component architecture
  rather than adopt MUI.
