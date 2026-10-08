# Phase 4D.3 — Tailwind v4 Design System & Theme

## Goal

Migrate the existing Bearust management UI to Tailwind CSS v4 and establish a consistent, responsive, accessible design system across all current pages without changing control-plane behavior or API contracts.

## Scope

The increment covers the setup, login, dashboard, proxy-host, certificate, users, roles, and audit-log views. It includes desktop, tablet, and mobile layouts, plus user-selectable `system`, `light`, and `dark` themes.

The increment does not add new backend settings endpoints, change authentication/RBAC behavior, or redesign data flows. Theme preference is persisted in `localStorage`; account-level synchronization remains a follow-up once system-settings persistence is implemented.

## Design system

Tailwind CSS v4 will be the sole styling system for application components. The legacy monolithic stylesheet will be removed after its rules have been replaced by utility classes or small component-level style declarations where Tailwind cannot express a browser primitive cleanly.

Design tokens will be declared in the main CSS entrypoint using Tailwind v4 theme variables and semantic CSS variables. Tokens include:

- Brand: Bearust gold `#D99906` with accessible foreground/hover variants.
- Surfaces: page, panel, elevated panel, input, and inverse surfaces.
- Content: primary, muted, inverse, and disabled text.
- Borders and focus ring.
- Semantic success, warning, danger, and info colors.

Components must consume semantic tokens rather than hard-coded colors so light/dark changes remain centralized. Shared primitives include buttons, fields, cards, alerts, badges, tables, section headings, navigation, and empty/loading states.

## Theme behavior

The theme provider exposes `theme`, `setTheme`, and a resolved theme value. `system` follows `prefers-color-scheme` and reacts to OS changes; explicit light/dark modes override it. The selected mode is applied before the first React paint when possible to avoid a flash of the wrong theme. The preference is stored under a versioned local-storage key, invalid values fall back to `system`, and browser storage failures fail soft.

The theme selector is available from the authenticated application shell and is keyboard accessible. It includes an accessible label and does not rely on color alone to communicate state.

## Responsive and accessibility requirements

- The shell, forms, cards, and controls remain usable at mobile widths without horizontal page overflow.
- Data tables use a bounded scroll region or a deliberate stacked presentation on small screens.
- Focus indicators remain visible in both themes.
- Text and interactive controls meet WCAG AA contrast targets where practical.
- Reduced-motion preferences disable non-essential transitions.
- Labels, buttons, theme controls, and status indicators expose meaningful accessible names.

## Migration strategy

1. Add Tailwind v4 dependencies and the CSS entrypoint.
2. Introduce token definitions and the theme provider/hook.
3. Create shared primitives and migrate the application shell.
4. Migrate each existing page without changing its state management or API calls.
5. Remove obsolete stylesheet rules and verify no component depends on them.

The migration should be incremental within one branch, with each page remaining buildable and testable. Existing realtime reload behavior, RBAC visibility, and error redaction must remain unchanged.

## Verification

- Frontend unit tests cover theme initialization, mode switching, system preference changes, persistence, invalid stored values, and storage failure.
- Component tests cover key authenticated and unauthenticated views in light and dark themes.
- A responsive smoke check verifies the shell and every management section at desktop and mobile viewport sizes.
- `npm test -- --run`, `npm run build`, and `git diff --check` must pass.
- A final review confirms no secrets, API behavior, or permission boundaries are affected by the styling migration.

## Deferred follow-ups

- Persisting theme preference through the account/system-settings API.
- Per-host permission scopes, audit export, and other remaining Phase 4 capabilities.
