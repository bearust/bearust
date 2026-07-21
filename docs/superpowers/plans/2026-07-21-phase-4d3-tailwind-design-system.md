# Phase 4D.3 Tailwind v4 Design System & Theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate every existing BeaRust UI page to Tailwind CSS v4 with shared semantic tokens, responsive layouts, accessible controls, and system/light/dark themes.

**Architecture:** Tailwind v4 is loaded from the frontend CSS entrypoint. Semantic CSS variables define the design tokens and are switched by a root `data-theme` attribute. A small React theme provider owns mode selection and local-storage persistence; presentational components consume Tailwind utilities and token classes without changing existing API/state behavior.

**Tech Stack:** React, TypeScript, Vite, Tailwind CSS v4, Vitest, jsdom.

## Global Constraints

- Brand primary color is `#D99906`.
- Supported modes are `system`, `light`, and `dark`.
- Theme preference is persisted in `localStorage`; account-level settings are deferred.
- Existing authentication, RBAC visibility, realtime reloads, API calls, and redaction behavior must remain unchanged.
- All current pages must remain usable at desktop, tablet, and mobile widths.
- Verification commands are `npm test -- --run`, `npm run build`, and `git diff --check`.

## File Map

- Modify `frontend/package.json`, `frontend/package-lock.json`, and `frontend/vite.config.ts`: Tailwind v4 tooling.
- Modify `frontend/src/styles.css`: Tailwind import and token definitions.
- Create `frontend/src/theme.tsx`: theme context, provider, persistence, and pre-paint bootstrap helper.
- Create `frontend/src/ui.tsx`: shared button, field, card, alert, badge, table, and loading primitives.
- Modify `frontend/src/main.tsx`: install the provider and bootstrap theme before rendering.
- Modify `frontend/src/App.tsx`: replace legacy classes/markup with shared primitives and responsive Tailwind utilities.
- Create `frontend/src/theme.test.tsx` and `frontend/src/ui.test.tsx`: provider and primitive tests.
- Modify existing frontend tests where selectors depend on removed legacy classes.

### Task 1: Install and configure Tailwind v4

**Files:** `frontend/package.json`, `frontend/package-lock.json`, `frontend/vite.config.ts`, `frontend/src/styles.css`

- [ ] **Step 1: Add Tailwind v4 dependencies**

Run from `frontend`:

```bash
npm install -D tailwindcss@latest @tailwindcss/vite@latest
```

Add the Tailwind Vite plugin and replace legacy stylesheet rules with `@import "tailwindcss";`.

- [ ] **Step 2: Verify the baseline build**

Run `npm run build`. Expected: TypeScript and Vite complete successfully.

- [ ] **Step 3: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/vite.config.ts frontend/src/styles.css
git commit -m "build: add tailwind css v4"
```

### Task 2: Add semantic tokens and theme provider

**Files:** `frontend/src/styles.css`, `frontend/src/theme.tsx`, `frontend/src/main.tsx`, `frontend/src/theme.test.tsx`

**Interfaces:** `ThemeMode = "system" | "light" | "dark"`; `ThemeContextValue = { mode, resolved, setMode }`; exports `ThemeProvider`, `useTheme`, `readStoredTheme`, and `bootstrapTheme`.

- [ ] **Step 1: Write failing tests**

Test default `system`, valid persisted values, invalid-value fallback, `setMode` persistence, OS preference changes, and storage exceptions in `frontend/src/theme.test.tsx`.

- [ ] **Step 2: Run focused tests**

Run `npm test -- --run src/theme.test.tsx`. Expected: FAIL because the provider is absent.

- [ ] **Step 3: Implement provider and tokens**

Use a versioned key such as `bearust.theme.v1`; set `document.documentElement.dataset.theme` to the resolved mode; subscribe to `matchMedia("(prefers-color-scheme: dark)")` only for `system`; catch storage errors. Define light defaults and `[data-theme="dark"]` overrides for page/panel surfaces, primary/muted text, borders, focus ring, brand, and success/warning/danger/info aliases. Wrap `<App />` with `ThemeProvider` and call `bootstrapTheme()` before `createRoot`.

- [ ] **Step 4: Run focused tests**

Run `npm test -- --run src/theme.test.tsx`. Expected: all theme tests pass.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/styles.css frontend/src/theme.tsx frontend/src/theme.test.tsx frontend/src/main.tsx
git commit -m "feat: add persisted system light dark themes"
```

### Task 3: Create shared accessible UI primitives

**Files:** `frontend/src/ui.tsx`, `frontend/src/ui.test.tsx`

**Interfaces:** `Button` supports `primary`, `secondary`, `danger`; `Card` renders a semantic section; `Field` associates label/input/error; `Alert` supports `info`, `success`, `warning`, `danger`; `ThemeSelect` uses `useTheme`.

- [ ] **Step 1: Write failing component tests**

Test label association, button disabled state, alert status role, and theme selector changes.

- [ ] **Step 2: Run tests to verify failure**

Run `npm test -- --run src/ui.test.tsx`. Expected: FAIL because primitives are absent.

- [ ] **Step 3: Implement primitives**

Use only Tailwind utilities and semantic token aliases. Include visible `focus-visible` rings, disabled styles, minimum touch targets, and status text that does not rely on color alone.

- [ ] **Step 4: Run component tests**

Run `npm test -- --run src/ui.test.tsx`. Expected: all primitive tests pass.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/ui.tsx frontend/src/ui.test.tsx
git commit -m "feat: add accessible tailwind ui primitives"
```

### Task 4: Migrate the application shell and all pages

**Files:** `frontend/src/App.tsx`, `frontend/src/styles.css`, and existing `frontend/src/*test.tsx` files whose selectors reference removed classes.

- [ ] **Step 1: Migrate setup and login**

Use `Card`, `Field`, and `Button` with responsive container utilities. Preserve first-user setup, setup-token errors, and password validation.

- [ ] **Step 2: Migrate authenticated shell**

Add responsive header/navigation, user information, logout, realtime status, and `ThemeSelect`. Preserve role-based visibility and session invalidation.

- [ ] **Step 3: Migrate management sections**

Refactor proxy hosts, certificates, users, roles, and audit log sections with responsive grids/forms, bounded table scrolling, semantic alerts, loading/empty states, and danger actions. Preserve API calls, filters, pagination, and redaction.

- [ ] **Step 4: Remove obsolete CSS**

Delete legacy selectors after all JSX references are removed. Keep only Tailwind imports, token declarations, theme overrides, and reduced-motion handling.

- [ ] **Step 5: Run the full frontend suite**

Run `npm test -- --run`. Expected: all existing and new tests pass.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/App.tsx frontend/src/styles.css frontend/src/*test.tsx
git commit -m "feat: migrate management ui to tailwind design system"
```

### Task 5: Responsive/accessibility verification and documentation

**Files:** `README.md` if frontend instructions need updates; `docs/PRD.md` for the Phase 4D.3 status note.

- [ ] **Step 1: Run build and static checks**

```bash
cd frontend && npm run build
cd .. && git diff --check
```

Expected: both commands pass.

- [ ] **Step 2: Run responsive smoke checks**

Start `npm run dev -- --host 0.0.0.0` from `frontend` and inspect setup/login plus authenticated routes at 1280px, 768px, and 390px. Verify no page-level horizontal overflow, clipped controls, or invisible focus indicators.

- [ ] **Step 3: Document completion and deferred account sync**

Add a concise PRD status note stating all existing pages use Tailwind v4, themes are system/light/dark with local persistence, and account-level preference sync remains part of system settings.

- [ ] **Step 4: Commit documentation**

```bash
git add README.md docs/PRD.md
git commit -m "docs: mark phase 4d3 frontend system complete"
```

## Final verification

```bash
cd frontend && npm test -- --run && npm run build
cd .. && git diff --check && git status --short --branch
```

Expected: tests and build pass, diff check is clean, and only the pre-existing untracked `.claude/` workspace metadata remains.
