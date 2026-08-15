# Frontend shadcn-admin Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace BeaRust's router-less, single-file frontend shell with a TanStack Router + TanStack Query + Zustand + shadcn/ui shell — dependencies, theming tokens, auth guard, sidebar/topbar layout, and command palette — with no product features ported yet (Setup/Login/Bot-Challenge are the only screens; the authenticated area shows a single placeholder landing route).

**Architecture:** Four new layers replace `App.tsx`: `routes/` (TanStack Router, file-based, thin), `stores/` (Zustand — `auth-store.ts`), `components/ui/` (vendored shadcn/ui primitives), `components/layout/` (sidebar/topbar shell). `api.ts`, `theme.tsx`, `i18n.ts`, `realtime.ts` are reused unchanged. This is Phase 0+1 of a larger migration; each of BeaRust's 15 feature sections becomes its own follow-up plan once this shell is verified working end-to-end.

**Tech Stack:** React 19 (already in use), TypeScript, Vite, Tailwind CSS v4 (already in use), `@tanstack/react-router` + `@tanstack/router-plugin`, `@tanstack/react-query`, `zustand`, Radix UI primitives, `class-variance-authority`, `clsx`, `tailwind-merge`, `lucide-react`, `sonner`, `cmdk`.

**Spec:** `docs/superpowers/specs/2026-08-15-frontend-shadcn-admin-migration-design.md`

## Global Constraints

- No backend/API change: `frontend/src/api.ts`'s exported functions and types are frozen and reused verbatim (per spec's "Data layer").
- No i18n copy or key-name changes: `en.json`/`id.json`/`ja.json` keep every existing key (per spec's "Scope").
- `theme.tsx`, `i18n.ts`, `realtime.ts` move over unchanged — no rewrite, only new call sites (per spec's "Layering").
- Icons: `lucide-react` throughout the new shell; the hand-authored `frontend/src/icons.tsx` is not used by anything built in this plan (per spec's "UI component system").
- Every task ends green on `npx tsc --noEmit`, `npx vitest run`, and `npm run build` before moving to the next task (per spec's "Verification").
- All commands below run from `/home/rizalord/Projects/personal/bearust/frontend` unless stated otherwise.

---

### Task 1: Dependencies, path alias, router codegen plugin

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/vite.config.ts`
- Modify: `frontend/tsconfig.json`

**Interfaces:**
- Produces: `@/*` import alias resolving to `frontend/src/*`, used by every subsequent task's imports.

- [ ] **Step 1: Install the new dependencies**

```bash
npm install @tanstack/react-router @tanstack/react-query zustand \
  class-variance-authority clsx tailwind-merge lucide-react tw-animate-css \
  @radix-ui/react-slot @radix-ui/react-dialog @radix-ui/react-dropdown-menu \
  @radix-ui/react-separator @radix-ui/react-avatar @radix-ui/react-label \
  @radix-ui/react-tooltip @radix-ui/react-collapsible cmdk sonner
npm install -D @tanstack/router-plugin
```

- [ ] **Step 2: Add the `@` path alias to `tsconfig.json`**

Edit `frontend/tsconfig.json`, add `baseUrl`/`paths` inside `compilerOptions`:

```json
{"compilerOptions":{"target":"ES2022","useDefineForClassFields":true,"lib":["ES2022","DOM","DOM.Iterable"],"allowJs":false,"skipLibCheck":true,"esModuleInterop":true,"allowSyntheticDefaultImports":true,"strict":true,"module":"ESNext","moduleResolution":"Bundler","resolveJsonModule":true,"isolatedModules":true,"noEmit":true,"jsx":"react-jsx","baseUrl":".","paths":{"@/*":["./src/*"]}},"include":["src"]}
```

- [ ] **Step 3: Add the alias to Vite and register the TanStack Router codegen plugin**

Replace `frontend/vite.config.ts` with:

```ts
import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { tanstackRouter } from '@tanstack/router-plugin/vite';
import { configDefaults } from 'vitest/config';

export default defineConfig({
  plugins: [
    tanstackRouter({ target: 'react', autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: { proxy: { '/api': 'http://localhost:8081' } },
  test: { exclude: [...configDefaults.exclude, 'e2e/**'] },
});
```

- [ ] **Step 4: Verify the toolchain still boots**

Run: `npx tsc --noEmit` — expect it to fail only on `Cannot find module './App'`-style errors that already existed before this task, not on anything alias-related. Run: `npm run dev -- --port 5183 &` then `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5183/` — expect `200`, then stop the dev server.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json vite.config.ts tsconfig.json
git commit -m "build: add TanStack Router/Query, Zustand, and shadcn/ui dependencies"
```

---

### Task 2: shadcn/ui token layer (`cn()` helper + Tailwind theme tokens)

**Files:**
- Create: `frontend/src/lib/utils.ts`
- Create: `frontend/src/styles/theme.css`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `cn(...inputs: ClassValue[]): string` from `@/lib/utils`, imported by every shadcn/ui primitive in Tasks 3-5.
- Produces: Tailwind utility classes `bg-primary`, `text-primary-foreground`, `bg-background`, `text-foreground`, `bg-card`, `bg-popover`, `bg-secondary`, `bg-muted`, `bg-accent`, `bg-destructive`, `border-border`, `border-input`, `ring-ring`, `bg-sidebar`, etc. (the shadcn/ui token vocabulary every vendored primitive assumes exists).

- [ ] **Step 1: Add the `cn()` helper**

Create `frontend/src/lib/utils.ts`:

```ts
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

- [ ] **Step 2: Add the shadcn/ui token layer, mapped to BeaRust's amber brand**

Create `frontend/src/styles/theme.css` (light values reuse the neutrals already established for BeaRust's dashboard; `--primary`/`--ring`/`--sidebar-primary` are BeaRust's amber, not shadcn-admin's default slate):

```css
:root {
  --radius: 0.625rem;
  --background: #f2f3f5;
  --foreground: #1c2128;
  --card: #ffffff;
  --card-foreground: #1c2128;
  --popover: #ffffff;
  --popover-foreground: #1c2128;
  --primary: #b87d05;
  --primary-foreground: #fffaf0;
  --secondary: #eceef1;
  --secondary-foreground: #1c2128;
  --muted: #eceef1;
  --muted-foreground: #626975;
  --accent: #eceef1;
  --accent-foreground: #1c2128;
  --destructive: #d32f2f;
  --destructive-foreground: #ffffff;
  --border: #e1e3e8;
  --input: #c7cbd3;
  --ring: #b87d05;

  --sidebar: #ffffff;
  --sidebar-foreground: #1c2128;
  --sidebar-primary: #b87d05;
  --sidebar-primary-foreground: #fffaf0;
  --sidebar-accent: #eceef1;
  --sidebar-accent-foreground: #1c2128;
  --sidebar-border: #e1e3e8;
  --sidebar-ring: #b87d05;
}

.dark {
  --background: #111318;
  --foreground: #e9eaec;
  --card: #1a1d24;
  --card-foreground: #e9eaec;
  --popover: #1a1d24;
  --popover-foreground: #e9eaec;
  --primary: #f5a524;
  --primary-foreground: #201505;
  --secondary: #232730;
  --secondary-foreground: #e9eaec;
  --muted: #232730;
  --muted-foreground: #9aa1ac;
  --accent: #232730;
  --accent-foreground: #e9eaec;
  --destructive: #ef5350;
  --destructive-foreground: #201505;
  --border: #2b303a;
  --input: #3c4250;
  --ring: #f5a524;

  --sidebar: #1a1d24;
  --sidebar-foreground: #e9eaec;
  --sidebar-primary: #f5a524;
  --sidebar-primary-foreground: #201505;
  --sidebar-accent: #232730;
  --sidebar-accent-foreground: #e9eaec;
  --sidebar-border: #2b303a;
  --sidebar-ring: #f5a524;
}

@theme inline {
  --radius-sm: calc(var(--radius) - 4px);
  --radius-md: calc(var(--radius) - 2px);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) + 4px);
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-destructive-foreground: var(--destructive-foreground);
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-ring: var(--sidebar-ring);
}
```

Theme selection (`.dark` class vs. default) is driven by BeaRust's existing `bootstrapTheme()`/`ThemeProvider` (`theme.tsx`) — Task 8 adds a `dark:` class binding driven by `document.documentElement.dataset.theme`, not a rewrite of the theme system itself.

- [ ] **Step 3: Import the new token layer and `tw-animate-css` from the main stylesheet**

Edit `frontend/src/styles.css`, add after the existing `@import "tailwindcss";` line:

```css
@import "tailwindcss";
@import "tw-animate-css";
@import "./styles/theme.css";
```

Leave every other rule in `styles.css` (the current Material-pass fonts/tokens/component rules) untouched for now — they still drive `frontend/src/ui.tsx` and `App.tsx`, which are not removed until each feature is ported in a later plan.

- [ ] **Step 4: Verify**

Run: `npx tsc --noEmit` (no new errors), `npm run build` (succeeds), then open `frontend/dist/assets/*.css` and confirm it contains `--color-primary` — grep: `grep -c 'color-primary' dist/assets/*.css` returns a nonzero count.

- [ ] **Step 5: Commit**

```bash
git add src/lib/utils.ts src/styles/theme.css src/styles.css
git commit -m "feat: add shadcn/ui token layer mapped to BeaRust's amber brand"
```

---

### Task 3: Core shadcn/ui primitives — Button, Input, Label, Card, Separator, Avatar

**Files:**
- Create: `frontend/src/components/ui/button.tsx`
- Create: `frontend/src/components/ui/input.tsx`
- Create: `frontend/src/components/ui/label.tsx`
- Create: `frontend/src/components/ui/card.tsx`
- Create: `frontend/src/components/ui/separator.tsx`
- Create: `frontend/src/components/ui/avatar.tsx`

**Interfaces:**
- Consumes: `cn` from `@/lib/utils` (Task 2).
- Produces: `Button`/`buttonVariants`, `Input`, `Label`, `Card`/`CardHeader`/`CardTitle`/`CardDescription`/`CardContent`/`CardFooter`/`CardAction`, `Separator`, `Avatar`/`AvatarImage`/`AvatarFallback` — used by Tasks 4, 5, 9, 11.

These six files are framework-neutral shadcn/ui primitives with zero BeaRust-specific logic — vendor them verbatim from the reference template already cloned locally, then verify each compiles standalone.

- [ ] **Step 1: Copy the six files verbatim**

```bash
for f in button input label card separator avatar; do
  cp /tmp/shadcn-admin-ref/src/components/ui/$f.tsx frontend/src/components/ui/$f.tsx
done
```

- [ ] **Step 2: Verify each file's only local import is `@/lib/utils`**

Run: `grep -L '@/lib/utils\|^import \* as React\|^import type' frontend/src/components/ui/{button,input,label,card,separator,avatar}.tsx` — expect no output (every file imports only `@/lib/utils` locally, everything else is `react` or a `@radix-ui/*` package already installed in Task 1).

- [ ] **Step 3: Type-check**

Run: `npx tsc --noEmit` — expect no errors referencing these six files.

- [ ] **Step 4: Commit**

```bash
git add src/components/ui/button.tsx src/components/ui/input.tsx src/components/ui/label.tsx src/components/ui/card.tsx src/components/ui/separator.tsx src/components/ui/avatar.tsx
git commit -m "feat: vendor core shadcn/ui primitives (button, input, label, card, separator, avatar)"
```

---

### Task 4: Layout primitives — Sidebar, DropdownMenu, Sheet, Tooltip, Collapsible

**Files:**
- Create: `frontend/src/components/ui/sidebar.tsx`
- Create: `frontend/src/components/ui/dropdown-menu.tsx`
- Create: `frontend/src/components/ui/sheet.tsx`
- Create: `frontend/src/components/ui/tooltip.tsx`
- Create: `frontend/src/components/ui/collapsible.tsx`
- Create: `frontend/src/hooks/use-mobile.tsx`
- Create: `frontend/src/lib/cookies.ts`

**Interfaces:**
- Consumes: `cn` (Task 2), `Separator`/`Input`/`Button` (Task 3).
- Produces: `Sidebar`, `SidebarProvider`, `SidebarInset`, `SidebarTrigger`, `SidebarRail`, `SidebarHeader`, `SidebarContent`, `SidebarFooter`, `SidebarMenu`/`SidebarMenuItem`/`SidebarMenuButton`, `SidebarGroup`/`SidebarGroupLabel`, `useSidebar()` (all from `sidebar.tsx`) — used by Task 11. `DropdownMenu*` — used by Task 11 (`nav-user.tsx`). `getCookie`/`setCookie`/`removeCookie` — used by Task 11 (sidebar collapsed-state persistence).

- [ ] **Step 1: Copy the five UI files and the mobile-breakpoint hook verbatim**

```bash
for f in sidebar dropdown-menu sheet tooltip collapsible; do
  cp /tmp/shadcn-admin-ref/src/components/ui/$f.tsx frontend/src/components/ui/$f.tsx
done
cp /tmp/shadcn-admin-ref/src/hooks/use-mobile.tsx frontend/src/hooks/use-mobile.tsx
```

- [ ] **Step 2: Add the cookie helper `sidebar.tsx` depends on**

Create `frontend/src/lib/cookies.ts`:

```ts
export function getCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  return match?.split("=")[1];
}

export function setCookie(name: string, value: string, maxAgeSeconds = 60 * 60 * 24 * 7) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=${value}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax`;
}

export function removeCookie(name: string) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; path=/; max-age=0`;
}
```

- [ ] **Step 3: Type-check**

Run: `npx tsc --noEmit` — expect no errors in `src/components/ui/{sidebar,dropdown-menu,sheet,tooltip,collapsible}.tsx`, `src/hooks/use-mobile.tsx`, or `src/lib/cookies.ts`.

- [ ] **Step 4: Commit**

```bash
git add src/components/ui/sidebar.tsx src/components/ui/dropdown-menu.tsx src/components/ui/sheet.tsx src/components/ui/tooltip.tsx src/components/ui/collapsible.tsx src/hooks/use-mobile.tsx src/lib/cookies.ts
git commit -m "feat: vendor shadcn/ui sidebar/dropdown-menu/sheet primitives"
```

---

### Task 5: Command palette and toast primitives

**Files:**
- Create: `frontend/src/components/ui/command.tsx`
- Create: `frontend/src/components/ui/dialog.tsx`
- Create: `frontend/src/components/ui/sonner.tsx`

**Interfaces:**
- Consumes: `cn` (Task 2), `useTheme` from `@/theme` (BeaRust's own, **not** the reference template's `@/context/theme-provider`).
- Produces: `Command`/`CommandDialog`/`CommandInput`/`CommandList`/`CommandEmpty`/`CommandGroup`/`CommandItem`/`CommandShortcut` — used by Task 12. `Dialog`/`DialogContent`/`DialogTrigger` — a dependency of `command.tsx`'s `CommandDialog`. `Toaster` — used by Task 8 (`__root.tsx`).

- [ ] **Step 1: Copy `command.tsx` and `dialog.tsx` verbatim**

```bash
cp /tmp/shadcn-admin-ref/src/components/ui/command.tsx frontend/src/components/ui/command.tsx
cp /tmp/shadcn-admin-ref/src/components/ui/dialog.tsx frontend/src/components/ui/dialog.tsx
```

Run: `npm install @radix-ui/react-dialog` if `tsc` reports it missing (Task 1 already installs it — this is a safety check, not a new dependency).

- [ ] **Step 2: Add `sonner.tsx`, adapted to BeaRust's own theme hook**

Create `frontend/src/components/ui/sonner.tsx` (differs from the reference template only in the import and the destructured field — BeaRust's `useTheme()` returns `{ mode, resolved, setMode }`, not `{ theme }`):

```tsx
import { Toaster as Sonner, type ToasterProps } from "sonner";
import { useTheme } from "@/theme";

export function Toaster({ ...props }: ToasterProps) {
  const { resolved } = useTheme();

  return (
    <Sonner
      theme={resolved}
      className="toaster group [&_div[data-content]]:w-full"
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
        } as React.CSSProperties
      }
      {...props}
    />
  );
}
```

- [ ] **Step 3: Type-check**

Run: `npx tsc --noEmit` — expect no errors in the three new files.

- [ ] **Step 4: Commit**

```bash
git add src/components/ui/command.tsx src/components/ui/dialog.tsx src/components/ui/sonner.tsx
git commit -m "feat: vendor shadcn/ui command palette and toast primitives"
```

---

### Task 6: Auth store (Zustand)

**Files:**
- Create: `frontend/src/stores/auth-store.ts`
- Test: `frontend/src/stores/auth-store.test.ts`

**Interfaces:**
- Consumes: `User` type from `@/api`.
- Produces: `useAuthStore()` returning `{ user: User | null; setUser: (user: User | null) => void; reset: () => void }` — used by Task 10 (auth guard sync) and Task 11 (sidebar RBAC gating, nav-user display).

- [ ] **Step 1: Write the failing test**

Create `frontend/src/stores/auth-store.test.ts`:

```ts
import { describe, expect, it, afterEach } from "vitest";
import { useAuthStore } from "./auth-store";

const admin = { id: 1, email: "admin@example.com", role: "admin", disabled: false } as const;

describe("useAuthStore", () => {
  afterEach(() => {
    useAuthStore.getState().reset();
  });

  it("starts with no user", () => {
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("setUser stores the user", () => {
    useAuthStore.getState().setUser(admin);
    expect(useAuthStore.getState().user).toEqual(admin);
  });

  it("reset clears the user", () => {
    useAuthStore.getState().setUser(admin);
    useAuthStore.getState().reset();
    expect(useAuthStore.getState().user).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/stores/auth-store.test.ts` — Expected: FAIL with "Cannot find module './auth-store'".

- [ ] **Step 3: Implement the store**

Create `frontend/src/stores/auth-store.ts`:

```ts
import { create } from "zustand";
import type { User } from "@/api";

interface AuthState {
  user: User | null;
  setUser: (user: User | null) => void;
  reset: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  setUser: (user) => set({ user }),
  reset: () => set({ user: null }),
}));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/stores/auth-store.test.ts` — Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/stores/auth-store.ts src/stores/auth-store.test.ts
git commit -m "feat: add Zustand auth store"
```

---

### Task 7: Extract bot-challenge solving logic

**Files:**
- Create: `frontend/src/features/bot-challenge/solve.ts`
- Test: `frontend/src/features/bot-challenge/solve.test.ts`
- Modify: `frontend/src/App.tsx:1231-1256` (remove `serverChallengeFingerprint`/`solveBotChallenge`; `BotChallengePage` at `App.tsx:2512` keeps working from its current import of `i18n` until Task 9 ports it into a route — this task only relocates the two standalone helper functions, which currently have zero test coverage)

**Interfaces:**
- Consumes: `BotChallenge` type from `@/api`, `i18n` from `@/i18n`.
- Produces: `serverChallengeFingerprint(): string`, `solveBotChallenge(challenge: BotChallenge, fingerprint: string): Promise<string>` — used by Task 9's ported bot-challenge route.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/features/bot-challenge/solve.test.ts`:

```ts
import { describe, expect, it, beforeEach } from "vitest";
import { serverChallengeFingerprint, solveBotChallenge } from "./solve";
import type { BotChallenge } from "@/api";

describe("serverChallengeFingerprint", () => {
  beforeEach(() => sessionStorage.clear());

  it("returns empty string when nothing is stored", () => {
    expect(serverChallengeFingerprint()).toBe("");
  });

  it("returns the stored value when it matches the 16-hex-char shape", () => {
    sessionStorage.setItem("bearust-bot-fingerprint", "0123456789abcdef");
    expect(serverChallengeFingerprint()).toBe("0123456789abcdef");
  });

  it("rejects a malformed stored value", () => {
    sessionStorage.setItem("bearust-bot-fingerprint", "not-hex");
    expect(serverChallengeFingerprint()).toBe("");
  });
});

describe("solveBotChallenge", () => {
  it("finds a nonce whose SHA-256 digest starts with the required zero prefix", async () => {
    const challenge: BotChallenge = {
      token: "header.payload.signature",
      difficulty: 1,
      expires_at: Date.now() + 60_000,
      fingerprint_prefix: "abcd",
    };
    const solution = await solveBotChallenge(challenge, "0123456789abcdef");
    const encoder = new TextEncoder();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${challenge.token.split(".")[1] ?? ""}${solution}`),
    );
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex.startsWith("0")).toBe(true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/features/bot-challenge/solve.test.ts` — Expected: FAIL with "Cannot find module './solve'".

- [ ] **Step 3: Implement `solve.ts`**

Create `frontend/src/features/bot-challenge/solve.ts` (moved verbatim from `App.tsx:1231-1256`, now exported):

```ts
import type { BotChallenge } from "@/api";
import { i18n } from "@/i18n";

export const serverChallengeFingerprint = () => {
  if (typeof sessionStorage === "undefined") return "";
  const value = sessionStorage.getItem("bearust-bot-fingerprint") ?? "";
  return /^[a-f0-9]{16}$/.test(value) ? value : "";
};

export async function solveBotChallenge(
  challenge: BotChallenge,
  fingerprint: string,
): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle)
    throw new Error(i18n.t("errors.challengeUnavailable"));
  const encoder = new TextEncoder();
  const prefix = "0".repeat(Math.min(challenge.difficulty, 4));
  for (let nonce = 0; nonce < 1_000_000; nonce += 1) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${challenge.token.split(".")[1] ?? ""}${nonce}`),
    );
    const hex = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    if (hex.startsWith(prefix)) return String(nonce);
  }
  throw new Error(i18n.t("errors.challengeVerification"));
}
```

Remove the two functions (`App.tsx:1231-1236` and `App.tsx:1237-1256`) from `App.tsx`, and change `App.tsx`'s `BotChallengePage` (currently at line 2512) to `import { serverChallengeFingerprint, solveBotChallenge } from "./features/bot-challenge/solve";` at the top of the file, replacing its two now-dangling references. `App.tsx` keeps working exactly as before for every screen not yet ported (Task 9 replaces the standalone `/bot-challenge` handling in `AppContent` entirely, at which point this import in `App.tsx` is deleted along with the rest of `BotChallengePage`).

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/features/bot-challenge/solve.test.ts` — Expected: PASS, 4 tests.

- [ ] **Step 5: Run the full existing suite to confirm nothing else broke**

Run: `npx vitest run` — Expected: same pass count as before this task (161 passed), since `App.tsx`'s behavior is unchanged, only its import source for two functions moved.

- [ ] **Step 6: Commit**

```bash
git add src/features/bot-challenge/solve.ts src/features/bot-challenge/solve.test.ts src/App.tsx
git commit -m "refactor: extract bot-challenge solving logic into its own tested module"
```

---

### Task 8: Router bootstrap — `__root.tsx` and `main.tsx`

**Files:**
- Create: `frontend/src/routes/__root.tsx`
- Modify: `frontend/src/main.tsx`

**Interfaces:**
- Consumes: `bootstrapTheme`, `ThemeProvider`, `useTheme` (`@/theme`, unchanged), `i18n`, `initI18n` (`@/i18n`, unchanged), `Toaster` (Task 5).
- Produces: a mounted `RouterProvider` any route file (Tasks 9-11) attaches to via `createFileRoute`; a `QueryClient` instance every feature's `hooks.ts` (future plans) reads via `useQueryClient()`.

- [ ] **Step 1: Create the root route**

Create `frontend/src/routes/__root.tsx`:

```tsx
import { type QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import { Toaster } from "@/components/ui/sonner";

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  component: () => (
    <>
      <Outlet />
      <Toaster duration={5000} />
    </>
  ),
});
```

- [ ] **Step 2: Rewrite `main.tsx` to bootstrap the router**

Replace `frontend/src/main.tsx` with:

```tsx
import React from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createRouter } from "@tanstack/react-router";
import { I18nextProvider } from "react-i18next";
import { i18n, initI18n } from "./i18n";
import { ThemeProvider, bootstrapTheme } from "./theme";
import "./styles.css";
import { routeTree } from "./routeTree.gen";

bootstrapTheme();
void initI18n();

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});

const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <ThemeProvider>
          <RouterProvider router={router} />
        </ThemeProvider>
      </I18nextProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
```

`retry: false` (rather than the reference template's retry-on-non-401/403 logic) is deliberate for this shell task: `api.ts`'s `request()` already throws a typed `ApiError`, and per-resource retry policy is a Task for each feature's `hooks.ts` in a later plan, not the shell.

- [ ] **Step 3: Generate the route tree and verify the dev server boots**

Run: `npm run dev -- --port 5183 &`, wait 2 seconds, then `test -f src/routeTree.gen.ts && echo FOUND` — Expected: `FOUND` (the Vite plugin from Task 1 generates this file on first run). Run: `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5183/` — Expected: `200`. Stop the dev server.

- [ ] **Step 4: Add `routeTree.gen.ts` to `.gitignore`**

Append to `frontend/.gitignore` (create the file if it doesn't exist): `src/routeTree.gen.ts`

- [ ] **Step 5: Type-check**

Run: `npx tsc --noEmit` — expect errors only from the not-yet-deleted `App.tsx`/`main.tsx`-adjacent files this task doesn't touch (none, since `main.tsx` no longer imports `App.tsx` — if `App.tsx` itself has no import errors on its own, `tsc` should be fully clean at this point since nothing references it anymore; if something still imports `App` for a reason not covered by this plan, note it and stop rather than guessing).

- [ ] **Step 6: Commit**

```bash
git add src/routes/__root.tsx src/main.tsx .gitignore
git commit -m "feat: bootstrap TanStack Router + TanStack Query in main.tsx"
```

---

### Task 9: Public routes — Setup, Login, Bot Challenge

**Files:**
- Create: `frontend/src/routes/(auth)/setup.tsx`
- Create: `frontend/src/routes/(auth)/login.tsx`
- Create: `frontend/src/routes/bot-challenge.tsx`
- Test: `frontend/src/routes/setup.test.tsx`
- Test: `frontend/src/routes/login.test.tsx`
- Test: `frontend/src/test-utils/render-route.tsx`

**Interfaces:**
- Consumes: `api.setup`, `api.login`, `api.botChallenge`, `api.verifyBotChallenge` (`@/api`, unchanged), `Button`/`Input`/`Label`/`Card` (Task 3), `serverChallengeFingerprint`/`solveBotChallenge` (Task 7), `useAuthStore` (Task 6).
- Produces: `render-route.tsx`'s `renderRoute(routeTree, opts)` helper, reused by every subsequent test in this plan and future feature plans.

- [ ] **Step 1: Write the shared route-testing helper**

Create `frontend/src/test-utils/render-route.tsx`:

```tsx
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
  type AnyRoute,
} from "@tanstack/react-router";
import { I18nextProvider } from "react-i18next";
import { i18n, initI18n } from "@/i18n";

export async function renderRoute(routes: AnyRoute[], initialPath: string) {
  await initI18n("en");
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const rootRoute = createRootRoute();
  const router = createRouter({
    routeTree: rootRoute.addChildren(routes),
    history: createMemoryHistory({ initialEntries: [initialPath] }),
    context: { queryClient },
  });
  const element = document.createElement("div");
  document.body.appendChild(element);
  const root: Root = createRoot(element);
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <I18nextProvider i18n={i18n}>
          <RouterProvider router={router} />
        </I18nextProvider>
      </QueryClientProvider>,
    );
  });
  return { element, root, router };
}
```

- [ ] **Step 2: Write the failing Setup route test**

Create `frontend/src/routes/setup.test.tsx`:

```tsx
// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { act } from "react";
import { api } from "@/api";
import { renderRoute } from "@/test-utils/render-route";
import { Route as SetupRoute } from "./(auth)/setup";

describe("Setup route", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("submits the setup form and shows a server error inline", async () => {
    vi.spyOn(api, "setup").mockRejectedValue(
      Object.assign(new Error("Invalid setup token"), { status: 400 }),
    );
    const { element } = await renderRoute([SetupRoute], "/setup");
    const form = element.querySelector("form") as HTMLFormElement;
    expect(form).toBeTruthy();
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(element.textContent).toContain("Invalid setup token");
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

Run: `npx vitest run src/routes/setup.test.tsx` — Expected: FAIL with "Cannot find module './(auth)/setup'".

- [ ] **Step 4: Port the Setup route**

Create `frontend/src/routes/(auth)/setup.tsx` (adapted from `App.tsx:199-247`'s `Setup` component — `Panel`/`Field`/`Alert`/`StatusLamp` (`ui.tsx`) become `Card`/`Input`+`Label`/inline error paragraph):

```tsx
import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/(auth)/setup")({
  component: SetupPage,
});

function sanitizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function SetupPage() {
  const { t } = useTranslation();
  const navigate = Route.useNavigate();
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [token, setToken] = useState(""),
    [error, setError] = useState("");

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <Card className="mx-auto w-full max-w-lg">
        <CardHeader>
          <CardTitle>{t("auth.setupTitle")}</CardTitle>
          <CardDescription>{t("auth.setupDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                await api.setup({ email, password, setup_token: token });
                void navigate({ to: "/" });
              } catch (x) {
                setError(sanitizeError(x));
              }
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="setup-email">{t("common.email")}</Label>
              <Input id="setup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="setup-password">{t("auth.passwordHint")}</Label>
              <Input id="setup-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="setup-token">{t("auth.setupToken")}</Label>
              <Input id="setup-token" value={token} onChange={(e) => setToken(e.target.value)} />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full">
              {t("auth.createAccount")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `npx vitest run src/routes/setup.test.tsx` — Expected: PASS, 1 test.

- [ ] **Step 6: Write the failing Login route test, then port `login.tsx` the same way**

Create `frontend/src/routes/login.test.tsx` (mirrors Step 2, mocking `api.login` instead of `api.setup`, importing `Route as LoginRoute` from `./(auth)/login`, asserting the rejected error text appears). Run it (FAIL), then create `frontend/src/routes/(auth)/login.tsx` adapted the same way from `App.tsx:248-299`'s `Login` component (brand mark span + `Card` wrapping the form; on success, `await api.login(...)` then `navigate({ to: "/" })`). Run the test again (PASS).

- [ ] **Step 7: Port the Bot Challenge route (no test — ported behavior is already covered by `solve.test.ts` from Task 7; the route itself is thin composition)**

Create `frontend/src/routes/bot-challenge.tsx`, adapted from `App.tsx:2512-2580`'s `BotChallengePage` (same state machine, `Panel`/`Alert`/`Button` swapped for `Card`/inline paragraph/`Button`, importing `serverChallengeFingerprint`/`solveBotChallenge` from `@/features/bot-challenge/solve` per Task 7):

```tsx
import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/api";
import type { BotChallenge } from "@/api";
import { serverChallengeFingerprint, solveBotChallenge } from "@/features/bot-challenge/solve";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

export const Route = createFileRoute("/bot-challenge")({
  component: BotChallengePage,
  validateSearch: (search: Record<string, unknown>) => ({
    fingerprint_prefix: typeof search.fingerprint_prefix === "string" ? search.fingerprint_prefix : undefined,
  }),
});

function BotChallengePage() {
  const { t } = useTranslation();
  const { fingerprint_prefix } = Route.useSearch();
  useEffect(() => {
    if (fingerprint_prefix && /^[a-f0-9]{16}$/.test(fingerprint_prefix)) {
      sessionStorage.setItem("bearust-bot-fingerprint", fingerprint_prefix);
    }
  }, [fingerprint_prefix]);

  const fingerprint = serverChallengeFingerprint();
  const [challenge, setChallenge] = useState<BotChallenge | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [complete, setComplete] = useState(false);

  useEffect(() => {
    if (!fingerprint) {
      setError(t("errors.challengeContext"));
      return;
    }
    setBusy(true);
    api
      .botChallenge(fingerprint)
      .then(setChallenge)
      .catch(() => setError(t("errors.challengeUnavailable")))
      .finally(() => setBusy(false));
  }, [fingerprint, t]);

  const verify = async () => {
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const solution = await solveBotChallenge(challenge, fingerprint);
      await api.verifyBotChallenge({ token: challenge.token, fingerprint, solution });
      setComplete(true);
    } catch {
      setError(t("errors.challengeVerification"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <Card className="mx-auto w-full max-w-lg">
        <CardHeader>
          <CardTitle>{t("bot.quickCheck")}</CardTitle>
          <CardDescription>{t("bot.quickCheckDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          {error && <p role="alert" className="mb-4 text-sm text-destructive">{error}</p>}
          {complete ? (
            <p className="text-sm text-primary">{t("bot.verificationComplete")}</p>
          ) : (
            <Button disabled={busy || !challenge} onClick={() => void verify()}>
              {busy ? t("bot.verifying") : t("bot.verifyBrowser")}
            </Button>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
```

- [ ] **Step 8: Run the full suite**

Run: `npx vitest run` — Expected: all prior tests still pass, plus the 2 new route tests (163 total).

- [ ] **Step 9: Commit**

```bash
git add src/test-utils/render-route.tsx src/routes/setup.test.tsx src/routes/login.test.tsx src/routes/\(auth\)/setup.tsx src/routes/\(auth\)/login.tsx src/routes/bot-challenge.tsx
git commit -m "feat: port Setup, Login, and Bot Challenge to routed pages"
```

---

### Task 10: Authenticated route guard

**Files:**
- Create: `frontend/src/routes/_authenticated/route.tsx`
- Test: `frontend/src/routes/_authenticated/route.test.tsx`

**Interfaces:**
- Consumes: `api.status`, `api.me` (`@/api`), `useAuthStore` (Task 6), `renderRoute` (Task 9).
- Produces: every `_authenticated/*` child route (Task 11) renders only after this guard's `beforeLoad` resolves; other plans reuse the `['me']` query key this guard establishes.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/routes/_authenticated/route.test.tsx`:

```tsx
// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { renderRoute } from "@/test-utils/render-route";
import { Route as AuthenticatedRoute } from "./route";
import { createRoute } from "@tanstack/react-router";

const admin = { id: 1, email: "admin@example.com", role: "admin", disabled: false } as const;

const childRoute = createRoute({
  getParentRoute: () => AuthenticatedRoute,
  path: "/",
  component: () => <p>authenticated home</p>,
});

describe("_authenticated route guard", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    useAuthStore.getState().reset();
    document.body.innerHTML = "";
  });

  it("renders children and syncs the auth store when a session exists", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: true });
    vi.spyOn(api, "me").mockResolvedValue(admin);
    const { element } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(element.textContent).toContain("authenticated home");
    expect(useAuthStore.getState().user).toEqual(admin);
  });

  it("redirects to /login when there is no session", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: true });
    vi.spyOn(api, "me").mockRejectedValue(Object.assign(new Error("unauthorized"), { status: 401 }));
    const { router } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(router.state.location.pathname).toBe("/login");
  });

  it("redirects to /setup when the backend has no admin yet", async () => {
    vi.spyOn(api, "status").mockResolvedValue({ initialized: false });
    const meSpy = vi.spyOn(api, "me");
    const { router } = await renderRoute([AuthenticatedRoute.addChildren([childRoute])], "/");
    expect(router.state.location.pathname).toBe("/setup");
    expect(meSpy).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/routes/_authenticated/route.test.tsx` — Expected: FAIL with "Cannot find module './route'".

- [ ] **Step 3: Implement the guard**

Create `frontend/src/routes/_authenticated/route.tsx`:

```tsx
import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context }) => {
    const status = await context.queryClient.fetchQuery({
      queryKey: ["setup-status"],
      queryFn: api.status,
      staleTime: Infinity,
    });
    if (!status.initialized) throw redirect({ to: "/setup" });

    try {
      const user = await context.queryClient.fetchQuery({
        queryKey: ["me"],
        queryFn: api.me,
      });
      useAuthStore.getState().setUser(user);
      return { user };
    } catch {
      useAuthStore.getState().reset();
      throw redirect({ to: "/login" });
    }
  },
  component: () => <Outlet />,
});
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/routes/_authenticated/route.test.tsx` — Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/routes/_authenticated/route.tsx src/routes/_authenticated/route.test.tsx
git commit -m "feat: add the _authenticated route guard backed by a TanStack Query ['me'] fetch"
```

---

### Task 11: Sidebar/topbar layout shell and the landing placeholder route

**Files:**
- Create: `frontend/src/components/layout/nav-group.tsx`
- Create: `frontend/src/components/layout/nav-user.tsx`
- Create: `frontend/src/components/layout/app-sidebar.tsx`
- Create: `frontend/src/components/layout/header.tsx`
- Create: `frontend/src/components/layout/authenticated-layout.tsx`
- Create: `frontend/src/components/layout/nav-data.ts`
- Create: `frontend/src/routes/_authenticated/index.tsx`
- Modify: `frontend/src/routes/_authenticated/route.tsx` (render `AuthenticatedLayout` instead of a bare `<Outlet/>`)
- Test: `frontend/src/components/layout/nav-group.test.tsx`

**Interfaces:**
- Consumes: `Sidebar`/`SidebarProvider`/`SidebarInset`/`SidebarTrigger`/`SidebarHeader`/`SidebarContent`/`SidebarFooter`/`SidebarMenu*`/`useSidebar` (Task 4), `DropdownMenu*` (Task 4), `Avatar*` (Task 3), `Separator` (Task 3), `getCookie` (Task 4), `useAuthStore` (Task 6), `useTheme`/`ThemeMode` (`@/theme`), `useLocalePreference`/`Locale` (`@/i18n`), `api.logout`.
- Produces: `NAV_ITEMS` (nav config other plans extend when a feature's real route replaces `_authenticated/index.tsx`'s placeholder).

- [ ] **Step 1: Define the nav config**

Create `frontend/src/components/layout/nav-data.ts` (mirrors today's `App.tsx` `NAV_GROUPS`, `lucide-react` icons replacing `icons.tsx`):

```ts
import type { LucideIcon } from "lucide-react";
import { Cable, Sparkles, ShieldCheck, BarChart3, Users, ScrollText } from "lucide-react";

export type NavItem = {
  title: string;
  labelKey: string;
  url: string;
  icon: LucideIcon;
  adminOnly?: boolean;
};

export const NAV_ITEMS: NavItem[] = [
  { title: "Proxy Hosts", labelKey: "nav.proxyHosts", url: "/", icon: Cable },
  { title: "AI Advisor", labelKey: "nav.aiAdvisor", url: "/ai-advisor", icon: Sparkles },
  { title: "Security", labelKey: "nav.security", url: "/security", icon: ShieldCheck },
  { title: "Analytics", labelKey: "nav.analytics", url: "/analytics", icon: BarChart3 },
  { title: "Users & Roles", labelKey: "nav.users", url: "/users", icon: Users, adminOnly: true },
  { title: "Audit Log", labelKey: "nav.audit", url: "/audit-log", icon: ScrollText },
];
```

- [ ] **Step 2: Write the failing nav-group test (RBAC filtering)**

Create `frontend/src/components/layout/nav-group.test.tsx`:

```tsx
// @vitest-environment jsdom
import { describe, expect, it, afterEach } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { NavGroup } from "./nav-group";

describe("NavGroup", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("hides admin-only items for non-admins", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(<NavGroup isAdmin={false} activePath="/" />);
    });
    expect(element.textContent).not.toContain("Users & Roles");
    expect(element.textContent).toContain("Proxy Hosts");
  });

  it("shows admin-only items for admins", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(<NavGroup isAdmin={true} activePath="/" />);
    });
    expect(element.textContent).toContain("Users & Roles");
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

Run: `npx vitest run src/components/layout/nav-group.test.tsx` — Expected: FAIL with "Cannot find module './nav-group'".

- [ ] **Step 4: Implement `nav-group.tsx`**

Create `frontend/src/components/layout/nav-group.tsx`:

```tsx
import { Link } from "@tanstack/react-router";
import { NAV_ITEMS } from "./nav-data";
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

export function NavGroup({ isAdmin, activePath }: { isAdmin: boolean; activePath: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupContent>
        <SidebarMenu>
          {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map((item) => (
            <SidebarMenuItem key={item.url}>
              <SidebarMenuButton asChild isActive={activePath === item.url}>
                <Link to={item.url}>
                  <item.icon />
                  <span>{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `npx vitest run src/components/layout/nav-group.test.tsx` — Expected: PASS, 2 tests.

- [ ] **Step 6: Implement `nav-user.tsx`** (account dropdown: email/role, theme select, language select, sign out — content ported from today's `App.tsx` `UserMenu`, shell rebuilt on `DropdownMenu`)

Create `frontend/src/components/layout/nav-user.tsx`:

```tsx
import { useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ChevronsUpDown, LogOut } from "lucide-react";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth-store";
import { useTheme, type ThemeMode } from "@/theme";
import { useLocalePreference, normalizeLocale } from "@/i18n";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar";

export function NavUser() {
  const { t } = useTranslation();
  const { isMobile } = useSidebar();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { mode, setMode } = useTheme();
  const { locale, setLocale } = useLocalePreference();
  if (!user) return null;
  const initials = user.email.slice(0, 2).toUpperCase();

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg">
              <Avatar className="h-8 w-8 rounded-lg">
                <AvatarFallback className="rounded-lg">{initials}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{user.email}</span>
                <span className="truncate text-xs text-muted-foreground">{user.role}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side={isMobile ? "bottom" : "right"} align="end" className="min-w-56">
            <DropdownMenuLabel className="font-normal">
              <div className="text-sm font-medium">{user.email}</div>
              <div className="text-xs text-muted-foreground">{user.role}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <div className="px-2 py-1.5 text-xs text-muted-foreground">{t("theme.label")}</div>
            <div className="px-2 pb-2">
              <select
                aria-label={t("theme.label")}
                value={mode}
                onChange={(e) => setMode(e.target.value as ThemeMode)}
                className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
              >
                <option value="system">{t("theme.system")}</option>
                <option value="light">{t("theme.light")}</option>
                <option value="dark">{t("theme.dark")}</option>
              </select>
            </div>
            <div className="px-2 py-1.5 text-xs text-muted-foreground">{t("language.label")}</div>
            <div className="px-2 pb-2">
              <select
                aria-label={t("language.label")}
                value={locale}
                onChange={(e) => void setLocale(normalizeLocale(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
              >
                <option value="en">{t("language.options.en")}</option>
                <option value="id">{t("language.options.id")}</option>
                <option value="ja">{t("language.options.ja")}</option>
              </select>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => {
                void api.logout().catch(() => undefined).finally(() => {
                  useAuthStore.getState().reset();
                  void navigate({ to: "/login" });
                });
              }}
            >
              <LogOut />
              {t("auth.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
```

- [ ] **Step 7: Implement `app-sidebar.tsx`, `header.tsx`, `authenticated-layout.tsx`**

Create `frontend/src/components/layout/app-sidebar.tsx`:

```tsx
import { useRouterState } from "@tanstack/react-router";
import { useAuthStore } from "@/stores/auth-store";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail } from "@/components/ui/sidebar";
import { NavGroup } from "./nav-group";
import { NavUser } from "./nav-user";

export function AppSidebar() {
  const user = useAuthStore((s) => s.user);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-2.5 px-2 py-1.5">
          <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-full bg-primary" />
          <span className="font-semibold tracking-tight text-primary">Bearust</span>
        </div>
      </SidebarHeader>
      <SidebarContent>
        <NavGroup isAdmin={user?.role === "admin"} activePath={pathname} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
```

Create `frontend/src/components/layout/header.tsx`:

```tsx
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";

export function Header({ children }: { children?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex h-16 items-center gap-3 border-b border-border bg-background px-4">
      <SidebarTrigger />
      <Separator orientation="vertical" className="h-6" />
      {children}
    </header>
  );
}
```

Create `frontend/src/components/layout/authenticated-layout.tsx`. **Note:** `nav-user.tsx` (Step 6, above) calls `useLocalePreference()`, which throws if rendered outside a `LocalePreferenceProvider` (`i18n.ts`, unchanged) — this layout is that provider's mount point, matching where today's `App.tsx` mounts it (wrapping the authenticated area, with `accountLocale` from the signed-in user):

```tsx
import { Outlet } from "@tanstack/react-router";
import { getCookie } from "@/lib/cookies";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

export function AuthenticatedLayout() {
  const defaultOpen = getCookie("sidebar_state") !== "false";
  const user = useAuthStore((s) => s.user);
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      <SidebarProvider defaultOpen={defaultOpen}>
        <AppSidebar />
        <SidebarInset>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
```

- [ ] **Step 8: Wire the layout into the guard route**

Edit `frontend/src/routes/_authenticated/route.tsx`, replace `component: () => <Outlet />,` with:

```tsx
component: AuthenticatedLayout,
```

adding `import { AuthenticatedLayout } from "@/components/layout/authenticated-layout";` and removing the now-unused `Outlet` import.

- [ ] **Step 9: Add the landing placeholder route**

Create `frontend/src/routes/_authenticated/index.tsx` (Proxy Hosts is deliberately not ported in this plan — see the spec's Phase 2 — this placeholder occupies the default/landing route so the shell is a complete, navigable, testable unit on its own):

```tsx
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Header } from "@/components/layout/header";

export const Route = createFileRoute("/_authenticated/")({
  component: ProxyHostsPlaceholder,
});

function ProxyHostsPlaceholder() {
  const { t } = useTranslation();
  return (
    <>
      <Header>
        <h1 className="text-lg font-semibold">{t("nav.proxyHosts")}</h1>
      </Header>
      <div className="p-6 text-sm text-muted-foreground">
        {t("nav.proxyHosts")} — not yet ported to the new shell.
      </div>
    </>
  );
}
```

- [ ] **Step 10: Run the full suite and build**

Run: `npx vitest run` — Expected: all tests pass. Run: `npx tsc --noEmit` — Expected: no errors. Run: `npm run build` — Expected: succeeds.

- [ ] **Step 11: Commit**

```bash
git add src/components/layout src/routes/_authenticated
git commit -m "feat: add sidebar/topbar authenticated layout shell with a landing placeholder"
```

---

### Task 12: Command palette (Ctrl+K)

**Files:**
- Create: `frontend/src/components/layout/command-palette.tsx`
- Modify: `frontend/src/routes/__root.tsx` (mount the palette)
- Test: `frontend/src/components/layout/command-palette.test.tsx`

**Interfaces:**
- Consumes: `CommandDialog`/`CommandInput`/`CommandList`/`CommandEmpty`/`CommandGroup`/`CommandItem` (Task 5), `NAV_ITEMS` (Task 11), `useAuthStore` (Task 6).

- [ ] **Step 1: Write the failing test**

Create `frontend/src/components/layout/command-palette.test.tsx`:

```tsx
// @vitest-environment jsdom
import { describe, expect, it, afterEach, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { CommandPalette } from "./command-palette";

describe("CommandPalette", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("opens on Ctrl+K and lists nav destinations", async () => {
    const element = document.createElement("div");
    document.body.appendChild(element);
    await act(async () => {
      createRoot(element).render(<CommandPalette />);
    });
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true }));
    });
    expect(document.body.textContent).toContain("Proxy Hosts");
    expect(document.body.textContent).toContain("Audit Log");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/components/layout/command-palette.test.tsx` — Expected: FAIL with "Cannot find module './command-palette'".

- [ ] **Step 3: Implement it**

Create `frontend/src/components/layout/command-palette.tsx`:

```tsx
import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { NAV_ITEMS } from "./nav-data";
import { useAuthStore } from "@/stores/auth-store";

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Jump to..." />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        <CommandGroup heading="Navigation">
          {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map((item) => (
            <CommandItem
              key={item.url}
              onSelect={() => {
                setOpen(false);
                void navigate({ to: item.url });
              }}
            >
              <item.icon />
              <span>{item.title}</span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `npx vitest run src/components/layout/command-palette.test.tsx` — Expected: PASS, 1 test.

- [ ] **Step 5: Mount it at the root**

Edit `frontend/src/routes/__root.tsx`, add `import { CommandPalette } from "@/components/layout/command-palette";` and render `<CommandPalette />` alongside `<Outlet />` and `<Toaster />`.

- [ ] **Step 6: Commit**

```bash
git add src/components/layout/command-palette.tsx src/components/layout/command-palette.test.tsx src/routes/__root.tsx
git commit -m "feat: add Ctrl+K command palette for sidebar navigation"
```

---

### Task 13: Wire realtime session invalidation

**Files:**
- Modify: `frontend/src/components/layout/authenticated-layout.tsx`

**Interfaces:**
- Consumes: `useRealtimeUpdates` (`@/realtime`, unchanged), `useQueryClient` (`@tanstack/react-query`).

Only `sessions.changed` is wired here — every other SSE event (`hosts`, `certificates`, `waf`, etc.) is wired by the plan that ports the corresponding feature, since there is no query for those resources to invalidate yet.

- [ ] **Step 1: Add the realtime hook to the authenticated layout**

Edit `frontend/src/components/layout/authenticated-layout.tsx` (adds `useQueryClient` + `useRealtimeUpdates` to the version from Task 11 Step 7 — the `LocalePreferenceProvider` wiring from that task is unchanged, keep it):

```tsx
import { Outlet } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { getCookie } from "@/lib/cookies";
import { useAuthStore } from "@/stores/auth-store";
import { LocalePreferenceProvider } from "@/i18n";
import { useRealtimeUpdates } from "@/realtime";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

export function AuthenticatedLayout() {
  const defaultOpen = getCookie("sidebar_state") !== "false";
  const user = useAuthStore((s) => s.user);
  const queryClient = useQueryClient();
  useRealtimeUpdates({
    sessions: () => void queryClient.invalidateQueries({ queryKey: ["me"] }),
  });
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      <SidebarProvider defaultOpen={defaultOpen}>
        <AppSidebar />
        <SidebarInset>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </LocalePreferenceProvider>
  );
}
```

- [ ] **Step 2: Verify**

Run: `npx tsc --noEmit`, `npx vitest run` — Expected: no new errors, no new failures. `realtime.test.tsx`'s existing tests (which test the `useRealtimeUpdates` hook directly, not this call site) still pass unchanged.

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/authenticated-layout.tsx
git commit -m "feat: invalidate the ['me'] query on a sessions.changed SSE event"
```

---

### Task 14: End-to-end shell verification

**Files:** none (verification only)

- [ ] **Step 1: Full automated check**

Run, in order, from `frontend/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build`. Every command must exit 0 before continuing.

- [ ] **Step 2: Mechanical anti-pattern scan**

Run: `node /home/rizalord/.claude/skills/impeccable/scripts/detect.mjs --json src/routes src/components/layout src/components/ui` — review and fix any findings before continuing.

- [ ] **Step 3: Start a real backend and the dev server**

```bash
mkdir -p /tmp/bearust-shell-check/data
cat > /tmp/bearust-shell-check/bearust.toml <<'EOF'
[server]
bind = "127.0.0.1:19095"
control_bind = "127.0.0.1:8095"
control_database = "/tmp/bearust-shell-check/data/control.sqlite"
certificate_store = "/tmp/bearust-shell-check/data/certs"
graceful_shutdown_seconds = 1
pid_file = "/tmp/bearust-shell-check/bearust.pid"

[health]

[[upstream_pools]]
name = "demo"
algorithm = "round_robin"
[[upstream_pools.backends]]
address = "127.0.0.1:19096"
health_check = "tcp"

[[routes]]
name = "demo"
host = "demo.local"
path_prefix = "/"
upstream_pool = "demo"
EOF
cd /home/rizalord/Projects/personal/bearust && cargo build --bin bearust 2>&1 | tail -5
cd /tmp/bearust-shell-check && nohup /home/rizalord/Projects/personal/bearust/target/debug/bearust serve --config bearust.toml > server.log 2>&1 &
sleep 2
cat /tmp/bearust-shell-check/data/setup-token
```

Then, with a Vite dev server proxying to port 8095 (temporarily edit `vite.config.ts`'s proxy target, or run a second `vite --config` copy as done in earlier sessions), use Playwright to capture: `desktop-setup.png`, `desktop-login.png`, `desktop-shell-dark.png`, `desktop-shell-light.png`, `mobile-shell-dark.png`, `desktop-command-palette.png`, `desktop-nav-user-menu.png` — open every file and confirm it shows the real, populated screen (not blank/loading).

- [ ] **Step 4: Manual click-through**

In a real browser against the same backend: complete Setup → land on `/` (placeholder) → open the sidebar collapse toggle → open the account dropdown, switch theme and language → open the command palette (Ctrl+K), jump to a nav item → sign out → confirm redirect to `/login`. Confirm the mobile breakpoint collapses the sidebar into a sheet.

- [ ] **Step 5: Stop the temporary backend**

```bash
kill $(cat /tmp/bearust-shell-check/bearust.pid)
```

- [ ] **Step 6: Update the coarse plan file's status**

Edit `/home/rizalord/.claude/plans/synchronous-zooming-spark.md`, add a note at the top: "Phase 0+1 superseded by `docs/superpowers/plans/2026-08-15-frontend-shadcn-admin-shell.md` (this plan) — see that file for the executed shell. Phase 2 (feature porting) still applies, one plan per feature/feature-cluster, written when each is started."

- [ ] **Step 7: Commit**

```bash
cd /home/rizalord/Projects/personal/bearust
git add .claude/plans/synchronous-zooming-spark.md 2>/dev/null; true
git commit -m "docs: mark the shell plan as superseding Phase 0+1 of the coarse migration plan" --allow-empty
```

---

## After this plan

`App.tsx` still exists, unchanged except for Task 7's two-function extraction, and is no longer imported by anything (`main.tsx` now boots the router directly) — it becomes the source every subsequent feature-porting plan reads from and shrinks, one exported section at a time, until it's deleted. The suggested next plans, in order (per the spec's Phase 2 port order): Proxy Hosts (replaces `_authenticated/index.tsx`'s placeholder), Users/Roles, Security (WAF/Bot Protection/Rate Limit tabs), Analytics/Baseline/Anomaly/AdaptiveTuning, Audit Log, AI Advisor.
