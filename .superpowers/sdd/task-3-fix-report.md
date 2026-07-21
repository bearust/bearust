# Task 3 review fixes

Addressed the Task 3 review findings for the shared Tailwind v4 UI primitives.

- Added all semantic aliases used by `frontend/src/ui.tsx` to the light and dark token maps: action, action-hover, action-foreground, surface, surface-muted, foreground, muted, focus offset, and info/success/warning/danger border, surface, foreground, and hover tokens.
- Kept the existing canonical token names (`page`, `panel`, `text`, `brand`, etc.) for compatibility.
- Set the global brand/action primary to `#D99906` in both themes, with a dark accessible foreground and hover value.
- Updated `ThemeSelect` to invoke a caller-provided `onChange` handler after synchronizing theme state.
- Added a regression test for the caller `onChange` behavior.

## Verification

Command:

```text
npm test -- --run src/ui.test.tsx src/theme.test.tsx
```

Output summary:

```text
Test Files  2 passed (2)
Tests       11 passed (11)
```

Command:

```text
npm run build
```

Output summary:

```text
✓ built in 85ms
```

Command:

```text
git diff --check
```

Output: passed (no output).
