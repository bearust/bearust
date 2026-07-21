#!/usr/bin/env bash
set -euo pipefail

if rg -n '\b(users-card|user-form)\b' frontend/src/App.tsx frontend/src/styles.css frontend/src/*.test.tsx; then
  echo "legacy page-specific class hooks found" >&2
  exit 1
fi

echo "legacy class guard: passed"
