# Contributing to BeaRust

Thanks for helping improve BeaRust. Bug reports, translations, documentation, and code contributions are all welcome.

## Ways to contribute

- **Report bugs** with reproduction steps, expected vs. actual behavior, and versions (see the bug report template).
- **Translate** the dashboard — supported locales are `en` (source), `id`, and `ja`. Follow [docs/localization.md](docs/localization.md).
- **Improve docs** — the entry points are [README.md](README.md), [DEVELOPMENT.md](DEVELOPMENT.md), and [DEPLOY.md](DEPLOY.md).
- **Write code** — for larger changes, please open an issue first so the design can be agreed before you invest time.

## Setup

The fastest path needs only Docker:

```sh
docker compose -f docker-compose.dev.yml up --build
```

This starts the Rust backend with cargo-watch and the frontend with hot reload at `http://localhost:5183` (dev setup token: `bearust-dev-setup`). For native development you need Rust 1.97.1 (pinned in `rust-toolchain.toml`) and Node 22. Details: [DEVELOPMENT.md](DEVELOPMENT.md).

## Workflow

1. Fork the repository and create a branch from `main`.
2. Follow the existing code style (`feat: …` / `fix: …` commit subjects, focused commits).
3. Add or update tests with every behavior change (Rust: `tests/`; frontend: co-located `*.test.tsx`).
4. Run the verification gates below before pushing.
5. Open a pull request against `main` with a clear description and test evidence.

## Verification gates

Run the same checks CI runs, from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
npm run validate-locales --prefix frontend
npm test --prefix frontend -- --run
npm run build --prefix frontend
git diff --check
```

Locale changes additionally require `npm run validate-locales --prefix frontend` to pass (included above). Browser-visual changes should also run the Playwright suite (`npm run test:e2e` in `frontend/`) after `npx playwright install chromium`.

## Pull request checklist

- [ ] Focused scope with a clear description (what changed and why)
- [ ] Tests added or updated; new tests fail without the fix
- [ ] All gates above pass
- [ ] Docs updated if behavior, config, or API changed (including new migrations, if any)
- [ ] No secrets, credentials, or generated artifacts committed

## Security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md) for private reporting.
