# Task 5 report: external database Compose profiles

Status: complete

Implemented opt-in `postgres` and `mysql` Compose profiles in both production
and development Compose files. Each profile includes environment-driven
credentials, a persistent named volume, and a health check. The Bearust service
keeps SQLite as the default and conditionally waits for either database health
check when that profile is enabled.

Updated `.env.example`, `DEPLOY.md`, and `README.md` with profile URLs, startup
migration behavior, volume/upgrade guidance, backend-switch export/import
limitations, and password-redaction guidance.

Verification:

- `docker compose config --quiet` passed.
- `docker compose --profile postgres config --quiet` passed.
- `docker compose --profile mysql config --quiet` passed.
- `git diff --check` passed.

Concern: runtime database URL wiring depends on the Phase 5 application
configuration work; this task only supplies the Compose environment and
deployment documentation.
