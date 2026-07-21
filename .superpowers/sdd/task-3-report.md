# Phase 4E Task 3 Report

Implemented per-host RBAC enforcement for proxy host CRUD.

- Added `repository::list_hosts_for_user`, returning only hosts covered by a user's global or exact `proxy_host` `proxy_hosts.read` grant.
- Proxy-host list supports scoped-only users while preserving global-role behavior.
- Detail, update, and delete handlers authorize with `ResourceContext::ProxyHost(id)`; inaccessible hosts return `404` before loading details, preventing existence leakage. Read-only users retain `403` for write operations.
- Scoped-only users cannot create hosts because creation requires the global write grant.
- Host deletion removes role scope assignments after successful reload. Reload failure restores the host using its original ID and leaves scope assignments intact.
- Added repository regression test for filtered scoped host listing.

Verification:

- `git diff --check`: passed.
- `cargo test --locked --test control_plane_repository scoped_user_lists_only_assigned_proxy_hosts` could not complete in the available Docker environment: the repository toolchain pins Rust 1.84.1, which cannot parse the dependency's Edition 2024 manifest; retrying with stable Rust 1.97.1 then failed because the image lacks `cmake` while compiling `libz-ng-sys`.
- Native `cargo` is unavailable in the host environment.

## Review-fix report

- Mutation authorization now checks only the scoped `proxy_hosts.write` grant, so write-only users can update/delete assigned hosts; denied detail/update/delete return safe `404` and emit `authorization_denied` with redacted resource metadata.
- Host deletion now removes the host and per-host role assignments in one SQLite transaction before reloading. Reload failure restores the host, scope rows, and active configuration.
- Added regression coverage for write-only host authorization.

Verification:

- `git diff --check` passed.
- Native `cargo`/Docker toolchain unavailable in this environment; Rust tests could not be executed here.

## Second review-fix wave

- Preserved `403` for users who have host read access but lack write access; users with neither grant still receive safe `404`.
- Scope-row lookup now fails closed on database errors.
- Reload rollback now checks host, scope, and reloader restoration results and records `rollback_failed` when any restoration step fails.

Verification: `git diff --check` passed. Native Cargo unavailable, so route integration tests could not be executed in this environment.
