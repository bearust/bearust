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
