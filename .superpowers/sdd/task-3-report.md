# Phase 10C Task 3 Report

## Status

Completed the proxy-host and host runtime-policy command-gateway integration
from base commit `d28b8c2`.

## Changed scope

- `src/control_plane/mod.rs`
  - Injects an optional `ConfigCommandGateway` into `AppState`.
  - Keeps session authentication, RBAC, host-scope checks, request validation,
    command actor construction, and audit attribution in the API handlers.
  - Routes proxy-host create/update/delete and adaptive recommendation
    apply/rollback through typed `ConfigCommand` submission.
  - Maps stable cluster failures to redacted HTTP error envelopes.
  - Uses the typed state-machine command path for unclustered single-node
    operation, preserving existing API behavior without a Raft dependency.
- `src/cli.rs`
  - Installs the configured Raft gateway in production control-plane state and
    registers the same gateway as the authenticated internal command handler.
- `src/cluster_command.rs`
  - Maps committed command variants to the existing public invalidation kinds.
  - Waits for a forwarded command to apply to the receiving follower before
    returning its receipt, so local reads/reloads cannot race the response.
  - Revalidates runtime-policy actors against the existing
    `system.settings.manage` permission while retaining proxy-host scope checks
    for host mutations.
- `src/control_plane/repository.rs`
  - Allocates explicit proxy-host IDs before command construction.
  - Cleans host-scoped RBAC assignments and host runtime policy in the same
    committed delete transaction.
  - Separates local adaptive-recommendation metadata finalization from the
    replicated runtime-policy mutation.
- `src/control_plane/realtime.rs`
  - Adds an internal committed-event stream carrying command ID, leader ID, and
    commit index.
  - Leaves the public `RealtimeEvent`/SSE payload unchanged.
- Focused tests build a real authenticated three-node Raft cluster and prove
  follower proxy-host POST/PATCH/DELETE forwarding, local follower reads,
  runtime-policy apply/rollback forwarding, all-node application, committed
  event metadata, and unchanged public event shape.

The global `/api/rate-limit/config` document is intentionally unchanged. The
existing replicated command is host-scoped and represents
`host_rate_limit_configs`; adaptive recommendation apply/rollback are the API
mutations that write that replicated runtime policy.

## Red evidence

Before implementation:

```text
error[E0432]: unresolved import `bearust::cluster_command::committed_event_kind`
error[E0599]: no method named `with_config_gateway` found for struct `AppState`
```

This was the expected failure because handlers had no gateway injection or
committed-event mapping.

## Verification

Required focused suites:

```text
cargo +stable test --test control_plane_cluster --test cluster_command_gateway -- --test-threads=1

cluster_command_gateway: 14 passed; 0 failed
control_plane_cluster: 4 passed; 0 failed
```

Compatibility suites:

```text
cargo +stable test --test control_plane_users --test adaptive_tuning_api \
  --test control_plane_realtime --test control_plane_rate_limit \
  -- --test-threads=1

adaptive_tuning_api: 4 passed; 0 failed
control_plane_rate_limit: 1 passed; 0 failed
control_plane_realtime: 7 passed; 0 failed
control_plane_users: 10 passed; 0 failed
```

Formatting, lint, and diff validation:

```text
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

All completed successfully.

## Scope notes

- No bot-protection or unrelated rate-limit implementation files were changed.
- `.superpowers/sdd/progress.md` was modified before this task and remains
  deliberately unstaged.
- A proxy runtime reload failure can no longer roll back a quorum-committed
  command locally. The API returns an explicit “committed but not activated”
  error and still publishes the committed invalidation so recovery/reload logic
  can converge without creating divergent database state.
