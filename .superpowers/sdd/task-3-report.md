# Phase 10C Task 3 Report

## Status

Completed the proxy-host and host runtime-policy command-gateway integration
from base commit `d28b8c2`, including final review corrections through
`9578e597`.

## Review corrections

- The standalone compatibility path moved inside `ConfigCommandGateway` and
  uses a serialized topology decision with membership checks immediately
  before and after direct application. Known standalone command outcomes are
  durable, so retrying the same command ID after membership activates commits
  it through Raft instead of silently diverging.
- Scheduled auto-enforcement calls the leader-only gateway entry point. A
  deposed leader refuses the command and does not use follower forwarding.
- Forwarded receipts survive a local apply-wait timeout as
  `LocalApplyPending { receipt }`. Proxy-host and recommendation handlers audit
  the committed mutation plus an activation-pending event, publish the
  committed invalidation, and return `202 local_apply_pending`.
- Proxy-host create/update/delete conflicts are deterministic replicated
  results (`DuplicateDomain`, `IdCollision`, and `NotFound`) rather than
  `StorageError`. The durable command-result ledger and snapshot path preserve
  retry semantics across restart and compaction.
- New regressions cover standalone-to-membership promotion, deposed scheduled
  actors, committed/local-pending audit semantics, all business-conflict
  variants, and concurrent stale-follower domain conflict without Raft
  poisoning.

- Adaptive auto-enforcement now constructs a typed
  `ConfigCommand::UpdateRuntimePolicy` and submits it through
  `ConfigCommandGateway` with the constrained system actor. Clustered
  auto-enforcement runs only on the confirmed local leader; followers remain
  non-mutating. A committed receipt is published before recommendation
  metadata is finalized, and the previous policy remains persisted for the
  existing rollback path.
- Local state-machine fallback now requires `cluster.is_single_node()`.
  Multi-node state without a gateway returns the stable
  `cluster_unavailable` response and performs no local write.
- A standalone node configured with only a cluster auth token remains on the
  local path while Raft has no explicit voter membership. A bootstrapped or
  persisted single-node membership continues to use the gateway.
- Proxy-host create, update, and delete record the actor-attributed committed
  mutation immediately after receipt. Runtime reload failures are recorded
  separately as `proxy_host_activation_failed`, with a redacted operation and
  stable failure reason, without relabeling the durable mutation as failed.
- Added regressions for missing-gateway multi-node writes, auth-token-only
  standalone startup, bootstrapped auto-enforcement receipts, follower
  auto-enforcement fencing, constrained system actors, and commit/activation
  audit separation.

## Review red evidence

Before the corrections, the expanded control-plane cluster suite failed four
regressions:

```text
auth_token_only_single_node_without_membership_keeps_local_mutations:
  expected 201, received 503
bootstrapped_single_node_auto_enforcement_uses_gateway_receipt:
  committed gateway event timed out
committed_proxy_mutations_and_activation_failures_are_audited_separately:
  missing committed mutation audit proxy_host_created
multi_node_state_without_gateway_rejects_replication_required_mutation:
  expected 503, received 201
```

## Review verification

Final combined control-plane/cluster/Raft/storage gate:

```text
cargo +stable test --test control_plane_cluster \
  --test cluster_command_gateway --test cluster --test cluster_raft \
  --test cluster_raft_runtime --test cluster_raft_storage \
  --test raft_three_node --test control_plane_repository \
  --test adaptive_tuning --test adaptive_tuning_api -- --test-threads=1

86 passed; 0 failed
```

```text
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check

All exited 0.
```

Earlier review verification:

```text
cargo +stable test --test control_plane_cluster --test cluster_command_gateway \
  --test cluster --test cluster_raft --test cluster_raft_runtime \
  --test cluster_raft_storage --test raft_three_node \
  --test adaptive_tuning --test adaptive_tuning_api -- --test-threads=1

60 passed; 0 failed
```

```text
cargo +stable clippy --all-targets -- -D warnings
Finished successfully with no warnings.
```

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
