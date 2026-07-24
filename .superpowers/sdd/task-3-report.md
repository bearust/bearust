# Phase 10C Task 3 Report

## Status

Completed the proxy-host and host runtime-policy command-gateway integration
from base commit `d28b8c2`, including final review corrections through
`8052ee9` and the final topology-state correction after `bb1dbe3`.

## Review corrections

- The topology-transition `RwLock` now carries the authoritative
  membership-initialized flag instead of only serializing access. Successful
  `initialize_membership` calls set the flag while still holding the write
  guard, so an immediately waiting standalone fallback cannot mistake
  eventually updated OpenRaft metrics for an uninitialized topology.
- The reverse-order regression initializes membership first and submits
  immediately afterward. On `bb1dbe3` it deterministically returned the
  forbidden standalone receipt `(leader_id=0, commit_index=0)`; the corrected
  gateway now requires the Raft path or returns a cluster error. The existing
  forward-order overlap regression and auth-token-only local behavior remain
  covered.
- `ClusterService` now provides the synchronization boundary between
  standalone submission and membership activation. The fallback path holds a
  shared topology guard from its membership decision through direct apply;
  the public membership initialization helper takes the exclusive guard
  before OpenRaft activation.
- `bootstrap_single_node` now requires the associated `ClusterService`, and
  multi-node fixtures use the same public `initialize_membership` helper.
  This prevents lifecycle callers from bypassing the topology boundary.
- A deterministic overlap regression stalls the standalone gateway database
  path independently of Raft storage. It proves initialization stays pending
  until the local mutation returns its standalone receipt; removing the
  exclusive guard makes the regression fail on premature activation.
- The standalone compatibility path moved inside `ConfigCommandGateway` and
  uses the serialized submission and shared topology guards. Known standalone
  command outcomes are durable, so retrying the same command ID after
  membership activates commits it through Raft instead of silently diverging.
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

Final topology-race gate:

```text
cargo +stable test --test cluster_command_gateway \
  --test control_plane_cluster --test raft_three_node -- --test-threads=1

cluster_command_gateway: 21 passed; 0 failed
control_plane_cluster: 10 passed; 0 failed
raft_three_node: 2 passed; 0 failed
```

Before the state-carrying lock correction, the new reverse-order regression
failed as intended:

```text
completed membership initialization returned a standalone receipt
left: (0, 0)
right: (0, 0)
```

Topology-transition focused gate:

```text
cargo +stable test --test cluster_command_gateway \
  --test control_plane_cluster --test cluster --test cluster_raft \
  --test cluster_raft_runtime --test cluster_raft_storage \
  --test raft_three_node -- --test-threads=1

61 passed; 0 failed
```

The overlap regression failed as intended when the exclusive transition lock
was temporarily removed:

```text
membership activated while a standalone submission was in flight
```

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
