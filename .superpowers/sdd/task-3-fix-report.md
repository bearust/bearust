# Phase 10C Task 3 Review-Fix Report

## Status

All Task 3 review findings through base `9578e597` are fixed.

## Final review corrections

- The gateway now owns the standalone-versus-Raft decision behind one
  submission mutex. It rechecks explicit membership immediately before and
  after the standalone transaction, and a standalone command with a known
  durable result can be retried under the same command ID and promoted through
  Raft after membership activates.
- Scheduled system-actor auto-enforcement uses a leader-only gateway path.
  Once the scheduling node is deposed it returns `LeaderUnknown`; it never
  forwards the stale policy decision to another leader.
- A forwarded command receipt is retained when the receiving follower cannot
  observe local application before the deadline. The distinct
  `LocalApplyPending { receipt }` outcome lets handlers publish and audit the
  committed mutation, record activation as pending, and return
  `202 local_apply_pending` without mislabeling the commit as failed.
- Replicated proxy-host create/update/delete application now returns typed,
  deterministic `DuplicateDomain`, `IdCollision`, and `NotFound` command
  results. These expected conflicts are recorded with the command ID and
  immutable receipt instead of escaping as storage errors and poisoning Raft.
  Migration `0013_raft_command_results.sql` makes the result ledger durable and
  snapshot transfer preserves it.
- A real three-node regression proposes concurrent same-domain creates from
  separate followers, observes exactly one typed conflict, then commits
  another command to prove the cluster remains writable.

## Corrections

- Adaptive auto-enforcement now submits a typed
  `ConfigCommand::UpdateRuntimePolicy` through `ConfigCommandGateway` with a
  constrained system actor.
- Clustered auto-enforcement is fenced to the confirmed local Raft leader.
  Followers do not write host runtime policy. Standalone deployments retain
  local enforcement, including auth-token-only startup with no explicit Raft
  membership.
- Local configuration-command fallback now requires
  `cluster.is_single_node()`. A multi-node `AppState` without a gateway returns
  `503 cluster_unavailable` and performs no local mutation.
- Explicit or persisted single-node Raft membership still uses the gateway and
  emits a committed receipt. The recommendation retains its pre-change policy
  metadata, preserving the existing rollback path.
- Proxy-host mutations are audited as actor-attributed committed operations
  immediately after receipt. A subsequent runtime reload failure records a
  separate `proxy_host_activation_failed` event with the operation and stable
  `reload_failed` reason.
- The public realtime payload remains unchanged; committed runtime-policy and
  proxy-host invalidations are emitted only after a receipt exists.

## Regression evidence

The new control-plane cluster regressions initially failed as expected:

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

Coverage now also proves that a follower adaptive tick does not auto-enforce
and that the system actor cannot submit proxy-host commands.

## Verification

Final review gate:

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

Earlier review gate:

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

The final formatting and diff checks also passed:

```text
cargo +stable fmt --all -- --check
git diff --check
```

## Scope

Task 3 source, tests, and reports only. The pre-existing
`.superpowers/sdd/progress.md` modification is excluded from the commit. No bot
files were changed.
