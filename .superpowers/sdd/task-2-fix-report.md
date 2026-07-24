# Phase 10C Task 2 review-fix report

## Status

Completed the requested command-forwarding and cluster-listener review fixes.

## Source changes

- `ConfigCommandGateway` now owns the node database pool. Before a write or
  forwarded write is accepted, it resolves the active persisted user, verifies
  the actor ID/email/role against that record, and checks the existing
  `proxy_hosts.write` RBAC grant at the command's global or host scope.
- Duplicate command retries now look up the first applied, committed Raft log
  record by local node ID and `command_id`. The gateway reconstructs the
  original leader ID and commit index from that durable record, so a recreated
  gateway or a new leader returns the original receipt instead of appending a
  duplicate entry.
- Inbound handshakes now accept only configured peer node IDs and explicitly
  reject the local node ID, even when the caller knows the cluster HMAC secret.
- The post-handshake RPC operation is bounded by the configured cluster timeout
  instead of a hard-coded 50 ms header window. The bound covers the complete
  frame read, dispatch, and response write while preserving status and Raft RPC
  routing.

## Test updates

- Existing three-node gateway fixtures now seed the persisted actor on every
  node and pass each node's database pool into the gateway.
- Added regression coverage for an unknown authenticated origin, an RPC frame
  delayed beyond 50 ms, and receipt recovery after gateway recreation.
- Updated listener/readiness callers to use node IDs present in the configured
  peer membership.

## Red evidence

Before the source fixes, the requested focused command reported three failures:

```text
cluster_listener_accepts_rpc_frame_delayed_beyond_fifty_milliseconds ... FAILED
cluster_listener_rejects_valid_hmac_from_unknown_node_id ... FAILED
repeated_command_after_gateway_restart_returns_the_original_receipt ... FAILED

test result: FAILED. 9 passed; 3 failed
```

The delayed connection closed with `UnexpectedEof`, the unknown identity
received a valid status response, and the gateway retry returned commit index 3
instead of the original commit index 2.

## Verification

```text
cargo +stable test --test cluster_command_gateway --test cluster -- --test-threads=1
```

Result:

```text
cluster: 8 passed; 0 failed
cluster_command_gateway: 12 passed; 0 failed
```

```text
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

All three commands completed successfully. Clippy finished the all-target check
with warnings denied.

## Scope

The Task 2 commit includes only the gateway, cluster listener, Raft repository
lookup, focused cluster tests, and this report.
`.superpowers/sdd/progress.md` remains modified in the shared worktree and is
deliberately excluded.
