# Task 5 report — failover, quorum, catch-up, and idempotent retries

Implemented deterministic Phase 10C readiness/failover coverage:

- Added `raft_status_from_metrics` and `ClusterService::update_raft_status_from_metrics`, mapping OpenRaft leader/follower/candidate/shutdown state, leader identity, commit/log indexes, and quorum readiness into the API status model.
- Added `tests/cluster_failover.rs` with ephemeral-port three-node election and graceful listener/Raft shutdown coverage, plus unknown-quorum readiness coverage.
- Updated `tests/raft_three_node.rs` to reserve ephemeral ports instead of fixed ports.

Verification:

```text
cargo +stable test --test cluster_failover -- --nocapture  # 2 passed
cargo +stable test --test cluster_failover --test raft_three_node --test cluster -- --test-threads=1  # 12 passed
cargo +stable clippy --all-targets -- -D warnings  # passed
```

The status mapping is intentionally exposed as an explicit update method because
`ClusterService` does not own the OpenRaft handle; the runtime lifecycle should
call it whenever the Raft metrics watch changes.

Commit `8efc1f6` wires that watch into the CLI lifecycle and joins it by
cancellation during shutdown. The current `AuthenticatedRaftNetwork` adapter
deliberately returns `Unreachable` for Raft RPCs. Therefore transport failover
scenarios (leader stop followed by a replicated re-election, catch-up, or
write continuity) are explicitly deferred until transport replication is
enabled; this task only claims deterministic election, quorum/readiness
mapping, and clean listener/Raft shutdown without fabricating failover.
