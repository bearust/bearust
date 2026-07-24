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

Follow-up commit `4eecfe1` wires that watch into the CLI lifecycle and joins it
by cancellation during shutdown. The current network adapter deliberately
returns `Unreachable` for Raft RPCs, so a leader-stop/re-election assertion is
not claimed until transport replication is enabled; the fixture covers
deterministic election and clean shutdown without fabricating failover.
