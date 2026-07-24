# Phase 10C Task 1 Report

## Status

Completed and committed the typed replicated configuration command gateway.

Commit: `9df09204e93ad05533b79dd189b2e39464f18365`

## Changed scope

- `src/cluster_command.rs`: added `CommandActor`, `CommitReceipt`, stable `ClusterWriteError`, and leader/quorum-gated `ConfigCommandGateway::submit`.
- `src/lib.rs`: registered `cluster_command`.
- `src/cluster.rs`: added `ClusterService::raft_write_state()`.
- `tests/cluster_command_gateway.rs`: role/quorum/single-node gateway tests.

The gateway validates non-internal configuration commands, checks local Raft role and quorum before calling `Raft::client_write`, and maps OpenRaft write errors into `ClusterWriteError`. It does not call repository mutation helpers.

## Commands and output

### Required red check

Command:

```text
cargo +stable test --test cluster_command_gateway follower_gateway_does_not_mutate_local_database
```

Output (exit 101):

```text
error[E0432]: unresolved import `bearust::cluster_command`
 --> tests/cluster_command_gateway.rs:2:14
  |
2 | use bearust::cluster_command::{
  |              ^^^^^^^^^^^^^^^ could not find `cluster_command` in `bearust`

error: could not compile `bearust` (test "cluster_command_gateway") due to 1 previous error
```

### Focused tests after implementation

Command:

```text
cargo +stable test --test cluster_command_gateway
```

Output (exit 0):

```text
running 4 tests
test gateway_rejects_writes_when_quorum_is_unavailable ... ok
test follower_gateway_does_not_mutate_local_database ... ok
test leader_gateway_submits_only_after_quorum_is_available ... ok
test single_node_gateway_keeps_local_command_submission ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

### Formatting and linting

Command:

```text
cargo +stable fmt --all -- --check
```

Initial output found rustfmt changes required in the new gateway and test. I ran the prescribed formatter, then verified with:

```text
cargo +stable fmt --all && cargo +stable fmt --all -- --check && cargo +stable clippy --all-targets -- -D warnings
```

Output (exit 0):

```text
Checking bearust v0.1.0 (/home/rizalord/Projects/personal/bearust)
Finished `dev` profile [unoptimized + debuginfo] target(s) in 7.05s
```

### Diff and commit checks

Command:

```text
git diff --check
```

Output: exit 0 (no whitespace errors).

Command:

```text
git add src/cluster_command.rs src/lib.rs src/cluster.rs tests/cluster_command_gateway.rs
git commit -m "feat: add replicated configuration command gateway"
git rev-parse HEAD
git status --short
```

Output (exit 0):

```text
[main 9df0920] feat: add replicated configuration command gateway
 4 files changed, 256 insertions(+)
 create mode 100644 src/cluster_command.rs
 create mode 100644 tests/cluster_command_gateway.rs
9df09204e93ad05533b79dd189b2e39464f18365
 M .superpowers/sdd/progress.md
```

## Concerns

- Authenticated follower-to-leader command forwarding is intentionally not implemented in this task; followers reject locally and Task 2 owns the transport boundary.
- The existing `.superpowers/sdd/progress.md` modification was present before this task and was deliberately not staged or committed.

## Review-fix evidence

The review hardening replaces caller-controlled `ClusterService::raft_write_state()` decisions with OpenRaft's live metrics. Multi-node writes now require local leader state, a self-matching current leader, and a quorum acknowledgement no older than one second. A bounded two-second `client_write` timeout prevents a lost quorum from leaving a command pending indefinitely. Single-node compatibility requires both single-node application configuration and a one-voter Raft membership.

The gateway tests now construct a real authenticated three-node transport, elect a live leader, verify follower rejection without local application, commit through an actual quorum, stop both followers and verify rejection after quorum loss, and retain the real single-node write path. During finalization, the focused suite exposed polling loops that held an OpenRaft `watch::Ref` across `await`, deadlocking metrics publication on Tokio's single-thread test runtime. Releasing each metrics guard before sleeping fixed the hang. Quorum-loss cleanup was also made tolerant of an already-closed listener receiver.

### Focused review tests

Command:

```text
cargo +stable test --test cluster_command_gateway -- --test-threads=1
```

Output (exit 0):

```text
running 4 tests
test follower_gateway_does_not_mutate_local_database ... ok
test gateway_rejects_writes_after_actual_quorum_loss ... ok
test leader_gateway_commits_through_actual_three_node_quorum ... ok
test single_node_gateway_keeps_local_command_submission ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.56s
```

### Final formatting and linting

Command:

```text
cargo +stable fmt --all -- --check
```

Output: exit 0 (no formatting changes required).

Command:

```text
cargo +stable clippy --all-targets -- -D warnings
```

Output (exit 0):

```text
Checking bearust v0.1.0 (/home/rizalord/Projects/personal/bearust)
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.35s
```
