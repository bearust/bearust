# Phase 10C Task 2 review-fix report

## Status

Completed the authenticated command-forwarding fixes, including the final
durable-receipt and actor-authorization findings.

## Source changes

- `ConfigCommandGateway` resolves duplicate command receipts from the
  `raft_command_receipts` state-machine ledger rather than purgeable Raft log
  rows. A recreated gateway therefore returns the first applied leader ID and
  commit index without appending another command.
- Migration `0012_raft_command_receipts.sql` creates the command-keyed receipt
  ledger and backfills the earliest recoverable committed receipt for existing
  applied commands whose log provenance is still present.
- State-machine apply records a real configuration command's ID, first log
  index, leader ID, and replicated mutation in one transaction. A duplicate
  apply, including one under a later leader, retains the original receipt.
- Raft snapshots now carry command receipt provenance. Snapshot installation
  atomically replaces both the receipt ledger and the applied-command ID ledger
  alongside replicated configuration, so a snapshot-recovered node can return
  the original receipt after compaction or leadership change.
- Forwarded actor shape validation no longer hard-codes the `admin` role. It
  bounds the ID, email, and role metadata, then both the submitting node and
  receiving leader re-resolve the active persisted user, require exact
  ID/email/role consistency, reject disabled or mismatched users, and consult
  the authoritative `proxy_hosts.write` grant at global or host scope.
- The earlier Task 2 fixes remain in place: inbound handshakes accept only
  configured peers, and the complete post-handshake operation uses the
  configured cluster timeout.

## Test updates

- Three-node gateway fixtures use an authorized persisted operator, proving
  that non-admin writers can submit and forward commands.
- Added denial coverage for a permissionless viewer, a disabled operator, and
  actor/persisted ID, email, or role mismatch.
- Added a regression that commits a command, purges its leader log row,
  recreates the gateway, retries the same command ID, and receives the original
  receipt.
- Added state-machine/snapshot coverage that applies a duplicate command under
  a later leader, installs the snapshot on another node, and verifies that the
  original leader ID, log index, and applied-command identity survive.

## Red evidence

Before the final fixes:

```text
forwarded_command_accepts_structurally_valid_viewer_for_authoritative_authorization
called `Result::unwrap()` on an `Err` value: ForwardAuthentication

follower_gateway_forwards_without_locally_committing
called `Result::unwrap()` on an `Err` value: ForwardAuthentication
```

The structural gate rejected both viewer metadata that should reach
authoritative authorization and an operator with the built-in
`proxy_hosts.write` grant.

After log purge and gateway recreation, the receipt regression reproduced the
provenance loss:

```text
assertion `left == right` failed
left:  CommitReceipt { leader_id: 1, commit_index: 3, ... }
right: CommitReceipt { leader_id: 1, commit_index: 2, ... }
```

Before receipt provenance was added to the snapshot envelope:

```text
snapshot_install_preserves_applied_command_provenance ... FAILED
snapshot install must preserve applied command identity
```

## Verification

Exact requested focused suite:

```text
cargo +stable test --test cluster_command_gateway --test cluster_raft_storage --test cluster -- --test-threads=1

cluster: 8 passed; 0 failed
cluster_command_gateway: 13 passed; 0 failed
cluster_raft_storage: 3 passed; 0 failed
```

Formatting and lint:

```text
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
```

Both commands completed successfully; Clippy finished with warnings denied.
`git diff --check` also completed without whitespace errors.

## Scope

The final Task 2 fix is limited to the receipt migration, Raft
repository/state-machine/snapshot path, command gateway authorization and
receipt lookup, focused tests, and this report. `.superpowers/sdd/progress.md`
remains modified in the shared worktree and is deliberately excluded.
