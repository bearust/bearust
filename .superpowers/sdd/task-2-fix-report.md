# Phase 10C Task 2 review-fix report

## Status

Completed the authenticated command-forwarding fixes, including the final
durable-receipt race, bounded-snapshot, and actor-authorization findings.

## Source changes

- `ConfigCommandGateway` resolves duplicate command receipts from the
  `raft_command_receipts` state-machine ledger rather than purgeable Raft log
  rows. A recreated gateway therefore returns the first applied leader ID and
  commit index without appending another command.
- After `client_write`, the gateway inspects `CommandResult` and reloads the
  authoritative receipt row. If a timed-out earlier proposal becomes visible
  between the retry's pre-check and apply, the retry's `Duplicate` result
  returns the earlier leader/index. A duplicate without durable provenance
  fails closed and is never synthesized or cached at the retry log position.
- The state machine likewise never backfills missing provenance from a later
  duplicate. Legacy command-ID-only rows remain receipt-less because the
  original leader/index is unknowable; the gateway returns a safe error.
- Migration `0012_raft_command_receipts.sql` creates the command-keyed receipt
  ledger and backfills the earliest recoverable committed receipt for existing
  applied commands whose log provenance is still present.
- State-machine apply records a real configuration command's ID, first log
  index, leader ID, and replicated mutation in one transaction. A duplicate
  apply, including one under a later leader, retains the original receipt.
- Raft snapshots carry a deterministic newest receipt window. At most 1,024
  receipts are selected by descending `(log_index, command_id)`, then the
  oldest selected receipts are omitted as needed to keep the complete
  serialized snapshot at or below both the 256 KiB repository payload limit
  and `MAX_RPC_FRAME_BYTES`. Building rejects replicated configuration that is
  already oversized before provenance is added.
- Snapshot construction does not prune `raft_command_receipts`; the source
  database ledger remains durable. Snapshot installation atomically restores
  the retained receipt and command-ID window. Commands older than that explicit
  1,024-entry/byte-budget snapshot window cannot retain retry provenance on a
  node recovered solely from that snapshot.
- OpenRaft snapshot transfer uses 48 KiB chunks so worst-case JSON byte-array
  expansion plus InstallSnapshot metadata stays within the authenticated RPC
  frame limit. One centralized configuration helper applies that bound to all
  three Raft constructors.
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
- Added a late-visibility regression that first observes no receipt, makes an
  earlier leader/index durable, then resolves a later duplicate response to
  the original receipt.
- Added an ID-only legacy regression proving a later duplicate neither creates
  a receipt nor returns the replay's leader/index.
- Added a 4,000-receipt regression proving that snapshot payloads remain within
  repository/RPC limits, the source ledger remains intact, the newest receipt
  survives installation, and receipts outside the retained window are omitted.
- Added worst-case snapshot-chunk encoding coverage against the authenticated
  RPC frame limit and constructor coverage for the centralized chunk setting.

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

Before the final hardening, the late-visibility regression did not compile
because there was no post-write receipt resolver; the production path ignored
`response.data`. The many-receipt regression then failed at snapshot build:

```text
called `Result::unwrap()` on an `Err` value:
raft snapshot exceeds configured limit
```

The final review's ID-only regression also reproduced provenance fabrication:

```text
a later duplicate cannot prove the original receipt provenance
```

## Verification

Exact requested focused suites:

```text
cargo +stable test --lib cluster_ -- --test-threads=1
cargo +stable test --test cluster_command_gateway --test cluster_raft_storage --test cluster_raft --test cluster -- --test-threads=1

cluster command/runtime unit tests: 4 passed; 0 failed
cluster: 8 passed; 0 failed
cluster_command_gateway: 13 passed; 0 failed
cluster_raft: 6 passed; 0 failed
cluster_raft_storage: 4 passed; 0 failed
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
