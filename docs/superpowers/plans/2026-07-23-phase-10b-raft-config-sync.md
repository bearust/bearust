# Phase 10B Raft Configuration Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add durable leader-based Raft coordination and safe configuration command replication while preserving single-node behavior.

**Architecture:** Extend `src/cluster.rs` with an OpenRaft node, RPC transport, database-backed log/snapshot storage, and a typed command state machine. Route the selected control-plane mutations through a leader-only dispatcher; expose redacted role/term/commit status through the existing authenticated cluster endpoint.

**Tech Stack:** Rust, OpenRaft, Tokio, Axum, SQLx, Serde/TOML, existing Phase 10A TCP transport and RBAC.

## Global Constraints

- Empty `CLUSTER_PEERS` remains single-node mode; the local node is the effective leader.
- Proxy request handling never waits on Raft or database replication.
- Only committed commands mutate replicated configuration state.
- Log entries, snapshots, audit details, and errors exclude secrets, credentials, private keys, request bodies, and raw database errors.
- All proposal payloads and snapshots are bounded; duplicate command IDs are idempotent.
- Keepalived, cross-node SSE replay, analytics aggregation, and process-local metrics replication are out of scope.

### Task 1: Add Raft dependency and persistent schema

**Files:**
- Modify: `Cargo.toml`
- Modify: `migrations/` with the next additive migration
- Modify: `src/control_plane/repository.rs`
- Test: `tests/control_plane_repository.rs`

- [ ] Add the pinned OpenRaft dependency and feature flags compatible with the current Tokio/Serde versions.
- [ ] Add tables for Raft hard state, bounded log entries, snapshots, and idempotency keys; include indexes for `(term, index)` and command IDs.
- [ ] Make migration additive and idempotent for SQLite, PostgreSQL, and MySQL paths already supported by the repository layer.
- [ ] Add migration tests for fresh databases, repeated migration, and legacy database preservation.
- [ ] Run `cargo +stable test --test control_plane_repository`.
- [ ] Commit as `feat: add persistent raft storage schema`.

### Task 2: Implement typed Raft command envelope and state machine

**Files:**
- Create: `src/cluster_raft.rs`
- Modify: `src/cluster.rs`
- Modify: `src/lib.rs`
- Test: `tests/cluster_raft.rs`

- [ ] Define `ConfigCommand` variants for proxy-host create/update/delete and host runtime-policy updates, each carrying a UUID command ID and bounded payload.
- [ ] Reject oversized serialized commands before proposal and redact command/debug output.
- [ ] Implement OpenRaft `RaftTypeConfig`, database log/state-machine adapters, atomic apply transactions, snapshot creation, and snapshot install.
- [ ] Record applied command IDs so replaying a committed command is a no-op.
- [ ] Add tests for apply ordering, duplicate idempotency, snapshot round-trip, malformed payload rejection, and secret redaction.
- [ ] Run `cargo +stable test --test cluster_raft` and Clippy on affected targets.
- [ ] Commit as `feat: add raft command state machine`.

### Task 3: Add node lifecycle, RPC, and status

**Files:**
- Modify: `src/cluster.rs`
- Modify: `src/cli.rs`
- Modify: `src/control_plane/mod.rs`
- Test: `tests/cluster.rs`
- Test: `tests/control_plane_cluster.rs`

- [ ] Add OpenRaft node startup, bootstrap/join behavior, bounded election/heartbeat timers, and graceful shutdown using the existing cluster listener lifecycle.
- [ ] Extend the Phase 10A handshake into authenticated Raft RPC framing without exposing peer addresses or credentials in status payloads.
- [ ] Expose role, leader ID, term, last-log-index, commit-index, quorum availability, and sync state through `GET /api/cluster/status`.
- [ ] Add three-node election, follower restart, malformed RPC, timeout, and quorum-loss tests.
- [ ] Run focused cluster tests and the complete Rust test suite.
- [ ] Commit as `feat: add raft node lifecycle and cluster status`.

### Task 4: Route selected control-plane writes through the leader

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/cluster_raft.rs`
- Test: `tests/control_plane_cluster.rs`
- Test: `tests/control_plane_users.rs` only where host-policy behavior is shared

- [ ] Add a leader gate before selected proxy-host and runtime-policy mutations.
- [ ] On followers, return stable `409` JSON with `code = "leader_required"` and a redacted leader ID; never perform a local write.
- [ ] On leaders, authorize and validate the request, propose the command, wait for quorum commit, then return the committed resource.
- [ ] Return stable `503 quorum_unavailable` when the command cannot commit; ordinary proxy requests continue.
- [ ] Test leader success, follower rejection, duplicate retry, quorum loss, and rollback on apply failure.
- [ ] Commit as `feat: route config writes through raft leader`.

### Task 5: Recovery, compaction, and operational documentation

**Files:**
- Modify: `src/cluster_raft.rs`
- Modify: `src/cli.rs`
- Modify: `README.md`
- Modify: `docs/PRD.md`
- Create: `docs/superpowers/reviews/phase-10b-final-review.md`

- [ ] Compact logs after a bounded snapshot threshold and verify follower catch-up from snapshot after restart.
- [ ] Ensure shutdown waits for Raft task termination within the configured graceful-shutdown bound.
- [ ] Document leader/follower behavior, quorum requirements, join procedure, firewall boundaries, backup implications, and deferred Phase 10C scope.
- [ ] Record verification evidence and known operational limits in the final review.
- [ ] Run `cargo +stable fmt --check`, `cargo +stable test --all-targets`, `cargo +stable clippy --all-targets -- -D warnings`, and `git diff --check`.
- [ ] Commit as `docs: complete phase 10b raft synchronization`.
