# Phase 10C HA Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route replicated configuration writes through the Raft leader, propagate post-commit invalidations across authenticated nodes, verify failover/quorum recovery, and document host-level keepalived/VIP operation.

**Architecture:** Add a typed `ConfigCommandGateway` between authenticated API handlers and OpenRaft. The gateway submits locally when leader and uses a bounded authenticated internal command RPC when follower; only committed state-machine application emits redacted events. A bounded cluster event channel distributes invalidations while Raft remains the source of truth. Keepalived remains host-level and consumes a readiness endpoint/script.

**Tech Stack:** Rust 2021, Tokio, Axum, SQLx, OpenRaft 0.9.21, serde/serde_json, HMAC-SHA256, existing `RealtimeHub`, SQLite test fixtures.

## Global Constraints

- Never write replicated configuration directly from a follower.
- Existing single-node mode (`cluster.peers = []`) remains behavior-compatible.
- Reuse `MAX_RPC_FRAME_BYTES`, the BEARUST1 handshake, and constant-time HMAC checks.
- Forwarded envelopes must exclude session cookies, passwords, private keys, provider credentials, request bodies, and raw SQL errors.
- All new queues, retries, payloads, peer fan-out, and timeouts are bounded.
- Read endpoints remain local and may expose the latest committed state known by that node.
- Run `cargo +stable fmt --all -- --check`, `cargo +stable clippy --all-targets -- -D warnings`, and focused tests after each task.

---

## File map

- Create: `src/cluster_command.rs` — typed command-gateway API, actor context, commit receipt, and stable cluster-write errors.
- Create: `src/cluster_events.rs` — authenticated post-commit invalidation envelope, bounded deduplication, and peer fan-out.
- Modify: `src/lib.rs` — register the two new modules.
- Modify: `src/cluster_raft_runtime.rs` — expose leader-aware command submission and internal command/event RPC handling.
- Modify: `src/cluster.rs` — expose leader/quorum readiness and route internal cluster frames.
- Modify: `src/control_plane/mod.rs` — inject gateway into `AppState` and route proxy-host/runtime-policy mutations through it.
- Modify: `src/control_plane/realtime.rs` — publish committed event metadata while retaining the existing SSE contract.
- Modify: `src/control_plane/repository.rs` — add read-only committed-state helpers required for gateway/readiness checks.
- Create: `tests/cluster_command_gateway.rs` — unit and three-node write-forwarding tests.
- Create: `tests/cluster_failover.rs` — leader loss, quorum loss, reconnect, and idempotent retry tests.
- Create: `docs/keepalived.md` — tested VIP readiness and fencing procedure.
- Modify: `docs/PRD.md` and `README.md` — Phase 10B/10C status and operations documentation.

## Interfaces shared by later tasks

```rust
pub struct CommandActor {
    pub user_id: i64,
    pub email: String,
    pub role: String,
}

pub struct CommitReceipt {
    pub command_id: uuid::Uuid,
    pub leader_id: u64,
    pub commit_index: u64,
}

pub enum ClusterWriteError {
    LeaderUnknown,
    QuorumUnavailable,
    ForwardTimeout,
    ForwardAuthentication,
    InvalidCommand,
    NotReplicatedCommand,
}

pub struct ConfigCommandGateway {
    pub raft: std::sync::Arc<openraft::Raft<crate::cluster_raft::BearustRaftConfig>>,
    pub cluster: std::sync::Arc<crate::cluster::ClusterService>,
    pub realtime: std::sync::Arc<crate::control_plane::realtime::RealtimeHub>,
}

impl ConfigCommandGateway {
    pub async fn submit(
        &self,
        command: crate::cluster_raft::ConfigCommand,
        actor: CommandActor,
    ) -> Result<CommitReceipt, ClusterWriteError>;
}
```

### Task 1: Add the typed command gateway boundary

**Files:**
- Create: `src/cluster_command.rs`
- Modify: `src/lib.rs`
- Modify: `src/cluster.rs`
- Test: `tests/cluster_command_gateway.rs`

**Interfaces:**
- Consumes: `ConfigCommand`, `RaftStatus`, `OpenRaftRpcHandler`, existing cluster auth token.
- Produces: `ConfigCommandGateway::submit`, `ClusterWriteError`, `CommitReceipt`, and `ClusterService::raft_write_state()`.

- [ ] **Step 1: Write failing gateway tests** for leader submission, leader-unknown rejection, quorum-unavailable rejection, and single-node compatibility.

```rust
#[tokio::test]
async fn follower_gateway_does_not_mutate_local_database() {
    let gateway = test_gateway_with_role(RaftRole::Follower, None).await;
    let result = gateway.submit(test_create_command(), test_actor()).await;
    assert!(matches!(result, Err(ClusterWriteError::LeaderUnknown)));
}
```

- [ ] **Step 2: Run the focused test and verify failure.**

Run: `cargo +stable test --test cluster_command_gateway follower_gateway_does_not_mutate_local_database`

Expected: FAIL because the gateway module and write-state accessor do not exist.

- [ ] **Step 3: Implement the gateway with explicit role/quorum checks.**

Use `Raft::client_write` only after confirming leader state; map OpenRaft errors into the stable enum and never call repository mutation helpers directly. In single-node mode, preserve the existing local command path.

- [ ] **Step 4: Run focused tests and verify pass.**

Run: `cargo +stable test --test cluster_command_gateway`

Expected: all gateway role/error tests pass.

- [ ] **Step 5: Commit.**

```bash
git add src/cluster_command.rs src/lib.rs src/cluster.rs tests/cluster_command_gateway.rs
git commit -m "feat: add replicated configuration command gateway"
```

### Task 2: Add authenticated internal command forwarding

**Files:**
- Modify: `src/cluster_raft_runtime.rs`
- Modify: `src/cluster.rs`
- Modify: `src/cluster_command.rs`
- Test: `tests/cluster_command_gateway.rs`

**Interfaces:**
- Consumes: `ConfigCommandGateway`, existing handshake/RPC transport.
- Produces: bounded `config_command` request/response envelopes and forwarding error mappings.

- [ ] **Step 1: Write failing transport tests** for authenticated command forwarding, tampered envelopes, oversized commands, actor metadata mismatch, and duplicate `command_id`.

```rust
#[tokio::test]
async fn forwarded_command_rejects_tampered_actor_envelope() {
    let response = dispatch_internal_command(tampered_frame()).await;
    assert_eq!(response, Err(ClusterWriteError::ForwardAuthentication));
}
```

- [ ] **Step 2: Run the focused tests and verify failure.**

Run: `cargo +stable test --test cluster_command_gateway forwarded_command_rejects_tampered_actor_envelope`

Expected: FAIL because `config_command` dispatch is not implemented.

- [ ] **Step 3: Implement bounded envelopes and dispatch.**

Serialize only typed command, `command_id`, origin node ID, actor ID/email/role, and protocol version. Authenticate the frame with the existing handshake and HMAC transport; revalidate command and actor role on the receiving node, then invoke the local gateway. Return only a bounded commit receipt or stable error code.

- [ ] **Step 4: Add idempotent retry handling.**

Use the existing command ID table/state-machine behavior so a repeated forwarded command returns the prior receipt without applying a second mutation.

- [ ] **Step 5: Run tests and commit.**

Run: `cargo +stable test --test cluster_command_gateway`

```bash
git add src/cluster_raft_runtime.rs src/cluster.rs src/cluster_command.rs tests/cluster_command_gateway.rs
git commit -m "feat: forward replicated writes through authenticated cluster RPC"
```

### Task 3: Route proxy-host and runtime-policy mutations through Raft

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/realtime.rs`
- Modify: `src/cluster_command.rs`
- Test: `tests/control_plane_cluster.rs`
- Test: `tests/cluster_command_gateway.rs`

**Interfaces:**
- Consumes: gateway from Tasks 1–2, existing RBAC/session actor, typed command constructors.
- Produces: no direct follower writes for proxy-host or runtime-policy mutations; committed event publication.

- [ ] **Step 1: Add failing API tests** proving follower `POST/PATCH/DELETE /api/proxy-hosts` and runtime-policy mutations forward, while reads remain local.
- [ ] **Step 2: Run the tests and verify failure** because handlers currently call repository mutation functions directly.
- [ ] **Step 3: Refactor handlers.** Keep authentication, RBAC, host-scope checks, request validation, and audit actor construction in the handler; replace direct mutation with `gateway.submit(command, actor)`.
- [ ] **Step 4: Publish only committed invalidations.** Map command types to existing event kinds (`proxy_hosts.changed`, `rate_limit.changed`) after successful gateway receipt; include commit metadata internally without changing the public SSE payload contract.
- [ ] **Step 5: Verify single-node compatibility and commit.**

Run: `cargo +stable test --test control_plane_cluster --test cluster_command_gateway`

```bash
git add src/control_plane/mod.rs src/control_plane/repository.rs src/control_plane/realtime.rs src/cluster_command.rs tests/control_plane_cluster.rs tests/cluster_command_gateway.rs
git commit -m "feat: route replicated control-plane mutations through raft"
```

### Task 4: Implement bounded cross-node event invalidation

**Files:**
- Create: `src/cluster_events.rs`
- Modify: `src/cluster.rs`
- Modify: `src/cluster_raft_runtime.rs`
- Modify: `src/control_plane/realtime.rs`
- Test: `tests/cluster_events.rs`

**Interfaces:**
- Consumes: post-commit event metadata from Task 3 and authenticated peer connections.
- Produces: `ClusterEventEnvelope`, bounded fan-out, deduplication, and catch-up trigger.

- [ ] **Step 1: Write failing tests** for redaction, HMAC rejection, payload limits, duplicate suppression, and reconnect-triggered state reload.
- [ ] **Step 2: Run the focused tests and verify failure.**

Run: `cargo +stable test --test cluster_events`

Expected: FAIL because no event envelope or peer fan-out exists.

- [ ] **Step 3: Implement `ClusterEventEnvelope`.** Include `event_id`, `command_id`, `commit_index`, `event_type`, `origin_node_id`, and timestamp; reject unknown versions and oversized payloads.
- [ ] **Step 4: Add bounded per-peer fan-out.** Use a bounded queue and authenticated `cluster_event` RPC. Deduplicate by `(origin_node_id, commit_index, event_id)` and trigger a local resource reload when a gap or reconnect is detected.
- [ ] **Step 5: Keep SSE compatibility.** Convert accepted remote invalidations into the existing local `RealtimeHub` event kinds without exposing internal envelope metadata.
- [ ] **Step 6: Run tests and commit.**

```bash
git add src/cluster_events.rs src/cluster.rs src/cluster_raft_runtime.rs src/control_plane/realtime.rs tests/cluster_events.rs
git commit -m "feat: fan out committed cluster invalidations"
```

### Task 5: Verify failover, quorum, catch-up, and idempotent retries

**Files:**
- Modify: `tests/raft_three_node.rs`
- Create: `tests/cluster_failover.rs`
- Modify: `src/cluster.rs`
- Modify: `src/cluster_raft_runtime.rs`

**Interfaces:**
- Consumes: command gateway and event fan-out from Tasks 1–4.
- Produces: deterministic integration coverage for Phase 10C acceptance criteria.

- [ ] **Step 1: Add failing integration scenarios** for follower write forwarding, leader shutdown/election, minority write rejection, rejoining-node catch-up, and duplicate command retry.
- [ ] **Step 2: Run each scenario to verify the missing behavior.**

Run: `cargo +stable test --test cluster_failover -- --nocapture`

Expected: failures until forwarding, readiness, and recovery behavior are wired.

- [ ] **Step 3: Add explicit readiness/quorum metrics mapping.** Update `ClusterService::RaftStatus` from OpenRaft metrics so API status distinguishes leader, follower, unknown leader, and unavailable quorum.
- [ ] **Step 4: Implement shutdown/reconnect test controls.** Ensure listener shutdown and Raft shutdown are graceful, test ports are dynamically allocated, and every spawned task is joined or cancelled.
- [ ] **Step 5: Run the full acceptance suite.**

Run: `cargo +stable test --all-targets -- --test-threads=1`

Expected: all existing tests plus failover scenarios pass with no background task panic.

- [ ] **Step 6: Commit.**

```bash
git add src/cluster.rs src/cluster_raft_runtime.rs tests/raft_three_node.rs tests/cluster_failover.rs
git commit -m "test: verify phase 10c failover and quorum behavior"
```

### Task 6: Add keepalived/VIP operations documentation and readiness check

**Files:**
- Create: `docs/keepalived.md`
- Modify: `README.md`
- Modify: `docs/PRD.md`
- Test: `tests/control_plane_cluster.rs`

**Interfaces:**
- Consumes: authenticated cluster status and readiness fields from Task 5.
- Produces: an operator-runnable health check and documented fencing procedure.

- [ ] **Step 1: Write documentation acceptance checks** for command examples, no container-level interface mutation, leader/quorum eligibility, and fencing warnings.
- [ ] **Step 2: Implement a bounded readiness response/script.** Return non-zero unless the local proxy is ready, cluster listener is ready, and the node satisfies the configured VIP eligibility policy.
- [ ] **Step 3: Document a three-node VRRP example.** Include priorities, `nopreempt`/preemption choice, authentication, health-check timeout, fencing, split-brain warning, and rollback steps.
- [ ] **Step 4: Update PRD/README status** only after implementation tests pass; explicitly mark Phase 10C delivered and Phase 11 as next.
- [ ] **Step 5: Run final verification and commit.**

Run: `cargo +stable fmt --all -- --check && cargo +stable clippy --all-targets -- -D warnings && cargo +stable test --all-targets -- --test-threads=1 && git diff --check`

```bash
git add docs/keepalived.md README.md docs/PRD.md tests/control_plane_cluster.rs
git commit -m "docs: document keepalived integration for phase 10c"
```

## Final review gate

- [ ] Run `git status --short` and confirm the worktree is clean.
- [ ] Review every new internal envelope for secret/request-body leakage.
- [ ] Confirm no follower code path calls direct replicated repository mutations.
- [ ] Confirm all new errors are stable, bounded, and documented.
- [ ] Request code review before merge/push.
