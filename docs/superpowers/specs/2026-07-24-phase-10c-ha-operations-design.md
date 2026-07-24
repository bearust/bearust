# Phase 10C — HA Operations and Multi-Node Control Plane Design

## Status

Design approved in brainstorming. Implementation is intentionally not included
in this document.

## Goal

Complete the operational multi-node control-plane behavior on top of Phase 10B
Raft replication: route configuration writes through the leader, propagate
post-commit invalidation events across nodes, recover safely from failures and
partitions, and document host-level keepalived/VIP integration.

## Context

Phase 10B provides durable SQLx-backed OpenRaft storage, authenticated vote,
append-entries, and snapshot RPCs, deterministic node IDs, and a verified
three-node leader election. The existing API handlers still perform local
database mutations and the realtime hub is process-local. Phase 10C adds the
control-plane boundary needed to make those capabilities safe for real
multi-node operation.

## Goals and non-goals

### Goals

- Centralize replicated configuration mutations behind a command gateway.
- Keep authentication, RBAC, input validation, and audit attribution at the
  receiving API node before a command is submitted.
- Submit commands only through the Raft leader and wait for quorum commit.
- Reject writes when leadership or quorum cannot be established; never perform
  an unsafe local fallback write.
- Publish redacted invalidation events only after committed state-machine apply.
- Deliver bounded cross-node event invalidations with deduplication and
  reconnect/catch-up behavior.
- Test leader forwarding, failover, quorum loss, retry idempotency, and node
  catch-up.
- Provide a documented keepalived/VIP health-check and fencing procedure.

### Non-goals

- Running keepalived inside the BeaRust container.
- Replicating users, passwords, sessions, private keys, provider credentials,
  audit history, or arbitrary database tables through Raft.
- Treating realtime events as a source of truth or implementing durable event
  replay as a replacement for Raft state.
- Allowing followers to accept and locally commit configuration writes.
- Adding a general-purpose policy language or changing existing RBAC semantics.

## Architecture

### Command gateway

All replicated configuration mutations use a `ConfigCommandGateway`. Existing
handlers continue to authenticate the session, enforce RBAC, validate request
fields, create the audit actor context, and construct a typed `ConfigCommand`.
The gateway then:

1. Reads the local Raft role and current leader.
2. Calls `client_write` locally when this node is leader.
3. Forwards the command over the authenticated cluster transport when this node
   is a follower and a leader endpoint is known.
4. Returns a structured error when the leader is unknown or quorum is
   unavailable.
5. Returns success only after the command is committed and applied locally.

The forwarded request contains a bounded command envelope, `command_id`, the
origin node ID, and the authenticated actor context needed for safe audit
attribution. It never contains a session cookie, password, private key,
provider credential, or raw request body. The receiver revalidates the command
and authorization context before calling its gateway.

The gateway is the only write path for replicated proxy-host and runtime-policy
commands. Reads remain local and may reflect the latest committed state known by
that node. Certificate, user/RBAC, session, and audit mutations remain local in
this phase unless explicitly represented by a future typed command.

### Commit and event ordering

The ordering invariant is:

```text
validate + authorize
  -> Raft commit quorum
  -> local state-machine apply
  -> local redacted realtime event
  -> bounded cross-node invalidation
```

Events carry only `event_id`, `command_id`, `commit_index`, `event_type`,
`origin_node_id`, and timestamp. Receivers validate the authenticated envelope,
deduplicate by event/commit identity, and invalidate or reload local views. A
missed event does not lose state because the receiver catches up from Raft
metrics/state and reloads the affected resource.

### Failure and recovery behavior

- Leader with quorum: writes commit normally.
- Follower with known leader: writes forward to the leader.
- Unknown leader: return `cluster_leader_unknown`.
- No quorum: return `cluster_quorum_unavailable`.
- Network partition: only the quorum side may commit; the minority is
  read-only for replicated configuration.
- Leader failure: OpenRaft elects a new leader; clients retry the same
  `command_id` to preserve idempotency.
- Rejoining node: OpenRaft catches up through log replication or snapshot; no
  write is accepted from it until membership/state is healthy.
- Event transport failure: mark the peer stale, reconnect with bounded retries,
  and perform state catch-up instead of replaying untrusted event payloads.

### Keepalived/VIP boundary

Keepalived runs on the host and owns the VRRP VIP. BeaRust supplies a documented
health-check script/API that reports whether the node is eligible to serve the
VIP: authenticated cluster status, leader/quorum state, listener readiness, and
local proxy readiness. The procedure includes priority/preemption settings,
fencing guidance, and a rule that only one healthy eligible node may hold the
VIP. BeaRust does not manipulate host interfaces or execute keepalived itself.

## Interfaces

The implementation plan will introduce focused interfaces rather than exposing
database internals:

- `ConfigCommandGateway::submit(command, actor) -> Result<CommitReceipt,
  ClusterWriteError>`
- `ClusterWriteError` variants for leader unknown, quorum unavailable,
  forwarding timeout, authentication failure, and validation rejection.
- An authenticated internal command envelope with bounded size and explicit
  command kind.
- An authenticated post-commit event envelope with deduplication metadata.
- A cluster readiness/eligibility result consumed by keepalived documentation
  and health-check tests.

## Security and limits

- Reuse the existing cluster HMAC handshake and bounded RPC frame limits.
- Enforce maximum command/event envelope sizes before allocation or parsing.
- Compare authentication tags in constant time.
- Never log raw forwarded payloads, credentials, session tokens, or SQL errors.
- Preserve centralized RBAC and host-scope checks at the API boundary.
- Treat forwarded actor metadata as untrusted until validated against the
  authenticated cluster identity and command policy.
- Use bounded timeouts, retries, and peer counts; no unbounded queues.

## Testing and acceptance criteria

The phase is complete only when all of the following are covered:

1. A three-node integration test submits a write through a follower and verifies
   the leader commits it and all quorum members apply it.
2. Direct follower writes never mutate the local database.
3. Leader-unknown and no-quorum writes return stable structured errors.
4. Retrying the same command ID is idempotent across forwarding and failover.
5. A leader shutdown results in a new leader and successful subsequent writes.
6. A rejoining node catches up through log replication or snapshot.
7. Events are emitted only after commit, are redacted, authenticated, bounded,
   and deduplicated.
8. Event disconnect/reconnect causes state reload/catch-up without stale
   mutation.
9. Network partition tests prove the minority cannot commit writes.
10. Keepalived documentation includes a tested readiness command, VIP fencing
    guidance, and no container-level host mutation.
11. Existing repository tests, `cargo +stable fmt --all -- --check`, and
    `cargo +stable clippy --all-targets -- -D warnings` pass.

## Rollout and compatibility

Single-node configuration remains unchanged: no peers means no forwarding and
local writes continue to work. Multi-node writes are opt-in through the
existing authenticated cluster configuration. Existing read APIs and response
schemas remain compatible; new cluster errors and status fields are additive.

## Open decisions resolved

- Command gateway rather than transparent HTTP proxying: preserves RBAC,
  validation, and audit boundaries.
- Cross-node events are invalidations, not replicated state: Raft remains the
  source of truth.
- Keepalived remains host-level and documented rather than reimplemented in
  Rust.
