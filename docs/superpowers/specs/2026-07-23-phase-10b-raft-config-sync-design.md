# Phase 10B: Raft Configuration Synchronization Design

## Goal

Add durable Raft coordination for BeaRust control-plane configuration so one
leader is the source of truth, followers can recover after restart, and
configuration writes are not acknowledged until the cluster commits them.

## Scope

Phase 10B delivers:

- A persistent OpenRaft node using the Phase 10A node identity and peer
  transport.
- Leader/follower/candidate status and authenticated cluster-status reporting.
- A durable Raft log and snapshot store backed by the configured control-plane
  database, with bounded entries and snapshot compaction.
- A typed configuration command envelope for proxy-host configuration and
  runtime policy updates, applied atomically on committed entries.
- Leader-only write gateway behavior: followers return a stable redirect or
  forward request, while reads remain locally available from the last committed
  state.
- Bootstrap, join, restart recovery, quorum loss, and partition tests.

Phase 10B does not deliver keepalived/VRRP automation, cross-node SSE replay,
analytics aggregation, or replication of process-local traffic statistics. Those
are Phase 10C or later concerns.

## Design

The `cluster` module owns OpenRaft node lifecycle, network RPC framing, and
status snapshots. A database-backed log store persists terms, votes, log
entries, and snapshots using bounded serialized command payloads. The state
machine applies only committed commands and uses an idempotency key to make
retries safe.

Control-plane mutations pass through a command dispatcher. The leader proposes
the command and waits for quorum commit before returning success. A follower
does not mutate local state for a write; it returns a stable `409 leader_required`
response containing only the redacted leader node ID when known. Existing
single-node mode treats the local node as the effective leader and keeps current
behavior unchanged.

The first replicated command set is deliberately explicit: proxy-host create,
update, delete, and the existing host-scoped runtime policy changes. Each
command validates authorization and input before proposal, then applies the
database mutation in one transaction during state-machine execution. Commands
never contain passwords, private keys, session tokens, request bodies, or raw
database errors.

## Acceptance criteria

1. A single node starts, serves, and passes all existing tests with no peer
   configuration changes.
2. A three-node test cluster elects one leader and exposes stable role/term/
   commit-index status through the authenticated API.
3. A committed command survives follower restart and snapshot compaction.
4. A follower write cannot create a divergent local mutation and returns the
   documented leader-required response.
5. Loss of quorum prevents new writes but does not reject ordinary proxy
   traffic or corrupt committed state.
6. Duplicate proposal retries are idempotent.
7. Full tests, Clippy with `-D warnings`, formatting, and diff checks pass.
