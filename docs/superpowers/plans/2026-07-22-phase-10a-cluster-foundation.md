# Phase 10A Cluster Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe, observable multi-node cluster foundations while preserving single-node behavior and keeping peer failures off the proxy request path.

**Architecture:** Add a focused `cluster` module for identity, peer parsing, validation, bounded health checks, and redacted status snapshots. Extend configuration and the authenticated control plane without introducing Raft state mutation; later phases will consume the stable cluster interfaces.

**Tech Stack:** Rust, Tokio, Axum, Serde/TOML, existing TLS and auth layers, SQLx-backed control plane.

## Global Constraints

- Empty `CLUSTER_PEERS` must preserve current single-node startup and request behavior.
- Cluster operations are out-of-band and must never block or reject proxied traffic.
- Peer addresses, credentials, private keys, and connection secrets must not appear in API responses, audit details, or logs.
- Peer dialing uses bounded timeouts and bounded peer counts.
- No Raft replication, leader election, write forwarding, replay, or keepalived automation in 10A.

### Task 1: Define cluster configuration and validation

**Files:**
- Modify: `src/config/mod.rs`
- Modify: `.env.example`
- Test: `tests/config.rs`

- [ ] Add `ClusterConfig` with `node_id`, `peers`, cluster bind address, and bounded timeout fields, all with safe single-node defaults.
- [ ] Parse `CLUSTER_PEERS` as a documented comma-separated `node_id=host:port` format and reject malformed, duplicate, empty, or self-referential entries.
- [ ] Add unit tests for omitted settings, valid multi-node settings, malformed addresses, duplicate IDs, and self-reference.
- [ ] Run `cargo +stable test config --all-targets` and confirm existing TOML fixtures still pass.
- [ ] Commit as `feat: add phase 10a cluster configuration`.

### Task 2: Add isolated peer health service

**Files:**
- Create: `src/cluster.rs`
- Modify: `src/lib.rs`
- Test: `tests/cluster.rs`

- [ ] Implement `ClusterService` with immutable local identity, bounded peer checks, and a redacted `ClusterSnapshot`.
- [ ] Ensure timeout, refusal, and malformed peer responses become per-peer unhealthy states rather than process errors.
- [ ] Add deterministic tests using local listeners for healthy, timeout, and unavailable peers; verify no secret-bearing fields are serialized.
- [ ] Run `cargo +stable test cluster --all-targets` and `cargo +stable clippy --all-targets -- -D warnings`.
- [ ] Commit as `feat: add bounded cluster peer health`.

### Task 3: Expose authenticated cluster status

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/realtime.rs` only if status invalidation is needed
- Test: `tests/control_plane_cluster.rs`

- [ ] Add an admin/operator-readable authenticated endpoint for local cluster identity and redacted peer health; require the existing authorization path.
- [ ] Return stable `200`/`401`/`403`/`400` envelopes consistent with other control-plane endpoints.
- [ ] Add API tests for authorized access, viewer denial if policy requires it, unauthenticated rejection, and peer failure visibility.
- [ ] Run the focused API tests plus `cargo +stable test --all-targets`.
- [ ] Commit as `feat: expose authenticated cluster status`.

### Task 4: Wire startup and operational documentation

**Files:**
- Modify: `src/cli.rs`
- Modify: `README.md`
- Modify: `docs/PRD.md`
- Create: `docs/superpowers/reviews/phase-10a-final-review.md`

- [ ] Initialize the cluster service during startup without changing proxy listener behavior or shutdown semantics.
- [ ] Document `NODE_ID`, `CLUSTER_PEERS`, cluster bind/port, firewall boundaries, and single-node defaults; explicitly defer Raft and keepalived to later increments.
- [ ] Record verification commands, test results, compatibility notes, and deferred scope in the final review.
- [ ] Run `cargo +stable fmt --check`, `cargo +stable test --all-targets`, `cargo +stable clippy --all-targets -- -D warnings`, and `git diff --check`.
- [ ] Commit as `docs: complete phase 10a cluster foundation`.
