# Phase 10A Cluster Foundation Final Review

## Overview

Phase 10A establishes node identity, cluster peer configuration, an authenticated
TCP cluster listener, bounded concurrent peer health checks, and a redacted status
endpoint for BeaRust multi-node operations — while preserving single-node defaults
and keeping all peer failures completely off the proxy request path.

## Verification Checklist

| Check | Result |
|---|---|
| `cargo +stable test --all-targets` | **PASS** |
| `cargo +stable clippy --all-targets -- -D warnings` | **PASS (0 warnings)** |
| `cargo +stable fmt --check` | **PASS** |
| `git diff --check` | **PASS (Clean)** |

## Delivered Features & Artifacts

### 1. Cluster Configuration & Strict Validation (`src/config/mod.rs`)
- `ClusterConfig` and `ClusterPeer` structs with TOML and env-var parsing.
- `NODE_ID` and `CLUSTER_PEERS` (`node_id=host:port` comma-separated) with defaults for single-node.
- Strict validation: empty node IDs, self-referential peers, duplicate peer IDs/addresses, malformed addresses, **empty peer entries** (e.g. `node1=..,,node2=..` or trailing commas), and **peer count capped at 64**.

### 2. Authenticated Cluster Listener & Handshake (`src/cluster.rs`)
- `run_cluster_listener(Arc<ClusterService>, watch::Receiver<bool>)`: binds `config.cluster.bind` and accepts inbound peer connections. Skipped entirely in single-node mode (zero listener overhead).
- Two-way handshake protocol: `BEARUST1` magic (8 bytes) + node_id length (1 byte) + node_id. Framed and bounded to 512 bytes per side to prevent resource abuse.
- Inbound connection handler: validates magic, enforces frame bounds, responds with local node_id, logs only peer_id (no raw addresses/credentials), closes connection after exchange.
- Handshake timeout: 5-second deadline per inbound connection.
- Graceful shutdown via `watch::Receiver<bool>` wired into the Tokio `select!` loop; listener is cancelled at process shutdown.

### 3. Bounded Out-of-Band Peer Health Checks (`src/cluster.rs`)
- `ClusterService::check_peer()` performs the bidirectional handshake as an outbound health check; reports `Healthy` only on successful protocol exchange (not just TCP connect).
- Max concurrent peers bounded at `MAX_PEERS = 64` (also validated in config).
- Peer count is bounded before `join_all` to prevent unbounded resource consumption.

### 4. Authenticated Cluster Status Endpoint (`src/control_plane/mod.rs`)
- `GET /api/cluster/status` — requires auth, returns `ClusterSnapshot`.
- Snapshot JSON omits raw peer addresses, secrets, private keys, and credentials.

### 5. Startup Wiring & Graceful Shutdown (`src/cli.rs`)
- `ClusterService::new(&config.cluster)` initialized at startup.
- `run_cluster_listener` spawned as an independent Tokio task (out-of-band — never blocks proxy path).
- `cluster_shutdown_tx.send(true)` cancels listener during graceful shutdown.

### 6. Documentation (`.env.example`, `README.md`, `docs/PRD.md`)
- `NODE_ID`, `CLUSTER_PEERS` documented in env file and README.
- Phase 10A status section in `docs/PRD.md` updated.

## Deferred Scope (Phase 10B/10C)

- Raft consensus state replication and leader election.
- Write forwarding across nodes.
- Cross-node SSE event fan-out / replay.
- Keepalived VIP automation.
