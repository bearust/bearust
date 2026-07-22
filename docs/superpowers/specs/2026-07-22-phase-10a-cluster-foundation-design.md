# Phase 10A: Cluster Foundation Design

## Goal

Prepare BeaRust for safe multi-node operation by defining node identity, peer
configuration, authenticated control-plane transport, and observable cluster
health without replicating configuration yet.

## Scope

Phase 10A delivers:

- Explicit `NODE_ID` and `CLUSTER_PEERS` configuration with strict validation.
- A bounded peer descriptor containing node ID, address, and transport identity.
- Authenticated, TLS-capable cluster transport boundaries and startup checks.
- Readiness/health reporting for local node identity and peer connectivity.
- Redacted cluster audit/log fields and bounded failure behavior.
- Unit, API, and integration tests for valid configuration, invalid peers,
  duplicate identities, unreachable peers, and single-node compatibility.

Phase 10A does not implement Raft state replication, leader election, write
forwarding, cross-node event replay, or keepalived automation. Those belong to
Phases 10B and 10C.

## Design

The existing TOML configuration remains the source of local startup settings.
Environment variables provide deployment-friendly defaults for `NODE_ID` and
`CLUSTER_PEERS`, while an empty peer list preserves current single-node
behavior. A dedicated cluster module owns parsing, validation, peer dialing,
and health snapshots so the proxy request path is unaffected by peer failure.

Cluster traffic uses a separate bind/port from public proxy and control-plane
traffic. Authentication is mandatory for peer requests, and logs never include
credentials, private keys, or full connection strings. Peer checks use bounded
timeouts and fail closed for cluster operations while keeping local proxying
available.

## Acceptance criteria

1. Existing configurations without cluster settings parse and run unchanged.
2. Invalid, duplicate, or self-referential peers fail startup with stable,
   actionable validation errors.
3. Cluster health is available through an authenticated control-plane endpoint
   and never exposes secrets.
4. Peer timeout or disconnect cannot reject ordinary proxied requests.
5. `cargo +stable test --all-targets`, Clippy with `-D warnings`, formatting,
   and documentation checks pass.
