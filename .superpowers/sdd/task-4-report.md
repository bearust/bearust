# Phase 10C Task 4 Report

## Delivered

- Added a versioned `ClusterEventEnvelope` containing only event ID, command
  ID, commit index, event type, origin node ID, and timestamp.
- Enforced a 2 KiB envelope limit, strict field decoding, supported event
  kinds, authenticated origin matching, and rejection of unknown protocol
  versions.
- Added bounded non-blocking per-peer queues. Queue overflow, transport
  failure, or committed-stream lag marks a peer stale; the next authenticated
  `cluster_event` RPC requests catch-up.
- Added bounded deduplication by `(origin_node_id, commit_index, event_id)`.
  Commit gaps and reconnect markers trigger both replicated resource
  invalidations before the accepted event is published.
- Routed `cluster_event` through the existing BEARUST1 identity handshake and
  HMAC-authenticated BRRAFT1 frame.
- Kept public SSE compatibility: remote events become the existing
  `proxy_hosts.changed` or `rate_limit.changed` shape, with no cluster envelope
  metadata exposed.

## Red evidence

The new focused suite initially failed because the Task 4 interfaces did not
exist:

```text
error[E0432]: unresolved import `bearust::cluster_events`
error[E0432]: no `dispatch_authenticated_rpc_with_event_handler`
error[E0599]: no method named `set_event_handler`
```

## Verification

```text
cargo +stable test --test cluster_events
6 passed; 0 failed

cargo +stable test --test cluster_events --test cluster \
  --test cluster_raft_runtime --test control_plane_realtime \
  --test cluster_command_gateway
52 passed; 0 failed

cargo +stable fmt --all -- --check
passed

cargo +stable clippy --all-targets -- -D warnings
passed

git diff --check
passed
```

The queue test uses a stalled authenticated peer to prove publisher calls stay
non-blocking and overflow is accounted for. The transport test starts the real
cluster listener and verifies end-to-end authenticated fan-out.

## Scope

Task 4 changes are limited to the event module, cluster listener/RPC dispatch,
realtime translation, module registration, focused tests, and this report.
The pre-existing `.superpowers/sdd/progress.md` modification is excluded.
