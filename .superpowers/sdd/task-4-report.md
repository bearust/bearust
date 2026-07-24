# Phase 10C Task 4 Report

## Delivered

- Wired `ClusterEventReceiver` and `ClusterEventFanout` into normal
  cluster-enabled startup in `src/cli.rs`. The receiver is registered before
  the cluster listener starts, the fanout subscribes to the committed event
  stream before API traffic begins, and the retained fanout is shut down before
  the listener and Raft runtime. Auth-token-only single-node configurations
  retain their zero-peer behavior.
- Added a versioned `ClusterEventEnvelope` containing only event ID, command
  ID, commit index, event type, origin node ID, and timestamp.
- Enforced the 2 KiB limit over the complete cluster-event RPC envelope.
  Authenticated dispatch first decodes only the outer RPC kind, so leading
  whitespace and unknown outer fields cannot be parsed into an unbounded
  semantic value before rejection. The handler independently enforces the same
  bound.
- Added a bounded SQLx applied-state loader. A received event waits until the
  durable local Raft applied index reaches its commit index before any local SSE
  invalidation is published. Events remain hints and never mutate replicated
  state.
- Added bounded non-blocking per-peer queues. Queue overflow, transport
  failure, or committed-stream lag marks a peer stale; the next authenticated
  `cluster_event` RPC requests catch-up.
- Added bounded deduplication by `(origin_node_id, commit_index, event_id)`.
  Gap detection now uses one global Raft commit watermark, avoiding false gaps
  when consecutive commits arrive from alternating origins. Real gaps and
  reconnect markers trigger both replicated resource invalidations before the
  accepted event is published.
- Routed `cluster_event` through the existing BEARUST1 identity handshake and
  HMAC-authenticated BRRAFT1 frame.
- Kept public SSE compatibility: remote events become the existing
  `proxy_hosts.changed` or `rate_limit.changed` shape, with no cluster envelope
  metadata exposed.

## Red evidence

The review regressions failed against Task 4 base `bf8ca515` for the expected
reasons:

```text
authenticated_dispatcher_rejects_oversized_event_rpc_before_semantic_parse
left: Ok(<accepted response>)
right: Err(PayloadTooLarge)

alternating_origins_share_one_commit_watermark_without_false_gaps
left: "proxy_hosts.changed"
right: "rate_limit.changed"

error[E0432]: unresolved import `bearust::cluster_events::AppliedStateLoader`
```

## Verification

```text
cargo +stable test --test cluster_events
9 passed; 0 failed

cargo +stable test --test cli --test cluster --test cluster_raft \
  --test cluster_raft_runtime --test cluster_raft_storage \
  --test cluster_command_gateway --test control_plane_cluster \
  --test control_plane_realtime --test raft_three_node
72 passed; 0 failed

cargo +stable test --test shutdown
3 passed; 0 failed

cargo +stable fmt --all -- --check
passed

cargo +stable clippy --all-targets -- -D warnings
passed

git diff --check
passed
```

The applied-state regression delivers an event before the local durable applied
index advances and verifies that SSE remains silent until
`raft_committed_state` reaches the event commit. The alternating-origin
regression proves contiguous global commits do not create catch-up noise. The
queue test uses a stalled authenticated peer to prove publisher calls stay
non-blocking and overflow is accounted for, and the transport test starts the
real cluster listener for end-to-end authenticated fan-out.

## Scope

The review fix is based on `bf8ca515` and is limited to cluster event startup
wiring, event receiver/dispatcher correctness, focused tests, and this report.
The pre-existing `.superpowers/sdd/progress.md` modification remains excluded.
