# Phase 10C Task 2 Report

## Status

Completed authenticated internal configuration-command forwarding.

## Changed scope

- `src/cluster_raft_runtime.rs`: added authenticated `config_command` dispatch, an internal command-handler boundary, and authenticated leader status for bounded discovery.
- `src/cluster.rs`: registered the command handler with the cluster listener and routed authenticated command frames alongside existing Raft RPCs.
- `src/cluster_command.rs`: added bounded typed forwarding envelopes/responses, actor and command revalidation, stable transport error mapping, duplicate-command receipt caching, and bounded follower leader discovery.
- `tests/cluster_command_gateway.rs`: added envelope/authentication/idempotency coverage and real three-node follower-to-leader forwarding with authenticated listener readiness checks.

Forwarded payloads contain only the protocol version, origin node ID, command ID, typed command, and bounded actor context. The receiver compares the envelope origin with the authenticated handshake identity before invoking the leader’s local gateway. Followers never fall back to a local write.

When local Raft metrics have not yet exposed a leader endpoint, the gateway polls only configured peers over the authenticated status RPC. It validates the returned node identity and accepts only a peer reporting itself as leader. Discovery is bounded by the existing two-second write deadline, uses 100 ms per-peer probes and a 25 ms polling interval, and returns `LeaderUnknown` when the deadline expires.

## Red evidence

After narrowing the three-node election wait to the actual live-leader condition, the forwarding test reproduced the missing discovery behavior:

```text
cargo +stable test --test cluster_command_gateway \
  follower_gateway_forwards_without_locally_committing \
  -- --nocapture --test-threads=1

called `Result::unwrap()` on an `Err` value: LeaderUnknown
test result: FAILED. 0 passed; 1 failed
```

The listener-readiness race was also isolated to setup that observed in-memory status before proving the endpoint accepted the authenticated protocol. The final setup performs a bounded authenticated status round trip to every listener before cluster initialization.

## Verification

Focused forwarding and transport tests:

```text
cargo +stable test --test cluster_command_gateway \
  --test cluster_raft_runtime -- --test-threads=1
```

Result:

```text
cluster_command_gateway: 9 passed; 0 failed
cluster_raft_runtime: 10 passed; 0 failed
```

Formatting:

```text
cargo +stable fmt --all -- --check
```

Result: passed with no formatting changes required after applying rustfmt.

Linting:

```text
cargo +stable clippy --all-targets -- -D warnings
```

Result:

```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.39s
```

Diff validation:

```text
git diff --check
```

Result: passed with no whitespace errors.

## Scope notes

- `.superpowers/sdd/progress.md` remains modified but is deliberately excluded from the Task 2 commit.
- No rate-limit or bot-protection files were changed.
