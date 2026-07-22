# Task 3 review fixes

## Changes

- Extract the peer IP directly from Pingora's `SocketAddr::Inet` via
  `as_inet().ip()`, preserving both IPv4 and IPv6 addresses and avoiding the
  lossy string round-trip that previously skipped real requests.
- Derive the temporary proxy-host identity from `ResolvedRoute.host` only;
  `path_prefix` is excluded so all paths on one host share one client quota.
- Added regressions for direct IPv4/IPv6 extraction, trusted bracketed IPv6
  forwarding, and shared host quota across paths.

## Verification

Command:

```text
cargo +nightly test --test proxy_rate_limit
```

Output:

```text
running 6 tests
test block_mode_exposes_retry_after_for_429_response ... ok
test buckets_are_isolated_by_proxy_host_and_client_ip ... ok
test client_ip_preserves_ipv4_and_ipv6_peer_addresses ... ok
test monitor_mode_records_limit_without_changing_decision_math ... ok
test one_host_quota_is_shared_across_paths ... ok
test trusted_forwarded_client_ip_supports_bracketed_ipv6 ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The repository's default Cargo 1.84.1 cannot parse the cached `clap_lex`
2024-edition manifest, so verification used the installed nightly toolchain.
