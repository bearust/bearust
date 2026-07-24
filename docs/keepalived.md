# Keepalived and VIP operations

BeaRust does not manage host network interfaces and does not run `keepalived`
inside the container. The host owns the VRRP virtual IP (VIP); BeaRust only
provides bounded, authenticated readiness signals. This separation is
intentional: a compromised or partitioned application container must not be
able to add or remove an address on the host.

## Readiness check

Install `curl` and `jq` on each host, then save the following as
`/etc/keepalived/bearust-ready.sh` with mode `0750`, owner `root:root`:

```sh
#!/bin/sh
set -eu

control_url=${BEARUST_CONTROL_URL:-http://127.0.0.1:8081}
proxy_url=${BEARUST_PROXY_URL:-http://127.0.0.1:8080/}
cookie_file=${BEARUST_CLUSTER_COOKIE:-/etc/bearust/cluster-status.cookies}
timeout_seconds=${BEARUST_HEALTH_TIMEOUT_SECONDS:-2}

# Every curl call has a finite deadline. A TCP listener that returns 404/401
# is still a live proxy listener, so only HTTP status 000 is rejected here.
control_code=$(curl --silent --show-error --max-time "$timeout_seconds" \
  --output /dev/null --write-out '%{http_code}' "$control_url/api/health") || exit 1
[ "$control_code" = 200 ] || exit 1

proxy_code=$(curl --silent --show-error --max-time "$timeout_seconds" \
  --output /dev/null --write-out '%{http_code}' "$proxy_url") || exit 1
case "$proxy_code" in
  000) exit 1 ;;
esac

# /api/cluster/status is authenticated. Use a root-readable, least-privilege
# viewer session cookie provisioned out of band; never put a token in a URL.
status=$(curl --silent --show-error --fail --max-time "$timeout_seconds" \
  --cookie "$cookie_file" "$control_url/api/cluster/status") || exit 1

# The default policy gives the VIP only to a leader with a current quorum
# lease and at least one healthy peer (the three-node majority case).
printf '%s' "$status" | jq -e '
  .cluster_enabled == true and
  .raft_role == "leader" and
  .raft_quorum_available == true and
  .raft_sync_state == "leader_ready" and
  (.healthy_peers >= 1)
' >/dev/null || exit 1
```

The script is deliberately fail-closed: any timeout, malformed response,
missing cookie, unhealthy peer set, unknown leader, or lost quorum returns a
non-zero status. `timeout_seconds` is clamped operationally to a small value
(the example default is two seconds); keepalived's `timeout`, `fall`, and
`rise` settings provide the outer retry policy. The cookie file should be
owned by root, mode `0600`, and belong to a dedicated viewer account. Rotate
it through the normal authenticated session workflow; do not log its contents.

The check covers all three eligibility layers: the control-plane health
listener, the local proxy listener, and the authenticated Raft/peer snapshot.
It does not mutate a container or host interface. A successful check means
the node is eligible to hold the VIP, not that application upstreams are
healthy for every route.

## Three-node VRRP example

Use one `vrrp_instance` per host with the same `virtual_router_id`, VIP, and
authentication password. The example uses `nopreempt` to avoid VIP flapping
when a recovered node rejoins; the node currently holding the VIP keeps it
until it fails its readiness check. Priorities still provide an orderly
fallback when the current owner becomes ineligible.

```conf
vrrp_script bearust_ready {
    script "/etc/keepalived/bearust-ready.sh"
    interval 2
    timeout 1
    fall 2
    rise 3
    weight -60
}

vrrp_instance BEARUST_VIP {
    state BACKUP                 # node-1 may start as MASTER if desired
    interface eth0
    virtual_router_id 51
    priority 150                  # node-1; use 140 on node-2, 130 on node-3
    advert_int 1
    nopreempt
    authentication {
        auth_type PASS
        auth_pass replace-with-a-random-vrrp-secret
    }
    virtual_ipaddress {
        192.0.2.50/24 dev eth0
    }
    track_script {
        bearust_ready
    }
}
```

Set `priority` to 140 and 130 on node-2 and node-3 respectively. A failed
check subtracts 60, so a healthy peer can take over. VRRP `auth_pass` protects
VRRP advertisements; it is not the BeaRust `CLUSTER_AUTH_TOKEN`, and both must
be rotated independently. Permit VRRP protocol 112 only between the three
trusted hosts, and keep the BeaRust cluster listener on its separately
firewalled peer network.

### Fencing and split-brain procedure

Never allow two nodes to serve the same VIP. If monitoring shows simultaneous
VIP ownership, or a network partition leaves leadership ambiguous:

1. From the management network, stop `keepalived` on the isolated/suspect
   host (`systemctl stop keepalived`) and disable its automatic restart.
2. Verify ownership from each host (`ip -brief address` is read-only) and
   confirm only the quorum-side leader reports successful readiness.
3. Restore peer connectivity and Raft quorum before starting keepalived again.
4. Check ARP/neighbor convergence, then re-enable the service and watch the
   readiness log through at least three `rise` intervals.

Do not resolve a split brain by adding or deleting the VIP from inside a
container, by changing Raft data, or by deleting database files. Those actions
hide the failure and can cause divergent configuration commits.

### Rollback

To roll back, stop keepalived on all hosts, remove the `vrrp_instance` and
`vrrp_script` blocks, and restore the previous single-node listener routing.
Keep BeaRust running without a VIP while validating the application directly.
Reinstall the script and restore the last known-good priorities only after
quorum, peer authentication, and the cookie file have been verified.

Phase 11 (localization) is the next planned product phase; VIP ownership and
host-level failover remain operational concerns rather than container APIs.
