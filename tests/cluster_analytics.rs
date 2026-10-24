//! Cross-node analytics: a cluster query merges every reachable node's
//! collector over the authenticated RPC and reports unreachable peers.

use bearust::analytics::{AnalyticsCollector, AnalyticsEvent, AnalyticsFilter, SecurityCounters};
use bearust::cluster::{run_cluster_listener, ClusterService};
use bearust::config::{ClusterConfig, ClusterPeer};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "01234567890123456789012345678901";

fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn record(collector: &AnalyticsCollector, host: i64, status: u16, latency_ms: u64) {
    collector.record(AnalyticsEvent {
        proxy_host_id: host,
        timestamp: chrono::Utc::now(),
        status_code: status,
        latency_ms,
        security: SecurityCounters {
            waf_blocks: u64::from(status == 403),
            ..Default::default()
        },
    });
}

#[tokio::test]
async fn cluster_query_merges_peer_collectors_and_reports_unreachable_peers() {
    let (a, b, dead) = (free_addr(), free_addr(), free_addr());
    let node = |id: &str, bind: SocketAddr, peers: Vec<(&str, SocketAddr)>| {
        Arc::new(ClusterService::new(&ClusterConfig {
            node_id: id.into(),
            bind,
            peers: peers
                .into_iter()
                .map(|(node_id, address)| ClusterPeer {
                    node_id: node_id.into(),
                    address,
                })
                .collect(),
            timeout_seconds: 2,
            auth_token: SECRET.into(),
        }))
    };
    let node_a = node("node-a", a, vec![("node-b", b), ("node-c", dead)]);
    let node_b = node("node-b", b, vec![("node-a", a)]);

    let local = Arc::new(AnalyticsCollector::default());
    let remote = Arc::new(AnalyticsCollector::default());
    record(&local, 1, 200, 5);
    record(&local, 1, 200, 5);
    record(&remote, 1, 403, 2_000);
    record(&remote, 2, 500, 2_000);
    node_b.set_analytics(remote);

    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_cluster_listener(node_b.clone(), stop_rx));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let all =
        bearust::cluster_analytics::query_cluster(&node_a, &local, &AnalyticsFilter::default())
            .await;
    let statuses = all
        .nodes
        .iter()
        .map(|n| (n.node_id.as_str(), n.status.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            ("node-a", "ok"),
            ("node-b", "ok"),
            ("node-c", "unavailable")
        ]
    );
    assert_eq!(all.history.summary.requests, 4);
    assert_eq!(all.history.summary.waf_blocks, 1);
    assert_eq!(all.history.summary.status_5xx, 1);
    // Percentiles come from the merged histogram, not from either node alone.
    assert_eq!(all.history.summary.p50_ms, Some(5));
    assert_eq!(all.history.summary.p99_ms, Some(2_500));
    assert_eq!(
        all.history
            .timeseries
            .iter()
            .map(|b| b.requests)
            .sum::<u64>(),
        4
    );

    let host_one = bearust::cluster_analytics::query_cluster(
        &node_a,
        &local,
        &AnalyticsFilter {
            proxy_host_id: Some(1),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(host_one.history.summary.requests, 3);
}
