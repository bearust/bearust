//! Cross-node analytics aggregation over the authenticated cluster RPC.
//!
//! Each node keeps its own bounded collector. A cluster query fans out one
//! `analytics_query` RPC per configured peer, merges the exports with the
//! local one, and reports which nodes answered. Peers that are unreachable
//! are listed as such instead of failing the whole query.

use crate::analytics::{
    merge_cluster_exports, AnalyticsCollector, AnalyticsFilter, AnalyticsHistory,
    AnalyticsInterval, NodeAnalyticsExport,
};
use crate::cluster::ClusterService;
use crate::cluster_raft_runtime::{
    decode_raft_rpc, encode_raft_rpc, send_authenticated_rpc_with_identity, RpcTransportError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const ANALYTICS_QUERY_KIND: &str = "analytics_query";
const ANALYTICS_RESPONSE_KIND: &str = "analytics_query_response";

/// Leave headroom below the RPC frame limit for the envelope and MAC.
const MAX_EXPORT_BYTES: usize = crate::cluster_raft::MAX_RPC_FRAME_BYTES - 4 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsQueryRequest {
    pub proxy_host_id: Option<i64>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: usize,
    pub interval: String,
}

impl AnalyticsQueryRequest {
    pub fn from_filter(filter: &AnalyticsFilter) -> Self {
        Self {
            proxy_host_id: filter.proxy_host_id,
            from: filter.from,
            to: filter.to,
            limit: filter.limit,
            interval: match filter.interval {
                AnalyticsInterval::Minute => "minute",
                AnalyticsInterval::Hour => "hour",
                AnalyticsInterval::Day => "day",
            }
            .into(),
        }
    }

    fn to_filter(&self) -> Result<AnalyticsFilter, RpcTransportError> {
        let interval = match self.interval.as_str() {
            "minute" => AnalyticsInterval::Minute,
            "hour" => AnalyticsInterval::Hour,
            "day" => AnalyticsInterval::Day,
            _ => return Err(RpcTransportError::Malformed),
        };
        if self.proxy_host_id.is_some_and(|id| id <= 0)
            || self.limit > crate::analytics::MAX_RETENTION_BUCKETS
        {
            return Err(RpcTransportError::Malformed);
        }
        Ok(AnalyticsFilter {
            proxy_host_id: self.proxy_host_id,
            from: self.from,
            to: self.to,
            limit: self.limit,
            interval,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsQueryResponse {
    pub node_id: String,
    pub export: NodeAnalyticsExport,
}

/// Answer an authenticated `analytics_query` payload (an RPC envelope) from
/// the local collector.
pub fn handle_analytics_query(
    payload: &[u8],
    node_id: &str,
    collector: &AnalyticsCollector,
) -> Result<Vec<u8>, RpcTransportError> {
    let request: AnalyticsQueryRequest = decode_raft_rpc(payload, ANALYTICS_QUERY_KIND)?;
    let filter = request.to_filter()?;
    encode_raft_rpc(
        ANALYTICS_RESPONSE_KIND,
        &AnalyticsQueryResponse {
            node_id: node_id.to_owned(),
            export: collector.export_for_cluster(&filter, MAX_EXPORT_BYTES),
        },
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeQueryStatus {
    pub node_id: String,
    /// `ok`, `truncated` (timeseries partial, totals exact), or `unavailable`.
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterAnalytics {
    pub nodes: Vec<NodeQueryStatus>,
    #[serde(flatten)]
    pub history: AnalyticsHistory,
}

/// Query every configured peer concurrently and merge with the local view.
pub async fn query_cluster(
    cluster: &ClusterService,
    collector: &AnalyticsCollector,
    filter: &AnalyticsFilter,
) -> ClusterAnalytics {
    let local = collector.export_for_cluster(filter, MAX_EXPORT_BYTES);
    let mut nodes = vec![NodeQueryStatus {
        node_id: cluster.node_id().to_owned(),
        status: status_of(&local).into(),
    }];
    let mut exports = vec![local];
    let request = AnalyticsQueryRequest::from_filter(filter);
    let secret = cluster.rpc_secret();
    let timeout = cluster.rpc_timeout();
    let calls = cluster.peers().iter().map(|peer| {
        let request = &request;
        let secret = &secret;
        async move {
            let result = async {
                let payload = encode_raft_rpc(ANALYTICS_QUERY_KIND, request)?;
                let endpoint = peer.address.to_string();
                let response = send_authenticated_rpc_with_identity(
                    &endpoint,
                    cluster.node_id(),
                    &payload,
                    secret,
                    timeout,
                )
                .await?;
                let response: AnalyticsQueryResponse =
                    decode_raft_rpc(&response, ANALYTICS_RESPONSE_KIND)?;
                if response.node_id != peer.node_id {
                    return Err(RpcTransportError::AuthenticationFailed);
                }
                Ok::<_, RpcTransportError>(response.export)
            }
            .await;
            (peer.node_id.clone(), result)
        }
    });
    for (node_id, result) in futures_util::future::join_all(calls).await {
        match result {
            Ok(export) => {
                nodes.push(NodeQueryStatus {
                    node_id,
                    status: status_of(&export).into(),
                });
                exports.push(export);
            }
            Err(error) => {
                tracing::debug!(event = "cluster_analytics_peer_failed", peer_id = %node_id, error = %error);
                nodes.push(NodeQueryStatus {
                    node_id,
                    status: "unavailable".into(),
                });
            }
        }
    }
    ClusterAnalytics {
        nodes,
        history: merge_cluster_exports(&exports, filter),
    }
}

fn status_of(export: &NodeAnalyticsExport) -> &'static str {
    if export.truncated {
        "truncated"
    } else {
        "ok"
    }
}
