//! Bounded, out-of-band multi-node cluster health service.
use crate::config::{ClusterConfig, ClusterPeer};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    Healthy,
    Unhealthy,
    Unreachable,
    Timeout,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerHealth {
    pub node_id: String,
    pub status: PeerStatus,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterSnapshot {
    pub local_node_id: String,
    pub cluster_enabled: bool,
    pub total_peers: usize,
    pub healthy_peers: usize,
    pub peers: Vec<PeerHealth>,
    pub timestamp: DateTime<Utc>,
}

pub struct ClusterService {
    node_id: String,
    peers: Vec<ClusterPeer>,
    timeout: Duration,
}

impl ClusterService {
    pub fn new(config: &ClusterConfig) -> Self {
        Self {
            node_id: config.node_id.clone(),
            peers: config.peers.clone(),
            timeout: Duration::from_secs(config.timeout_seconds.max(1)),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn peers(&self) -> &[ClusterPeer] {
        &self.peers
    }

    pub fn is_single_node(&self) -> bool {
        self.peers.is_empty()
    }

    pub async fn check_peer(&self, peer: &ClusterPeer) -> PeerHealth {
        let start = Instant::now();
        let timeout = self.timeout;

        let res = tokio::time::timeout(timeout, async {
            tokio::net::TcpStream::connect(peer.address).await
        })
        .await;

        let elapsed = start.elapsed().as_millis() as u64;

        match res {
            Ok(Ok(_stream)) => PeerHealth {
                node_id: peer.node_id.clone(),
                status: PeerStatus::Healthy,
                latency_ms: Some(elapsed),
                error: None,
            },
            Ok(Err(e)) => {
                let err_msg = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
                    std::io::ErrorKind::TimedOut => "connection timeout".to_string(),
                    _ => "connection failed".to_string(),
                };
                PeerHealth {
                    node_id: peer.node_id.clone(),
                    status: PeerStatus::Unhealthy,
                    latency_ms: Some(elapsed),
                    error: Some(err_msg),
                }
            }
            Err(_) => PeerHealth {
                node_id: peer.node_id.clone(),
                status: PeerStatus::Timeout,
                latency_ms: Some(elapsed),
                error: Some("health check timeout".to_string()),
            },
        }
    }

    pub async fn snapshot(&self) -> ClusterSnapshot {
        let now = Utc::now();
        if self.peers.is_empty() {
            return ClusterSnapshot {
                local_node_id: self.node_id.clone(),
                cluster_enabled: false,
                total_peers: 0,
                healthy_peers: 0,
                peers: vec![],
                timestamp: now,
            };
        }

        let mut futures = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            futures.push(self.check_peer(peer));
        }

        let peer_healths = futures_util::future::join_all(futures).await;
        let healthy_peers = peer_healths
            .iter()
            .filter(|p| p.status == PeerStatus::Healthy)
            .count();

        ClusterSnapshot {
            local_node_id: self.node_id.clone(),
            cluster_enabled: true,
            total_peers: self.peers.len(),
            healthy_peers,
            peers: peer_healths,
            timestamp: now,
        }
    }
}
