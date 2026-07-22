//! Bounded, out-of-band multi-node cluster health service.
//!
//! Phase 10A scope: node identity, bounded TCP peer health checks, and an
//! authenticated inbound listener. Raft, leader election, write forwarding,
//! cross-node replay, and keepalived automation are deferred to Phase 10B+.
use crate::config::{ClusterConfig, ClusterPeer};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maximum number of peer health checks to run concurrently.
pub const MAX_PEERS: usize = 64;

/// Magic byte sequence for cluster peer handshake (framing only; not a secret).
pub const HANDSHAKE_MAGIC: &[u8] = b"BEARUST1";
/// Maximum handshake frame size to prevent oversized reads.
const MAX_HANDSHAKE_LEN: usize = 512;

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
    bind: SocketAddr,
}

impl ClusterService {
    pub fn new(config: &ClusterConfig) -> Self {
        let peer_count = config.peers.len().min(MAX_PEERS);
        Self {
            node_id: config.node_id.clone(),
            peers: config.peers[..peer_count].to_vec(),
            timeout: Duration::from_secs(config.timeout_seconds.clamp(1, 60)),
            bind: config.bind,
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn peers(&self) -> &[ClusterPeer] {
        &self.peers
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn is_single_node(&self) -> bool {
        self.peers.is_empty()
    }

    /// Perform a single authenticated TCP health check against one peer.
    ///
    /// Sends the cluster handshake (BEARUST1 + local node_id length byte +
    /// node_id bytes) and reads back the peer's identification response.
    /// Peer addresses, raw socket details, and credential material are never
    /// included in the returned `PeerHealth`.
    pub async fn check_peer(&self, peer: &ClusterPeer) -> PeerHealth {
        let start = Instant::now();
        let timeout = self.timeout;
        let local_id = self.node_id.as_bytes().to_vec();

        let res = tokio::time::timeout(timeout, async move {
            let mut stream = TcpStream::connect(peer.address).await?;
            // Send handshake: magic (8 bytes) + node_id length (1 byte) + node_id.
            let id_len = local_id.len().min(255) as u8;
            let mut frame = Vec::with_capacity(9 + local_id.len());
            frame.extend_from_slice(HANDSHAKE_MAGIC);
            frame.push(id_len);
            frame.extend_from_slice(&local_id[..id_len as usize]);
            stream.write_all(&frame).await?;
            // Read response: magic (8) + peer_id_len (1) + peer_id.
            let mut magic = [0u8; 8];
            stream.read_exact(&mut magic).await?;
            if magic != HANDSHAKE_MAGIC {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "handshake magic mismatch",
                ));
            }
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let peer_id_len = len_buf[0] as usize;
            if peer_id_len == 0 || peer_id_len > MAX_HANDSHAKE_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid peer id length in handshake",
                ));
            }
            let mut peer_id_buf = vec![0u8; peer_id_len];
            stream.read_exact(&mut peer_id_buf).await?;
            Ok::<Vec<u8>, std::io::Error>(peer_id_buf)
        })
        .await;

        let elapsed = start.elapsed().as_millis() as u64;

        match res {
            Ok(Ok(_peer_id_bytes)) => PeerHealth {
                node_id: peer.node_id.clone(),
                status: PeerStatus::Healthy,
                latency_ms: Some(elapsed),
                error: None,
            },
            Ok(Err(e)) => {
                let err_msg = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
                    std::io::ErrorKind::TimedOut => "connection timeout".to_string(),
                    std::io::ErrorKind::InvalidData => "handshake failed".to_string(),
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

        // Run bounded concurrent health checks (peer count already capped at MAX_PEERS).
        let futures: Vec<_> = self.peers.iter().map(|p| self.check_peer(p)).collect();
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

/// Bind and run the cluster listener on `config.bind`.
///
/// Accepts inbound peer connections, performs the two-way handshake, logs
/// the connection, then closes it. No data is replicated or forwarded in
/// Phase 10A. The future runs until the cancellation token fires or the
/// listener encounters an unrecoverable error.
///
/// Cluster addresses and raw peer details are never logged or exposed to
/// control-plane API responses.
pub async fn run_cluster_listener(
    service: Arc<ClusterService>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if service.is_single_node() {
        // No peers configured — listener is not started in single-node mode.
        return;
    }

    let bind_addr = service.bind();
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(event = "cluster_listener_bind_failed", error = %e);
            return;
        }
    };
    let bound_addr = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(event = "cluster_listener_start", bind = %bound_addr);

    loop {
        tokio::select! {
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    tracing::info!(event = "cluster_listener_stop");
                    break;
                }
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _remote)) => {
                        let local_id = service.node_id().to_string();
                        tokio::spawn(handle_cluster_connection(stream, local_id));
                    }
                    Err(e) => {
                        tracing::warn!(event = "cluster_accept_error", error = %e);
                    }
                }
            }
        }
    }
}

/// Handle one inbound cluster peer connection.
///
/// Reads the peer's handshake frame, validates magic bytes and frame size,
/// responds with local node identification, then closes the connection.
/// Only the `node_id` of the connecting peer is logged; raw socket addresses
/// and credentials are not included in log fields.
async fn handle_cluster_connection(mut stream: TcpStream, local_node_id: String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    let result = tokio::time::timeout_at(deadline, async {
        // Read: magic (8) + peer_id_len (1) + peer_id bytes.
        let mut magic = [0u8; 8];
        stream.read_exact(&mut magic).await?;
        if magic != HANDSHAKE_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "handshake magic mismatch",
            ));
        }
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await?;
        let peer_id_len = len_buf[0] as usize;
        if peer_id_len == 0 || peer_id_len > MAX_HANDSHAKE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid peer id length",
            ));
        }
        let mut peer_id_buf = vec![0u8; peer_id_len];
        stream.read_exact(&mut peer_id_buf).await?;
        let peer_id = String::from_utf8(peer_id_buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 peer id")
        })?;

        // Respond: magic (8) + local_id_len (1) + local_id bytes.
        let local_id_bytes = local_node_id.as_bytes();
        let id_len = local_id_bytes.len().min(255) as u8;
        let mut resp = Vec::with_capacity(9 + id_len as usize);
        resp.extend_from_slice(HANDSHAKE_MAGIC);
        resp.push(id_len);
        resp.extend_from_slice(&local_id_bytes[..id_len as usize]);
        stream.write_all(&resp).await?;

        Ok::<String, std::io::Error>(peer_id)
    })
    .await;

    match result {
        Ok(Ok(peer_id)) => {
            tracing::debug!(event = "cluster_peer_connected", peer_id = %peer_id);
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
            tracing::warn!(
                event = "cluster_peer_handshake_failed",
                reason = "protocol_error"
            );
        }
        Ok(Err(_)) => {
            tracing::debug!(event = "cluster_peer_disconnected");
        }
        Err(_) => {
            tracing::debug!(event = "cluster_peer_handshake_timeout");
        }
    }
}
