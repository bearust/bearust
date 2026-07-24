//! Bounded, authenticated cross-node realtime invalidations.
//!
//! These events are hints, not replicated state. They carry only post-commit
//! metadata and translate back into the existing process-local SSE event
//! kinds. A gap or reconnected peer invalidates every replicated resource so
//! clients reload from the local Raft-applied state.

use crate::cluster::ClusterService;
use crate::cluster_raft_runtime::{
    decode_raft_rpc, encode_raft_rpc, send_authenticated_rpc_with_identity, ClusterEventHandler,
    RpcTransportError,
};
use crate::control_plane::realtime::{CommittedRealtimeEvent, RealtimeHub};
use crate::control_plane::repository::{self, DbPool};
use async_trait::async_trait;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const CLUSTER_EVENT_PROTOCOL_VERSION: u8 = 1;
pub const MAX_CLUSTER_EVENT_BYTES: usize = 2 * 1024;
pub const MAX_CLUSTER_EVENT_QUEUE_CAPACITY: usize = 64;
const MAX_DEDUPLICATION_KEYS: usize = 1_024;
const MAX_EVENT_TYPE_BYTES: usize = 64;
const MAX_NODE_ID_BYTES: usize = 255;
const MAX_TIMESTAMP_BYTES: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterEventEnvelope {
    pub protocol_version: u8,
    pub event_id: u64,
    pub command_id: Uuid,
    pub commit_index: u64,
    pub event_type: String,
    pub origin_node_id: String,
    pub timestamp: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterEventDisposition {
    Accepted,
    Duplicate,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClusterEventError {
    #[error("cluster event protocol version is unsupported")]
    UnsupportedVersion,
    #[error("cluster event payload exceeds configured limit")]
    PayloadTooLarge,
    #[error("cluster event envelope is invalid")]
    InvalidEnvelope,
    #[error("cluster event identity does not match the authenticated peer")]
    AuthenticationFailed,
    #[error("cluster event queue capacity is invalid")]
    InvalidQueueCapacity,
    #[error("local Raft state did not catch up to the cluster event")]
    AppliedStateUnavailable,
}

impl ClusterEventEnvelope {
    pub fn from_committed(
        event: &CommittedRealtimeEvent,
        origin_node_id: &str,
    ) -> Result<Self, ClusterEventError> {
        let envelope = Self {
            protocol_version: CLUSTER_EVENT_PROTOCOL_VERSION,
            event_id: event.event.id,
            command_id: event.command_id,
            commit_index: event.commit_index,
            event_type: event.event.kind.clone(),
            origin_node_id: origin_node_id.to_string(),
            timestamp: event.event.created_at.clone(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ClusterEventError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| ClusterEventError::InvalidEnvelope)?;
        if encoded.len() > MAX_CLUSTER_EVENT_BYTES {
            return Err(ClusterEventError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ClusterEventError> {
        if payload.len() > MAX_CLUSTER_EVENT_BYTES {
            return Err(ClusterEventError::PayloadTooLarge);
        }
        let envelope: Self =
            serde_json::from_slice(payload).map_err(|_| ClusterEventError::InvalidEnvelope)?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), ClusterEventError> {
        if self.protocol_version != CLUSTER_EVENT_PROTOCOL_VERSION {
            return Err(ClusterEventError::UnsupportedVersion);
        }
        if self.event_id == 0
            || self.command_id.is_nil()
            || self.commit_index == 0
            || self.origin_node_id.is_empty()
            || self.origin_node_id.len() > MAX_NODE_ID_BYTES
            || self.event_type.len() > MAX_EVENT_TYPE_BYTES
            || self.timestamp.is_empty()
            || self.timestamp.len() > MAX_TIMESTAMP_BYTES
            || DateTime::parse_from_rfc3339(&self.timestamp).is_err()
            || !is_replicated_event_type(&self.event_type)
        {
            return Err(ClusterEventError::InvalidEnvelope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClusterEventRequest {
    reconnected: bool,
    event: ClusterEventEnvelope,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClusterEventResponse {
    Accepted,
    Duplicate,
}

pub fn encode_cluster_event_rpc(
    event: &ClusterEventEnvelope,
    reconnected: bool,
) -> Result<Vec<u8>, ClusterEventError> {
    event.encode()?;
    let request = encode_raft_rpc(
        "cluster_event",
        &ClusterEventRequest {
            reconnected,
            event: event.clone(),
        },
    )
    .map_err(map_transport_encoding_error)?;
    if request.len() > MAX_CLUSTER_EVENT_BYTES {
        return Err(ClusterEventError::PayloadTooLarge);
    }
    Ok(request)
}

fn map_transport_encoding_error(error: RpcTransportError) -> ClusterEventError {
    match error {
        RpcTransportError::PayloadTooLarge => ClusterEventError::PayloadTooLarge,
        _ => ClusterEventError::InvalidEnvelope,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EventIdentity {
    origin_node_id: String,
    commit_index: u64,
    event_id: u64,
}

#[derive(Default)]
struct ReceiverState {
    identities: BTreeSet<EventIdentity>,
    identity_order: VecDeque<EventIdentity>,
    last_commit_index: Option<u64>,
}

#[async_trait]
/// Waits until authoritative local state includes a received commit index.
///
/// Implementations observe Raft-applied state only. Cluster events remain
/// invalidation hints and never apply or mutate replicated state themselves.
pub trait AppliedStateLoader: Send + Sync {
    async fn wait_until_applied(&self, commit_index: u64) -> Result<(), ClusterEventError>;
}

/// Bounded applied-index loader backed by the durable local Raft state machine.
pub struct SqlxAppliedStateLoader {
    pool: DbPool,
    node_id: String,
    timeout: Duration,
}

impl SqlxAppliedStateLoader {
    pub fn new(pool: DbPool, node_id: impl Into<String>, timeout: Duration) -> Self {
        Self {
            pool,
            node_id: node_id.into(),
            timeout,
        }
    }
}

#[async_trait]
impl AppliedStateLoader for SqlxAppliedStateLoader {
    async fn wait_until_applied(&self, commit_index: u64) -> Result<(), ClusterEventError> {
        let wait = async {
            loop {
                let applied = repository::load_raft_committed_state(&self.pool, &self.node_id)
                    .await
                    .map_err(|_| ClusterEventError::AppliedStateUnavailable)?
                    .and_then(|state| u64::try_from(state.log_index).ok())
                    .unwrap_or(0);
                if applied >= commit_index {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(self.timeout, wait)
            .await
            .map_err(|_| ClusterEventError::AppliedStateUnavailable)?
    }
}

pub struct ClusterEventReceiver {
    hub: Arc<RealtimeHub>,
    applied_state: Arc<dyn AppliedStateLoader>,
    state: Mutex<ReceiverState>,
}

impl ClusterEventReceiver {
    pub fn new(hub: Arc<RealtimeHub>, applied_state: Arc<dyn AppliedStateLoader>) -> Self {
        Self {
            hub,
            applied_state,
            state: Mutex::new(ReceiverState::default()),
        }
    }

    pub async fn accept(
        &self,
        event: ClusterEventEnvelope,
        authenticated_node_id: &str,
        reconnected: bool,
    ) -> Result<ClusterEventDisposition, ClusterEventError> {
        event.validate()?;
        if event.origin_node_id != authenticated_node_id {
            return Err(ClusterEventError::AuthenticationFailed);
        }

        let identity = EventIdentity {
            origin_node_id: event.origin_node_id.clone(),
            commit_index: event.commit_index,
            event_id: event.event_id,
        };
        let catch_up = {
            let mut state = self.state.lock().await;
            if state.identities.contains(&identity) {
                return Ok(ClusterEventDisposition::Duplicate);
            }
            self.applied_state
                .wait_until_applied(event.commit_index)
                .await?;
            let gap = state
                .last_commit_index
                .is_some_and(|last| event.commit_index > last.saturating_add(1));
            state.last_commit_index = Some(
                state
                    .last_commit_index
                    .map_or(event.commit_index, |last| last.max(event.commit_index)),
            );
            if state.identities.len() >= MAX_DEDUPLICATION_KEYS {
                if let Some(oldest) = state.identity_order.pop_front() {
                    state.identities.remove(&oldest);
                }
            }
            state.identities.insert(identity.clone());
            state.identity_order.push_back(identity);
            gap || reconnected
        };

        if catch_up {
            self.hub.publish_cluster_catch_up();
        }
        self.hub
            .publish_cluster_event(&event.event_type)
            .ok_or(ClusterEventError::InvalidEnvelope)?;
        Ok(ClusterEventDisposition::Accepted)
    }
}

#[async_trait]
impl ClusterEventHandler for ClusterEventReceiver {
    async fn handle_cluster_event(
        &self,
        payload: &[u8],
        authenticated_node_id: &str,
    ) -> Result<Vec<u8>, RpcTransportError> {
        if payload.len() > MAX_CLUSTER_EVENT_BYTES {
            return Err(RpcTransportError::PayloadTooLarge);
        }
        let request: ClusterEventRequest = decode_raft_rpc(payload, "cluster_event")?;
        let response = match self
            .accept(request.event, authenticated_node_id, request.reconnected)
            .await
        {
            Ok(ClusterEventDisposition::Accepted) => ClusterEventResponse::Accepted,
            Ok(ClusterEventDisposition::Duplicate) => ClusterEventResponse::Duplicate,
            Err(ClusterEventError::AuthenticationFailed) => {
                return Err(RpcTransportError::AuthenticationFailed);
            }
            Err(ClusterEventError::PayloadTooLarge) => {
                return Err(RpcTransportError::PayloadTooLarge);
            }
            Err(ClusterEventError::AppliedStateUnavailable) => {
                return Err(RpcTransportError::Unavailable);
            }
            Err(_) => return Err(RpcTransportError::Malformed),
        };
        encode_raft_rpc("cluster_event_response", &response)
    }
}

struct PeerEventQueue {
    sender: mpsc::Sender<ClusterEventEnvelope>,
    stale: Arc<AtomicBool>,
}

/// Owns one bounded non-blocking queue and one delivery worker per configured
/// peer. Queue overflow or transport failure marks that peer stale; the next
/// successful request asks the receiver to reload replicated resources.
pub struct ClusterEventFanout {
    publisher: JoinHandle<()>,
    workers: Vec<JoinHandle<()>>,
    dropped_events: Arc<AtomicU64>,
}

impl ClusterEventFanout {
    pub fn start(
        cluster: Arc<ClusterService>,
        hub: Arc<RealtimeHub>,
        queue_capacity: usize,
    ) -> Result<Self, ClusterEventError> {
        if queue_capacity == 0 || queue_capacity > MAX_CLUSTER_EVENT_QUEUE_CAPACITY {
            return Err(ClusterEventError::InvalidQueueCapacity);
        }

        let dropped_events = Arc::new(AtomicU64::new(0));
        let mut queues = Vec::with_capacity(cluster.peers().len());
        let mut workers = Vec::with_capacity(cluster.peers().len());
        for peer in cluster.peers() {
            let (sender, receiver) = mpsc::channel(queue_capacity);
            let stale = Arc::new(AtomicBool::new(true));
            workers.push(tokio::spawn(run_peer_worker(
                receiver,
                stale.clone(),
                peer.address.to_string(),
                cluster.node_id().to_string(),
                cluster.rpc_secret(),
                cluster.rpc_timeout(),
            )));
            queues.push(PeerEventQueue { sender, stale });
        }

        let mut committed = hub.subscribe_committed();
        let origin_node_id = cluster.node_id().to_string();
        let publisher_dropped = dropped_events.clone();
        let publisher = tokio::spawn(async move {
            loop {
                match committed.recv().await {
                    Ok(event) => {
                        let Ok(envelope) =
                            ClusterEventEnvelope::from_committed(&event, &origin_node_id)
                        else {
                            continue;
                        };
                        for queue in &queues {
                            if queue.sender.try_send(envelope.clone()).is_err() {
                                queue.stale.store(true, Ordering::Release);
                                publisher_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        for queue in &queues {
                            queue.stale.store(true, Ordering::Release);
                        }
                        publisher_dropped.fetch_add(skipped, Ordering::Relaxed);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Self {
            publisher,
            workers,
            dropped_events,
        })
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub async fn shutdown(self) {
        self.publisher.abort();
        let _ = self.publisher.await;
        for worker in self.workers {
            worker.abort();
            let _ = worker.await;
        }
    }
}

async fn run_peer_worker(
    mut receiver: mpsc::Receiver<ClusterEventEnvelope>,
    stale: Arc<AtomicBool>,
    endpoint: String,
    local_node_id: String,
    secret: Vec<u8>,
    timeout: std::time::Duration,
) {
    while let Some(event) = receiver.recv().await {
        let reconnected = stale.swap(false, Ordering::AcqRel);
        let delivery = async {
            let request = encode_cluster_event_rpc(&event, reconnected)
                .map_err(|_| RpcTransportError::Malformed)?;
            let response = send_authenticated_rpc_with_identity(
                &endpoint,
                &local_node_id,
                &request,
                &secret,
                timeout,
            )
            .await?;
            let _: ClusterEventResponse = decode_raft_rpc(&response, "cluster_event_response")?;
            Ok::<(), RpcTransportError>(())
        }
        .await;
        if delivery.is_err() {
            stale.store(true, Ordering::Release);
        }
    }
}

fn is_replicated_event_type(kind: &str) -> bool {
    matches!(kind, "proxy_hosts.changed" | "rate_limit.changed")
}
