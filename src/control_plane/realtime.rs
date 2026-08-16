use chrono::{SecondsFormat, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Process-local event fan-out used to invalidate connected control-plane UIs.
///
/// Events are intentionally small and contain no request or credential data.
pub struct RealtimeHub {
    sender: broadcast::Sender<RealtimeEvent>,
    committed_sender: broadcast::Sender<CommittedRealtimeEvent>,
    sequence: AtomicU64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RealtimeEvent {
    pub id: u64,
    pub kind: String,
    pub created_at: String,
}

/// Internal post-commit metadata for authenticated cluster invalidation.
///
/// The public SSE stream continues to serialize only [`RealtimeEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRealtimeEvent {
    pub event: RealtimeEvent,
    pub command_id: Uuid,
    pub leader_id: u64,
    pub commit_index: u64,
}

impl RealtimeHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        let (committed_sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            committed_sender,
            sequence: AtomicU64::new(0),
        }
    }

    pub fn publish(&self, kind: &'static str) -> RealtimeEvent {
        let event = self.next_event(kind);
        let _ = self.sender.send(event.clone());
        event
    }

    /// Publish one authenticated remote cluster invalidation through the same
    /// public SSE shape as a local event.
    pub fn publish_cluster_event(&self, kind: &str) -> Option<RealtimeEvent> {
        match kind {
            "proxy_hosts.changed" => Some(self.publish("proxy_hosts.changed")),
            "load_balancer.changed" => Some(self.publish("load_balancer.changed")),
            "runtime_config.changed" => Some(self.publish("load_balancer.changed")),
            "rate_limit.changed" => Some(self.publish("rate_limit.changed")),
            "security.changed" => Some(self.publish("security.changed")),
            "plugins.changed" => Some(self.publish("plugins.changed")),
            _ => None,
        }
    }

    /// Invalidate every replicated control-plane view after a cluster event
    /// gap or reconnect. Raft state remains authoritative; these events make
    /// local consumers reload that already-applied state.
    pub fn publish_cluster_catch_up(&self) {
        self.publish("proxy_hosts.changed");
        self.publish("rate_limit.changed");
        self.publish("load_balancer.changed");
        self.publish("security.changed");
    }

    pub fn publish_committed(
        &self,
        kind: &'static str,
        receipt: &crate::cluster_command::CommitReceipt,
    ) -> RealtimeEvent {
        let event = self.next_event(kind);
        let _ = self.sender.send(event.clone());
        let _ = self.committed_sender.send(CommittedRealtimeEvent {
            event: event.clone(),
            command_id: receipt.command_id,
            leader_id: receipt.leader_id,
            commit_index: receipt.commit_index,
        });
        event
    }

    fn next_event(&self, kind: &'static str) -> RealtimeEvent {
        RealtimeEvent {
            id: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            kind: kind.to_owned(),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.sender.subscribe()
    }

    pub fn subscribe_committed(&self) -> broadcast::Receiver<CommittedRealtimeEvent> {
        self.committed_sender.subscribe()
    }
}
