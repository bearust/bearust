use chrono::{SecondsFormat, Utc};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Process-local event fan-out used to invalidate connected control-plane UIs.
///
/// Events are intentionally small and contain no request or credential data.
pub struct RealtimeHub {
    sender: broadcast::Sender<RealtimeEvent>,
    committed_sender: broadcast::Sender<CommittedRealtimeEvent>,
    sequence: AtomicU64,
    /// Identifies this process's sequence space. Event ids restart with the
    /// process, so a reconnecting client's id is only meaningful when its
    /// epoch matches.
    epoch: String,
    /// Bounded history of recent events for `Last-Event-ID` replay.
    history: Mutex<VecDeque<RealtimeEvent>>,
}

/// Number of recent events kept for reconnect replay.
pub const REPLAY_CAPACITY: usize = 512;

/// Outcome of resolving a client's last seen event id.
#[derive(Debug, PartialEq, Eq)]
pub enum Replay {
    /// The client had no prior id; nothing to replay.
    Fresh,
    /// Every missed event is still retained and is returned in order.
    Events(Vec<RealtimeEvent>),
    /// The id belongs to another process or predates the retained history;
    /// the client must reload current state.
    Gap,
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
            epoch: Uuid::new_v4().simple().to_string()[..12].to_owned(),
            history: Mutex::new(VecDeque::with_capacity(REPLAY_CAPACITY)),
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
        // Allocate the id and record history under one lock so the history
        // stays ordered by id even when publishers race.
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let event = RealtimeEvent {
            id: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            kind: kind.to_owned(),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        if history.len() == REPLAY_CAPACITY {
            history.pop_front();
        }
        history.push_back(event.clone());
        event
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The public SSE id for an event: `<epoch>:<sequence>`.
    pub fn event_id(&self, event: &RealtimeEvent) -> String {
        format!("{}:{}", self.epoch, event.id)
    }

    /// Resolve a client's `Last-Event-ID` into the events it missed.
    pub fn replay_since(&self, last_event_id: Option<&str>) -> Replay {
        let Some(last) = last_event_id.map(str::trim).filter(|v| !v.is_empty()) else {
            return Replay::Fresh;
        };
        let Some((epoch, seq)) = last.split_once(':') else {
            return Replay::Gap;
        };
        let Ok(seq) = seq.parse::<u64>() else {
            return Replay::Gap;
        };
        if epoch != self.epoch || seq > self.sequence.load(Ordering::Relaxed) {
            return Replay::Gap;
        }
        let history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // The client must have seen the event just before the oldest one we
        // still hold; otherwise something fell out of the window.
        let oldest = history.front().map_or(seq + 1, |event| event.id);
        if seq + 1 < oldest {
            return Replay::Gap;
        }
        Replay::Events(history.iter().filter(|e| e.id > seq).cloned().collect())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.sender.subscribe()
    }

    pub fn subscribe_committed(&self) -> broadcast::Receiver<CommittedRealtimeEvent> {
        self.committed_sender.subscribe()
    }
}
