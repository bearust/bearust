use chrono::{SecondsFormat, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

/// Process-local event fan-out used to invalidate connected control-plane UIs.
///
/// Events are intentionally small and contain no request or credential data.
pub struct RealtimeHub {
    sender: broadcast::Sender<RealtimeEvent>,
    sequence: AtomicU64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RealtimeEvent {
    pub id: u64,
    pub kind: String,
    pub created_at: String,
}

impl RealtimeHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            sequence: AtomicU64::new(0),
        }
    }

    pub fn publish(&self, kind: &'static str) -> RealtimeEvent {
        let event = RealtimeEvent {
            id: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            kind: kind.to_owned(),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let _ = self.sender.send(event.clone());
        event
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.sender.subscribe()
    }
}
