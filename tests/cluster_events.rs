use bearust::cluster::{run_cluster_listener, ClusterService};
use bearust::cluster_command::CommitReceipt;
use bearust::cluster_events::{
    encode_cluster_event_rpc, ClusterEventDisposition, ClusterEventEnvelope, ClusterEventError,
    ClusterEventFanout, ClusterEventReceiver, CLUSTER_EVENT_PROTOCOL_VERSION,
    MAX_CLUSTER_EVENT_BYTES,
};
use bearust::cluster_raft::encode_rpc_frame;
use bearust::cluster_raft_runtime::{
    dispatch_authenticated_rpc_with_event_handler, RpcTransportError,
};
use bearust::config::{ClusterConfig, ClusterPeer};
use bearust::control_plane::realtime::{CommittedRealtimeEvent, RealtimeEvent, RealtimeHub};
use chrono::{SecondsFormat, Utc};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use uuid::Uuid;

const SECRET: &str = "01234567890123456789012345678901";

fn committed_event(event_id: u64, commit_index: u64, kind: &str) -> CommittedRealtimeEvent {
    CommittedRealtimeEvent {
        event: RealtimeEvent {
            id: event_id,
            kind: kind.to_string(),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        },
        command_id: Uuid::new_v4(),
        leader_id: 7,
        commit_index,
    }
}

fn envelope(event_id: u64, commit_index: u64, kind: &str) -> ClusterEventEnvelope {
    ClusterEventEnvelope::from_committed(&committed_event(event_id, commit_index, kind), "node-a")
        .unwrap()
}

#[test]
fn event_envelope_is_versioned_bounded_and_redacted() {
    let event = committed_event(4, 19, "proxy_hosts.changed");
    let envelope = ClusterEventEnvelope::from_committed(&event, "node-a").unwrap();
    let encoded = envelope.encode().unwrap();

    assert!(encoded.len() <= MAX_CLUSTER_EVENT_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let fields = value.as_object().unwrap();
    assert_eq!(fields.len(), 7);
    assert_eq!(value["protocol_version"], CLUSTER_EVENT_PROTOCOL_VERSION);
    assert_eq!(value["event_id"], 4);
    assert_eq!(value["command_id"], event.command_id.to_string());
    assert_eq!(value["commit_index"], 19);
    assert_eq!(value["event_type"], "proxy_hosts.changed");
    assert_eq!(value["origin_node_id"], "node-a");
    assert!(value["timestamp"].as_str().is_some());
    assert!(value.get("leader_id").is_none());
    assert!(value.get("event").is_none());
    assert!(!String::from_utf8(encoded.clone())
        .unwrap()
        .contains("secret"));
    assert_eq!(ClusterEventEnvelope::decode(&encoded).unwrap(), envelope);

    let mut unknown_version = value;
    unknown_version["protocol_version"] = serde_json::json!(99);
    assert_eq!(
        ClusterEventEnvelope::decode(&serde_json::to_vec(&unknown_version).unwrap()),
        Err(ClusterEventError::UnsupportedVersion)
    );
    assert_eq!(
        ClusterEventEnvelope::decode(&vec![b'x'; MAX_CLUSTER_EVENT_BYTES + 1]),
        Err(ClusterEventError::PayloadTooLarge)
    );
}

#[tokio::test]
async fn authenticated_event_rpc_rejects_tampered_hmac() {
    let receiver = ClusterEventReceiver::new(Arc::new(RealtimeHub::new(8)));
    let payload = encode_cluster_event_rpc(&envelope(1, 1, "proxy_hosts.changed"), false).unwrap();
    let mut frame = encode_rpc_frame(&payload, SECRET.as_bytes()).unwrap();
    *frame.last_mut().unwrap() ^= 1;

    let result = dispatch_authenticated_rpc_with_event_handler(
        &frame,
        SECRET.as_bytes(),
        "node-b",
        "node-a",
        &receiver,
    )
    .await;

    assert_eq!(result, Err(RpcTransportError::AuthenticationFailed));
}

#[tokio::test]
async fn duplicate_remote_events_are_suppressed_without_leaking_cluster_metadata() {
    let hub = Arc::new(RealtimeHub::new(8));
    let mut local_events = hub.subscribe();
    let receiver = ClusterEventReceiver::new(hub);
    let envelope = envelope(9, 44, "rate_limit.changed");

    assert_eq!(
        receiver
            .accept(envelope.clone(), "node-a", false)
            .await
            .unwrap(),
        ClusterEventDisposition::Accepted
    );
    let event = local_events.recv().await.unwrap();
    assert_eq!(event.kind, "rate_limit.changed");
    let public = serde_json::to_value(event).unwrap();
    assert!(public.get("command_id").is_none());
    assert!(public.get("commit_index").is_none());
    assert!(public.get("origin_node_id").is_none());

    assert_eq!(
        receiver.accept(envelope, "node-a", false).await.unwrap(),
        ClusterEventDisposition::Duplicate
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), local_events.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reconnect_or_commit_gap_triggers_local_resource_catch_up() {
    let hub = Arc::new(RealtimeHub::new(16));
    let mut local_events = hub.subscribe();
    let receiver = ClusterEventReceiver::new(hub);

    receiver
        .accept(envelope(1, 10, "proxy_hosts.changed"), "node-a", false)
        .await
        .unwrap();
    assert_eq!(
        local_events.recv().await.unwrap().kind,
        "proxy_hosts.changed"
    );

    receiver
        .accept(envelope(2, 12, "rate_limit.changed"), "node-a", false)
        .await
        .unwrap();
    let gap_events = [
        local_events.recv().await.unwrap().kind,
        local_events.recv().await.unwrap().kind,
        local_events.recv().await.unwrap().kind,
    ];
    assert!(gap_events.contains(&"proxy_hosts.changed".to_string()));
    assert!(gap_events.contains(&"rate_limit.changed".to_string()));

    receiver
        .accept(envelope(3, 13, "rate_limit.changed"), "node-a", true)
        .await
        .unwrap();
    let reconnect_events = [
        local_events.recv().await.unwrap().kind,
        local_events.recv().await.unwrap().kind,
        local_events.recv().await.unwrap().kind,
    ];
    assert!(reconnect_events.contains(&"proxy_hosts.changed".to_string()));
    assert!(reconnect_events.contains(&"rate_limit.changed".to_string()));
}

async fn reserve_address() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn cluster_config(
    node_id: &str,
    bind: std::net::SocketAddr,
    peers: Vec<ClusterPeer>,
    timeout_seconds: u64,
) -> ClusterConfig {
    ClusterConfig {
        node_id: node_id.to_string(),
        peers,
        bind,
        timeout_seconds,
        auth_token: SECRET.to_string(),
    }
}

#[tokio::test]
async fn committed_events_fan_out_over_the_authenticated_cluster_transport() {
    let node_a_address = reserve_address().await;
    let node_b_address = reserve_address().await;
    let node_a = Arc::new(ClusterService::new(&cluster_config(
        "node-a",
        node_a_address,
        vec![ClusterPeer {
            node_id: "node-b".into(),
            address: node_b_address,
        }],
        1,
    )));
    let node_b = Arc::new(ClusterService::new(&cluster_config(
        "node-b",
        node_b_address,
        vec![ClusterPeer {
            node_id: "node-a".into(),
            address: node_a_address,
        }],
        1,
    )));
    let source_hub = Arc::new(RealtimeHub::new(8));
    let target_hub = Arc::new(RealtimeHub::new(16));
    let mut target_events = target_hub.subscribe();
    node_b.set_event_handler(Arc::new(ClusterEventReceiver::new(target_hub)));

    let (shutdown, shutdown_rx) = watch::channel(false);
    let listener = tokio::spawn(run_cluster_listener(node_b, shutdown_rx));
    tokio::time::sleep(Duration::from_millis(25)).await;
    let fanout = ClusterEventFanout::start(node_a, source_hub.clone(), 4).unwrap();
    source_hub.publish_committed(
        "proxy_hosts.changed",
        &CommitReceipt {
            command_id: Uuid::new_v4(),
            leader_id: 1,
            commit_index: 1,
        },
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if target_events.recv().await.unwrap().kind == "proxy_hosts.changed" {
                break;
            }
        }
    })
    .await
    .expect("cluster invalidation was not delivered");

    fanout.shutdown().await;
    let _ = shutdown.send(true);
    listener.await.unwrap();
}

#[tokio::test]
async fn peer_fan_out_queue_is_bounded_and_never_blocks_publishers() {
    let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_address = blackhole.local_addr().unwrap();
    let blackhole_task = tokio::spawn(async move {
        let (_stream, _) = blackhole.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let node = Arc::new(ClusterService::new(&cluster_config(
        "node-a",
        reserve_address().await,
        vec![ClusterPeer {
            node_id: "node-b".into(),
            address: blackhole_address,
        }],
        1,
    )));
    let hub = Arc::new(RealtimeHub::new(16));
    let fanout = ClusterEventFanout::start(node, hub.clone(), 1).unwrap();

    let started = Instant::now();
    for commit_index in 1..=8 {
        hub.publish_committed(
            "proxy_hosts.changed",
            &CommitReceipt {
                command_id: Uuid::new_v4(),
                leader_id: 1,
                commit_index,
            },
        );
    }
    assert!(started.elapsed() < Duration::from_millis(100));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if fanout.dropped_events() > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded queue did not report overflow");

    fanout.shutdown().await;
    blackhole_task.abort();
}
