use bearust::cluster_raft::{CommandError, ConfigCommand, ReplicatedConfig};
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use uuid::Uuid;

fn host() -> ProxyHost {
    ProxyHost {
        id: 42,
        name: "web".into(),
        domain: "web.example.test".into(),
        upstream_host: "127.0.0.1".into(),
        upstream_port: 8080,
        tls_mode: "disabled".into(),
        certificate_id: None,
        enabled: true,
    }
}

#[test]
fn command_round_trip_preserves_id_and_rejects_oversized_payloads() {
    let id = Uuid::new_v4();
    let command = ConfigCommand::CreateProxyHost {
        command_id: id,
        host: host(),
    };
    let payload = command.to_payload().unwrap();
    assert!(payload.len() <= bearust::cluster_raft::MAX_COMMAND_BYTES);
    let decoded = ConfigCommand::from_payload(&payload).unwrap();
    assert_eq!(decoded.command_id(), id);

    let oversized = vec![b'x'; bearust::cluster_raft::MAX_COMMAND_BYTES + 1];
    assert!(matches!(
        ConfigCommand::from_payload(&oversized),
        Err(CommandError::PayloadTooLarge)
    ));
}

#[test]
fn command_debug_redacts_mutation_payload() {
    let command = ConfigCommand::UpdateProxyHost {
        command_id: Uuid::new_v4(),
        host_id: 42,
        host: host(),
    };
    let debug = format!("{command:?}");
    assert!(!debug.contains("web.example.test"));
    assert!(debug.contains("UpdateProxyHost"));
}

#[test]
fn state_machine_applies_in_order_and_ignores_duplicate_commands() {
    let id = Uuid::new_v4();
    let command = ConfigCommand::CreateProxyHost {
        command_id: id,
        host: host(),
    };
    let mut state = ReplicatedConfig::default();
    assert!(state.apply(&command).unwrap());
    assert!(!state.apply(&command).unwrap());
    assert_eq!(state.proxy_hosts().len(), 1);

    let snapshot = state.snapshot().unwrap();
    let restored = ReplicatedConfig::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.proxy_hosts().len(), 1);
    assert!(restored.has_applied(id));
}

#[tokio::test]
async fn committed_proxy_host_command_is_applied_atomically_and_idempotently() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let command = ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: host(),
    };

    assert!(repository::apply_raft_command(&pool, &command)
        .await
        .unwrap());
    assert!(!repository::apply_raft_command(&pool, &command)
        .await
        .unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_hosts WHERE id=42")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
