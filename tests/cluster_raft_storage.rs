use bearust::cluster_raft::ConfigCommand;
use bearust::cluster_raft_storage::SqlxRaftStorage;
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use uuid::Uuid;

async fn storage() -> SqlxRaftStorage {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    SqlxRaftStorage::new(pool, "node-a").unwrap()
}

fn command() -> ConfigCommand {
    ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: ProxyHost {
            id: 11,
            name: "example".into(),
            domain: "example.test".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 8080,
            tls_mode: "disabled".into(),
            certificate_id: None,
            enabled: true,
        },
    }
}

#[tokio::test]
async fn persists_vote_command_log_and_snapshot_round_trip() {
    let storage = storage().await;
    assert!(storage.raft_id().await.unwrap() > 0);
    storage.save_vote(4, Some("node-b")).await.unwrap();
    assert_eq!(storage.load_vote().await.unwrap().unwrap().current_term, 4);

    let command = command();
    storage.append_command(1, 4, 1, &command).await.unwrap();
    let entries = storage.load_entries(1).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        SqlxRaftStorage::decode_command(&entries[0])
            .await
            .unwrap()
            .command_id(),
        command.command_id()
    );

    storage.save_snapshot(1, 4, b"snapshot").await.unwrap();
    let snapshot = storage.load_snapshot().await.unwrap().unwrap();
    assert_eq!(snapshot.snapshot_index, 1);
    assert_eq!(snapshot.payload, b"snapshot");
}

#[tokio::test]
async fn truncation_and_purge_are_scoped_to_node() {
    let storage = storage().await;
    let first = command();
    storage.append_command(1, 1, 1, &first).await.unwrap();
    let second = command();
    storage.append_command(2, 1, 1, &second).await.unwrap();
    storage.truncate(2).await.unwrap();
    assert_eq!(storage.load_entries(1).await.unwrap().len(), 1);
    storage.purge(1).await.unwrap();
    assert!(storage.load_entries(1).await.unwrap().is_empty());
}
