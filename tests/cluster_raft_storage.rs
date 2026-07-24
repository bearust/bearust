use bearust::cluster_raft::ConfigCommand;
use bearust::cluster_raft_storage::SqlxRaftStorage;
use bearust::control_plane::models::ProxyHost;
use bearust::control_plane::repository;
use openraft::storage::RaftStateMachine;
use openraft::RaftSnapshotBuilder;
use openraft::{Entry, EntryPayload, LogId};
use sqlx::Row;
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

#[tokio::test]
async fn snapshot_install_preserves_applied_command_provenance() {
    let source_pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&source_pool).await.unwrap();
    let mut source = SqlxRaftStorage::new(source_pool, "node-a").unwrap();
    let command = command();
    let command_id = command.command_id().to_string();
    let original_log_id = LogId::new(openraft::CommittedLeaderId::new(3, 2), 7);
    source
        .apply(vec![Entry {
            log_id: original_log_id,
            payload: EntryPayload::Normal(command.clone()),
        }])
        .await
        .unwrap();
    let duplicate_log_id = LogId::new(openraft::CommittedLeaderId::new(4, 3), 8);
    assert_eq!(
        source
            .apply(vec![Entry {
                log_id: duplicate_log_id,
                payload: EntryPayload::Normal(command),
            }])
            .await
            .unwrap(),
        vec![bearust::cluster_raft::CommandResult::Duplicate]
    );
    let mut builder = source.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.unwrap();
    let snapshot_meta = snapshot.meta.clone();

    let target_pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&target_pool).await.unwrap();
    let mut target = SqlxRaftStorage::new(target_pool.clone(), "node-b").unwrap();
    target
        .install_snapshot(&snapshot_meta, snapshot.snapshot)
        .await
        .unwrap();

    let receipt = repository::load_raft_command_receipt(&target_pool, &command_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.log_index, original_log_id.index as i64);
    assert_eq!(receipt.leader_id, original_log_id.leader_id.node_id as i64);
    assert!(
        !repository::record_raft_command_id(&target_pool, &command_id)
            .await
            .unwrap(),
        "snapshot install must preserve applied command identity"
    );
}

#[tokio::test]
async fn snapshot_bounds_many_receipts_and_keeps_the_newest_provenance() {
    const RECEIPT_COUNT: i64 = 4_000;

    let source_pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&source_pool).await.unwrap();
    let mut source = SqlxRaftStorage::new(source_pool.clone(), "node-a").unwrap();
    let mut tx = source_pool.begin().await.unwrap();
    let byte_pressure_applied_at = format!("2026-07-24T00:00:00Z-{}", "x".repeat(1_024));
    for index in 1..=RECEIPT_COUNT {
        let command_id = Uuid::from_u128(index as u128).to_string();
        sqlx::query(
            "INSERT INTO raft_command_ids(command_id,applied_at) VALUES(?,?)
             ON CONFLICT(command_id) DO NOTHING",
        )
        .bind(&command_id)
        .bind(&byte_pressure_applied_at)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO raft_command_receipts(command_id,log_index,leader_id,applied_at)
             VALUES(?,?,?,?)",
        )
        .bind(command_id)
        .bind(index)
        .bind(1_i64)
        .bind(&byte_pressure_applied_at)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    repository::save_raft_committed_state(&source_pool, "node-a", RECEIPT_COUNT, 1, 1)
        .await
        .unwrap();

    let mut builder = source.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.unwrap();
    let snapshot_meta = snapshot.meta.clone();
    let snapshot_bytes = snapshot.snapshot.get_ref().clone();
    assert!(snapshot_bytes.len() <= repository::MAX_RAFT_PAYLOAD_BYTES);
    assert!(snapshot_bytes.len() <= bearust::cluster_raft::MAX_RPC_FRAME_BYTES);
    let source_receipt_count: i64 =
        sqlx::query("SELECT COUNT(*) AS count FROM raft_command_receipts")
            .fetch_one(&source_pool)
            .await
            .unwrap()
            .get("count");
    assert_eq!(
        source_receipt_count, RECEIPT_COUNT,
        "snapshot truncation must not prune the durable source ledger"
    );

    let target_pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&target_pool).await.unwrap();
    let mut target = SqlxRaftStorage::new(target_pool.clone(), "node-b").unwrap();
    target
        .install_snapshot(
            &snapshot_meta,
            Box::new(std::io::Cursor::new(snapshot_bytes)),
        )
        .await
        .unwrap();

    let target_receipt_count: i64 =
        sqlx::query("SELECT COUNT(*) AS count FROM raft_command_receipts")
            .fetch_one(&target_pool)
            .await
            .unwrap()
            .get("count");
    assert!(target_receipt_count < RECEIPT_COUNT);
    assert!(
        target_receipt_count <= bearust::cluster_raft_storage::MAX_SNAPSHOT_COMMAND_RECEIPTS as i64
    );
    let oldest_retained_index: i64 =
        sqlx::query("SELECT MIN(log_index) AS log_index FROM raft_command_receipts")
            .fetch_one(&target_pool)
            .await
            .unwrap()
            .get("log_index");
    assert_eq!(
        oldest_retained_index,
        RECEIPT_COUNT - target_receipt_count + 1,
        "the byte budget must retain one contiguous newest receipt window"
    );
    assert!(
        repository::load_raft_command_receipt(
            &target_pool,
            &Uuid::from_u128(RECEIPT_COUNT as u128).to_string(),
        )
        .await
        .unwrap()
        .is_some(),
        "the newest receipt must survive bounded snapshot retention"
    );
    assert!(
        repository::load_raft_command_receipt(&target_pool, &Uuid::from_u128(1).to_string())
            .await
            .unwrap()
            .is_none(),
        "receipts outside the newest bounded window must be omitted"
    );
}
