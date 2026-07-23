use bearust::cluster_raft_runtime::construct_raft_with_id;
use bearust::control_plane::repository;

/// Construction smoke test for deterministic three-node IDs. This verifies
/// the durable adapters can be attached to three independent Raft handles;
/// election is intentionally not asserted because the network listener is not
/// connected to a Raft registry in this milestone.
#[tokio::test]
async fn three_node_raft_handles_construct_and_shutdown() {
    let mut handles = Vec::new();
    for id in 1..=3u64 {
        let pool = repository::connect("sqlite::memory:")
            .await
            .unwrap();
        repository::migrate(&pool).await.unwrap();
        let raft = construct_raft_with_id(pool, format!("node-{id}"), b"test-secret-raft", id)
            .await
            .unwrap();
        handles.push(raft);
    }
    assert_eq!(handles.len(), 3);
    for raft in &handles {
        raft.shutdown().await.unwrap();
    }
}
