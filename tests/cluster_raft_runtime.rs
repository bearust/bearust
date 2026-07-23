use bearust::cluster_raft::BearustRaftConfig;

/// This smoke test locks the OpenRaft 0.9.21 integration boundary in place.
/// It deliberately does not instantiate a node: no durable SQLx adapters are
/// available yet, and a fake adapter would invalidate the recovery contract.
#[test]
fn openraft_runtime_requires_durable_adapter_set() {
    fn assert_config<C: openraft::RaftTypeConfig<NodeId = u64>>() {}
    assert_config::<BearustRaftConfig>();
    assert_eq!(std::mem::size_of::<BearustRaftConfig>(), 0);
}
