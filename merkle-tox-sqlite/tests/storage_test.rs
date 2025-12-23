use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::{GlobalStore, NodeStore, ReconciliationStore, SyncRange};
use merkle_tox_sqlite::Storage;

#[test]
fn test_insert_and_get_node() {
    let storage = Storage::open_in_memory().expect("Failed to open storage");
    let conv_id = ConversationId::from([0u8; 32]);

    let node = MerkleNode {
        parents: vec![NodeHash::from([0u8; 32])],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 1,
        network_timestamp: 123456789,
        content: Content::Text("Persistence test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    let hash = node.hash();
    storage
        .put_node(&conv_id, node.clone(), true)
        .expect("Failed to insert node");

    let retrieved = storage.get_node(&hash);
    assert_eq!(retrieved, Some(node));
}

#[test]
fn test_edges_insertion() {
    let storage = Storage::open_in_memory().expect("Failed to open storage");
    let conv_id = ConversationId::from([0u8; 32]);

    let parent_hash = [1u8; 32];
    let node = MerkleNode {
        parents: vec![NodeHash::from(parent_hash)],
        author_pk: LogicalIdentityPk::from([2u8; 32]),
        sender_pk: PhysicalDevicePk::from([2u8; 32]),
        sequence_number: 1,
        topological_rank: 2,
        network_timestamp: 123456789,
        content: Content::Text("Child node".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    storage
        .put_node(&conv_id, node.clone(), true)
        .expect("Failed to insert node");

    // Verify edge exists
    let conn = storage.connection().lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT child_hash FROM edges WHERE parent_hash = ?1")
        .unwrap();
    let mut rows = stmt.query(rusqlite::params![parent_hash]).unwrap();
    let first_row = rows.next().unwrap().expect("Edge not found");
    let child_hash: [u8; 32] = first_row.get(0).unwrap();
    assert_eq!(NodeHash::from(child_hash), node.hash());
}

#[test]
fn test_reconciliation_store() {
    let storage = Storage::open_in_memory().expect("Failed to open storage");
    let conv_id = ConversationId::from([1u8; 32]);
    let range = SyncRange {
        epoch: 1,
        min_rank: 100,
        max_rank: 200,
    };
    let sketch_data = vec![1, 2, 3, 4, 5];

    storage
        .put_sketch(&conv_id, &range, &sketch_data)
        .expect("Failed to put sketch");

    let retrieved = storage
        .get_sketch(&conv_id, &range)
        .expect("Failed to get sketch");
    assert_eq!(retrieved, Some(sketch_data));

    let unknown_range = SyncRange {
        epoch: 1,
        min_rank: 500,
        max_rank: 600,
    };
    let retrieved_none = storage
        .get_sketch(&conv_id, &unknown_range)
        .expect("Failed to get sketch");
    assert_eq!(retrieved_none, None);
}

#[test]
fn test_global_store() {
    let storage = Storage::open_in_memory().expect("Failed to open storage");

    assert_eq!(storage.get_global_offset(), None);

    storage
        .set_global_offset(1234)
        .expect("Failed to set global offset");
    assert_eq!(storage.get_global_offset(), Some(1234));

    storage
        .set_global_offset(-5678)
        .expect("Failed to set global offset");
    assert_eq!(storage.get_global_offset(), Some(-5678));
}
