use merkle_tox_core::dag::{
    Content, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac, PhysicalDevicePk,
};

#[test]
fn test_node_hashing() {
    let node = MerkleNode {
        parents: vec![NodeHash::from([0u8; 32])],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 1,
        network_timestamp: 123456789,
        content: Content::Text("Hello Merkle-Tox".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    let hash1 = node.hash();
    let hash2 = node.hash();

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, NodeHash::from([0u8; 32]));
}

#[test]
fn test_node_serialization_roundtrip() {
    let node = MerkleNode {
        parents: vec![NodeHash::from([0u8; 32]), NodeHash::from([1u8; 32])],
        author_pk: LogicalIdentityPk::from([2u8; 32]),
        sender_pk: PhysicalDevicePk::from([3u8; 32]),
        sequence_number: 42,
        topological_rank: 5,
        network_timestamp: 987654321,
        content: Content::Text("Roundtrip test".to_string()),
        metadata: vec![1, 2, 3],
        authentication: NodeAuth::Mac(NodeMac::from([4u8; 32])),
    };

    let serialized = tox_proto::serialize(&node).expect("Failed to serialize");
    let deserialized: MerkleNode =
        tox_proto::deserialize(&serialized).expect("Failed to deserialize");

    assert_eq!(node, deserialized);
}

// end of file
