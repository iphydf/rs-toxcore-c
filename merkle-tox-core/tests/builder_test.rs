use merkle_tox_core::builder::NodeBuilder;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{Content, ControlAction, KConv, LogicalIdentityPk, NodeAuth, NodeMac};

#[test]
fn test_group_genesis_pow() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let creator_pk = LogicalIdentityPk::from(sk.verifying_key().to_bytes());
    let node =
        NodeBuilder::new_group_genesis("Test Room".to_string(), creator_pk, 0, 123456789, &sk);

    assert!(node.validate_pow());
    if let Content::Control(ControlAction::Genesis { title, .. }) = node.content {
        assert_eq!(title, "Test Room");
    } else {
        panic!("Wrong content type");
    }
}

#[test]
fn test_1on1_genesis() {
    let pk_a = LogicalIdentityPk::from([1u8; 32]);
    let pk_b = LogicalIdentityPk::from([2u8; 32]);
    let keys = ConversationKeys::derive(&KConv::from([0u8; 32]));

    let node1 = NodeBuilder::new_1on1_genesis(pk_a, pk_b, &keys);
    let node2 = NodeBuilder::new_1on1_genesis(pk_b, pk_a, &keys);

    assert_eq!(
        node1.hash(),
        node2.hash(),
        "Genesis node should be deterministic and commutative"
    );
    assert_eq!(node1.parents.len(), 0);

    // MAC check
    if let NodeAuth::Mac(mac) = node1.authentication {
        assert_ne!(mac, NodeMac::from([0u8; 32]));
    } else {
        panic!("Should have MAC");
    }
}

// end of file
