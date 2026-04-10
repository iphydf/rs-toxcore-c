pub mod cas;
pub mod gateway;
pub mod hub;
pub mod identity;
pub mod store;

pub use cas::{create_available_blob_info, create_blob_info};
pub use gateway::MerkleToxGateway;
pub use hub::{NodeTrafficCounters, SimulatedTransport, TrafficSnapshot, VirtualHub};
pub use identity::{
    TestIdentity, TestRoom, create_admin_node, create_dummy_node, create_msg,
    create_signed_content_node, make_cert, random_signing_key, register_test_ephemeral_key,
    sign_admin_node, sign_content_node, sign_content_node_with_key, test_ephemeral_signing_key,
    test_node, test_pack_content_keys, transfer_ephemeral_keys,
};
pub use store::{InMemoryStore, ManagedStore, delegate_store};

/// Create a Genesis node with valid proof-of-work for testing.
/// Uses v2 PoW formula (nonce inside genesis action).
pub fn create_genesis_pow(
    conv_id: &crate::dag::ConversationId,
    alice: &TestIdentity,
    title: &str,
) -> crate::dag::MerkleNode {
    let creator_pk = alice.master_pk;
    let mut node = crate::dag::MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_sk.verifying_key().to_bytes().into(),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: crate::dag::Content::Control(crate::dag::ControlAction::Genesis {
            title: title.to_string(),
            creator_pk,
            permissions: crate::dag::Permissions::all(),
            flags: 0,
            created_at: 1000,
            pow_nonce: 0,
        }),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: crate::dag::NodeAuth::Signature(crate::dag::Ed25519Signature::from(
            [0u8; 64],
        )),
        pow_nonce: 0,
    };
    // Mine v2 PoW: iterate pow_nonce inside genesis action
    let mut nonce = 0u64;
    loop {
        if let crate::dag::Content::Control(crate::dag::ControlAction::Genesis {
            pow_nonce, ..
        }) = &mut node.content
        {
            *pow_nonce = nonce;
        }
        if let crate::dag::Content::Control(ref action) = node.content
            && crate::dag::validate_pow_v2(creator_pk.as_bytes(), action)
        {
            break;
        }
        nonce += 1;
    }
    // Sign after mining (signature covers mined action content)
    sign_admin_node(&mut node, conv_id, &alice.device_sk);
    node
}

pub fn get_node_from_effects(effects: Vec<crate::engine::Effect>) -> crate::dag::MerkleNode {
    effects
        .into_iter()
        .find_map(|e| {
            if let crate::engine::Effect::WriteStore(_, node, _) = e {
                Some(node)
            } else {
                None
            }
        })
        .expect("No node found in effects")
}

/// Returns all nodes from effects in order.
pub fn get_all_nodes_from_effects(
    effects: &[crate::engine::Effect],
) -> Vec<crate::dag::MerkleNode> {
    effects
        .iter()
        .filter_map(|e| {
            if let crate::engine::Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect()
}

pub fn is_verified_in_effects(effects: &[crate::engine::Effect]) -> bool {
    effects.iter().any(|e| {
        if let crate::engine::Effect::WriteStore(_, _, verified) = e {
            *verified
        } else {
            false
        }
    })
}

pub fn has_verified_in_effects(effects: &[crate::engine::Effect]) -> bool {
    is_verified_in_effects(effects)
}

/// Transfers wire nodes from authoring effects into a receiving store.
/// Call this before `handle_node` so encrypt-then-sign verification can
/// look up the wire node's auth data (ciphertext) to verify the signature.
pub fn transfer_wire_nodes(effects: &[crate::engine::Effect], store: &dyn crate::sync::NodeStore) {
    for effect in effects {
        if let crate::engine::Effect::WriteWireNode(cid, hash, node) = effect {
            let _ = store.put_wire_node(cid, hash, node.clone());
        }
    }
}

pub fn apply_effects(effects: Vec<crate::engine::Effect>, store: &dyn crate::sync::NodeStore) {
    for effect in effects {
        match effect {
            crate::engine::Effect::WriteStore(cid, node, verified) => {
                let _ = store.put_node(&cid, node, verified);
            }
            crate::engine::Effect::WriteWireNode(cid, hash, node) => {
                let _ = store.put_wire_node(&cid, &hash, node);
            }
            crate::engine::Effect::DeleteWireNode(cid, hash) => {
                let _ = store.remove_wire_node(&cid, &hash);
            }
            crate::engine::Effect::WriteRatchetKey(cid, hash, key, epoch_id) => {
                let _ = store.put_ratchet_key(&cid, &hash, key, epoch_id);
            }
            crate::engine::Effect::DeleteRatchetKey(cid, hash) => {
                let _ = store.remove_ratchet_key(&cid, &hash);
            }
            crate::engine::Effect::UpdateHeads(cid, heads, is_admin) => {
                if is_admin {
                    let _ = store.set_admin_heads(&cid, heads);
                } else {
                    let _ = store.set_heads(&cid, heads);
                }
            }
            crate::engine::Effect::WriteConversationKey(cid, epoch, key) => {
                let _ = store.put_conversation_key(&cid, epoch, key);
            }
            crate::engine::Effect::WriteEpochMetadata(cid, count, time) => {
                let _ = store.update_epoch_metadata(&cid, count, time);
            }
            _ => {}
        }
    }
}
