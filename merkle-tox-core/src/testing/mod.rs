pub mod cas;
pub mod gateway;
pub mod hub;
pub mod identity;
pub mod store;

pub use cas::{create_available_blob_info, create_blob_data, create_blob_info};
pub use gateway::MerkleToxGateway;
pub use hub::{SimulatedTransport, VirtualHub};
pub use identity::{
    TestIdentity, TestRoom, create_admin_node, create_dummy_node, create_msg,
    create_signed_content_node, make_cert, random_signing_key, sign_admin_node, sign_content_node,
    test_node,
};
pub use store::{InMemoryStore, ManagedStore, delegate_store};

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
            crate::engine::Effect::WriteRatchetKey(cid, hash, key) => {
                let _ = store.put_ratchet_key(&cid, &hash, key);
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
