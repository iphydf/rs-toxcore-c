//! Adversarial coverage for `Content::HistoryExport` permission gating.
//!
//! `HistoryExport` nodes distribute `K_export` (the blob-decryption
//! key) to every authorised device in a conversation, and on receipt
//! trigger a `BlobQuery` out to the swarm. Both side-effects are
//! admin-gated semantically — but the verification layer's content
//! permission table (`verification.rs`) originally listed
//! `HistoryExport` alongside `Text` / `Blob` as MESSAGE-only. Any
//! authorised MESSAGE-level device could therefore author a
//! `HistoryExport`, forcing peers to fetch attacker-chosen blobs.
//!
//! The fix raises the required permission for `Content::HistoryExport`
//! to `ADMIN` in that table. This test confirms it.

use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, EphemeralSigningPk, EphemeralX25519Pk, NodeHash, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_signed_content_node,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

fn setup_room() -> (TestRoom, MerkleToxEngine, InMemoryStore) {
    let room = TestRoom::new(2);
    let store = InMemoryStore::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        room.identities[0].device_pk,
        room.identities[0].master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );
    room.setup_engine(&mut engine, &store);
    if let Some(genesis) = &room.genesis_node {
        let effects = engine
            .handle_node(room.conv_id, genesis.clone(), &store, None)
            .unwrap();
        apply_effects(effects, &store);
    }
    (room, engine, store)
}

fn get_all_heads(
    store: &InMemoryStore,
    conv_id: &merkle_tox_core::dag::ConversationId,
) -> Vec<NodeHash> {
    let mut heads: Vec<NodeHash> = store.get_heads(conv_id);
    for admin_head in store.get_admin_heads(conv_id) {
        if !heads.contains(&admin_head) {
            heads.push(admin_head);
        }
    }
    heads
}

fn make_history_export(blob_hash: NodeHash) -> Content {
    Content::HistoryExport {
        blob_hash,
        blob_size: tox_proto::Untrusted::new(65_536),
        ephemeral_pk: EphemeralX25519Pk::from([0u8; 32]),
        wrapped_keys: tox_proto::BoundedVec::new(),
    }
}

/// §HE-1 — A `HistoryExport` authored by a device holding only
/// `MESSAGE` permission must fail the permission gate at verification
/// time, so receivers never register the blob or emit a `BlobQuery`.
#[test]
fn test_non_admin_cannot_author_history_export() {
    let (room, mut engine, store) = setup_room();

    // Add Charlie as a fresh member with MESSAGE-only permissions.
    let charlie = TestIdentity::new();
    engine
        .identity_manager
        .add_member(room.conv_id, charlie.master_pk, 1, 0);
    charlie.authorize_in_engine(&mut engine, room.conv_id, Permissions::MESSAGE, i64::MAX);
    merkle_tox_core::testing::register_test_ephemeral_key(
        &mut engine,
        &room.keys,
        &charlie.device_pk,
    );
    engine
        .peer_ephemeral_signing_keys
        .insert((charlie.device_pk, 0), EphemeralSigningPk::from([0u8; 32]));

    // Charlie tries to author a HistoryExport. Gathering heads and a
    // fresh rank mirrors the production author path.
    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = heads
        .iter()
        .filter_map(|h| store.get_node(h))
        .map(|n| n.topological_rank)
        .max()
        .unwrap_or(0);
    let node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        charlie.master_pk,
        charlie.device_pk,
        heads,
        make_history_export(NodeHash::from([0xAAu8; 32])),
        parent_rank + 1,
        2,
        3000,
    );

    let result = engine.handle_node(room.conv_id, node, &store, None);
    match result {
        Ok(effects) => {
            let verified_as_valid = effects
                .iter()
                .any(|e| matches!(e, merkle_tox_core::engine::Effect::WriteStore(_, _, true)));
            assert!(
                !verified_as_valid,
                "HistoryExport authored by a MESSAGE-only device must \
                 not be marked verified — otherwise peers would \
                 register the attacker's blob hash and fetch it"
            );
        }
        Err(e) => {
            // Permission-denied error is the expected rejection.
            assert!(
                format!("{}", e).contains("permission") || format!("{}", e).contains("Permission"),
                "expected permission-related rejection, got: {}",
                e,
            );
        }
    }
}

/// §HE-3 — A HistoryExport declaring an absurd `blob_size` (e.g.
/// `u64::MAX`) must not register a blob_syncs entry, even when the
/// authoring admin is legitimate. The blob_size value flows into
/// receiver buffer allocation (testing/store.rs:443:
/// `*buffer = vec![0u8; info.size as usize]`); without a clamp at
/// the construction boundary, a compromised admin could OOM every
/// peer in their conversation by signing a single HistoryExport.
/// This is the type-system gate the audit pinned: peer-supplied
/// (or admin-supplied) sizes must be bounded by `MAX_BLOB_SIZE`
/// before they can drive any allocation.
#[test]
fn test_history_export_with_oversized_blob_size_is_rejected() {
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];

    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = heads
        .iter()
        .filter_map(|h| store.get_node(h))
        .map(|n| n.topological_rank)
        .max()
        .unwrap_or(0);
    let attacker_blob = NodeHash::from([0xDEu8; 32]);
    let oversized = Content::HistoryExport {
        blob_hash: attacker_blob,
        blob_size: tox_proto::Untrusted::new(u64::MAX),
        ephemeral_pk: EphemeralX25519Pk::from([0u8; 32]),
        wrapped_keys: tox_proto::BoundedVec::new(),
    };
    let node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads,
        oversized,
        parent_rank + 1,
        2,
        3000,
    );

    let _ = engine.handle_node(room.conv_id, node, &store, None);

    assert!(
        !engine.blob_syncs.contains_key(&attacker_blob),
        "HistoryExport with oversized blob_size must be dropped at \
         the BlobInfo construction boundary — receiver allocates \
         buffers of `info.size`, so an unclamped value is a one-shot \
         OOM amplifier signed by a single admin",
    );
}

/// §HE-2 — The founder (admin) must still be able to author a
/// HistoryExport. Regression guard against the fix being "reject
/// everything".
#[test]
fn test_admin_can_still_author_history_export() {
    let (room, mut engine, store) = setup_room();
    let alice = &room.identities[0];

    let heads = get_all_heads(&store, &room.conv_id);
    let parent_rank = heads
        .iter()
        .filter_map(|h| store.get_node(h))
        .map(|n| n.topological_rank)
        .max()
        .unwrap_or(0);
    let node = create_signed_content_node(
        &room.conv_id,
        &room.keys,
        alice.master_pk,
        alice.device_pk,
        heads,
        make_history_export(NodeHash::from([0xBBu8; 32])),
        parent_rank + 1,
        2,
        3000,
    );

    let effects = engine
        .handle_node(room.conv_id, node, &store, None)
        .expect("admin-authored HistoryExport must succeed");
    let verified = effects
        .iter()
        .any(|e| matches!(e, merkle_tox_core::engine::Effect::WriteStore(_, _, true)));
    assert!(
        verified,
        "admin-authored HistoryExport must be marked verified — the \
         fix must not regress to blanket-rejection",
    );
}
