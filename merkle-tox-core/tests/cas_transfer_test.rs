//! Tests for CAS blob transfer correctness.
//!
//! These tests verify that the blob swarm protocol handles seeder discovery
//! correctly and that multi-node transfers complete in a reasonable time.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{LogicalIdentityPk, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::InMemoryStore;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// A node that has blob_info with status Pending (i.e. it is still downloading
/// the blob) should NOT respond to BlobQuery with BlobAvail.  Advertising
/// availability for a blob you cannot fully serve causes requesters to send
/// chunk requests that are silently dropped, wasting FETCH_TIMEOUT (15 s)
/// before the requester retries.
#[test]
fn pending_blob_should_not_advertise_as_available() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let querying_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let store = InMemoryStore::new();

    // Store blob_info with Pending status — this node is still downloading.
    let pending_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(pending_info).unwrap();

    // A peer queries us for this blob.
    let effects = engine
        .handle_message(
            querying_peer,
            ProtocolMessage::BlobQuery(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    // The node should NOT send BlobAvail for a blob it hasn't fully received.
    let sends_blob_avail = effects.iter().any(|e| {
        matches!(e, Effect::SendPacket(_, ProtocolMessage::BlobAvail(_)))
    });

    assert!(
        !sends_blob_avail,
        "Node with Pending blob_info responded to BlobQuery with BlobAvail. \
         This causes the querying peer to add us as a seeder, but we cannot \
         serve most chunks yet, leading to silently dropped BlobReq and 15 s \
         FETCH_TIMEOUT stalls per wasted request."
    );
}

/// A node with Downloading status (has some chunks) SHOULD respond to
/// BlobQuery with BlobAvail that includes its received_mask, enabling
/// chunk-level swarming.
#[test]
fn downloading_blob_should_advertise_with_mask() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let querying_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xCCu8; 32]);
    let store = InMemoryStore::new();

    // Store blob_info with Downloading status and a partial mask.
    let mask = vec![0x05u8]; // chunks 0 and 2
    let downloading_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Downloading,
        received_mask: Some(mask.clone()),
        decryption_key: None,
    };
    store.put_blob_info(downloading_info).unwrap();

    let effects = engine
        .handle_message(
            querying_peer,
            ProtocolMessage::BlobQuery(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    let avail = effects.iter().find_map(|e| {
        if let Effect::SendPacket(_, ProtocolMessage::BlobAvail(info)) = e {
            Some(info.clone())
        } else {
            None
        }
    });

    assert!(
        avail.is_some(),
        "Downloading node should respond to BlobQuery with BlobAvail for swarming"
    );
    assert_eq!(
        avail.unwrap().received_mask,
        Some(mask),
        "BlobAvail from Downloading node should include received_mask"
    );
}

/// A node that has a fully Available blob SHOULD respond to BlobQuery.
/// This is the control case: real seeders must still work.
#[test]
fn available_blob_should_advertise() {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let node_pk = PhysicalDevicePk::from([1u8; 32]);
    let querying_peer = PhysicalDevicePk::from([2u8; 32]);

    let mut engine = MerkleToxEngine::new(
        node_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );

    let blob_hash = NodeHash::from([0xDDu8; 32]);
    let store = InMemoryStore::new();

    let available_info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(available_info).unwrap();

    let effects = engine
        .handle_message(
            querying_peer,
            ProtocolMessage::BlobQuery(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    let sends_blob_avail = effects.iter().any(|e| {
        matches!(e, Effect::SendPacket(_, ProtocolMessage::BlobAvail(_)))
    });

    assert!(
        sends_blob_avail,
        "Node with Available blob_info should respond to BlobQuery with BlobAvail"
    );
}
