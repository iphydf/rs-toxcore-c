//! Minimal end-to-end blob transfer test using MerkleToxNode with VirtualHub.

use merkle_tox_core::cas::{BlobInfo, BlobStatus};
use merkle_tox_core::clock::{ManualTimeProvider, TimeProvider};
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, NodeHash, Permissions, PhysicalDeviceSk,
};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::testing::{InMemoryStore, SimulatedTransport, TestIdentity, VirtualHub};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn blob_transfer_completes_between_two_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("merkle_tox_core=debug")
        .with_test_writer()
        .try_init();

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let hub = Arc::new(VirtualHub::new(tp.clone()));
    let conv_id = ConversationId::from([0x42u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);

    let ids = vec![TestIdentity::new(), TestIdentity::new()];

    let mut nodes = Vec::new();
    let mut receivers = Vec::new();

    for (i, id) in ids.iter().enumerate() {
        let rx = hub.register(id.device_pk);
        let transport = SimulatedTransport::new(id.device_pk, hub.clone());
        let store = InMemoryStore::new();
        store
            .put_conversation_key(&conv_id, 0, k_conv.clone())
            .unwrap();

        let mut engine = MerkleToxEngine::with_sk(
            id.device_pk,
            id.master_pk,
            PhysicalDeviceSk::from(id.device_sk.to_bytes()),
            StdRng::seed_from_u64(i as u64),
            tp.clone(),
        );

        for other_id in &ids {
            engine
                .identity_manager
                .add_member(conv_id, other_id.master_pk, 1, 0);
            let cert = other_id.make_device_cert_for(Permissions::ALL, i64::MAX, conv_id);
            let ctx = merkle_tox_core::identity::CausalContext::global();
            engine
                .identity_manager
                .authorize_device(
                    &ctx,
                    conv_id,
                    other_id.master_pk,
                    &cert,
                    0,
                    0,
                    NodeHash::from([0u8; 32]),
                )
                .unwrap();
        }

        engine.load_conversation_state(conv_id, &store).unwrap();

        let node = MerkleToxNode::new(engine, transport, store, tp.clone());
        nodes.push(node);
        receivers.push(rx);
    }

    // Sync nodes
    for i in 0..2 {
        let peer_pk = ids[1 - i].device_pk;
        let n = &mut nodes[i];
        let effects = n.engine.start_sync(conv_id, Some(peer_pk), &n.store);
        let now = n.time_provider.now_instant();
        let now_ms = n.time_provider.now_system_ms() as u64;
        let mut wakeup = now;
        let _ = n.process_effects(effects, now, now_ms, &mut wakeup);
    }

    // Run initial DAG sync
    for _ in 0..200 {
        hub.poll();
        for i in 0..2 {
            while let Ok((from, data)) = receivers[i].try_recv() {
                nodes[i].handle_packet(from, &data);
            }
            nodes[i].poll();
        }
        tp.advance(Duration::from_millis(10));
    }

    // Create blob on node 0
    let blob_size = 64 * 1024u64;
    let blob_data: Vec<u8> = (0..blob_size as usize).map(|i| (i % 251) as u8).collect();
    let blob_hash = NodeHash::from(
        merkle_tox_core::cas::ChunkMerkleTree::from_chunks(
            blob_data.chunks(merkle_tox_core::cas::CHUNK_SIZE as usize),
        )
        .root(),
    );

    nodes[0]
        .store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size: blob_size,
            status: BlobStatus::Available,
            received_mask: None,
            decryption_key: None,
        })
        .unwrap();
    nodes[0]
        .store
        .put_chunk(&conv_id, &blob_hash, 0, &blob_data, None)
        .unwrap();

    // Author blob content node
    {
        let n = &mut nodes[0];
        let effects = n
            .engine
            .author_node(
                conv_id,
                Content::Blob {
                    hash: blob_hash,
                    name: "test.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    size: blob_size,
                    metadata: tox_proto::BoundedBytes::new(),
                },
                vec![],
                &n.store,
            )
            .unwrap();
        let now = tp.now_instant();
        let now_ms = tp.now_system_ms() as u64;
        let mut wakeup = now;
        n.process_effects(effects, now, now_ms, &mut wakeup)
            .unwrap();
    }

    // Run transfer loop
    let transfer_start = tp.now_instant();
    let timeout = Duration::from_secs(30);

    for tick in 0..3000 {
        hub.poll();
        for i in 0..2 {
            while let Ok((from, data)) = receivers[i].try_recv() {
                nodes[i].handle_packet(from, &data);
            }
            nodes[i].poll();
        }

        if tick % 100 == 0 {
            let bob_info = nodes[1].store.get_blob_info(&blob_hash);
            let push_count = nodes[0].engine.push_streams.len();
            let syncs = nodes[1].engine.blob_syncs.len();
            println!(
                "tick {}: bob={:?} push={} syncs={}",
                tick,
                bob_info.as_ref().map(|i| format!("{:?}", i.status)),
                push_count,
                syncs,
            );
        }

        if nodes[1].store.has_blob(&blob_hash) {
            println!("Blob transfer completed at tick {}", tick);
            return;
        }

        if tp.now_instant().duration_since(transfer_start) > timeout {
            break;
        }
        tp.advance(Duration::from_millis(10));
    }

    let bob_info = nodes[1].store.get_blob_info(&blob_hash);
    let push_count = nodes[0].engine.push_streams.len();
    let syncs = nodes[1].engine.blob_syncs.len();
    panic!(
        "Blob transfer timed out. bob={:?} push={} syncs={}",
        bob_info.map(|i| format!("{:?}", i.status)),
        push_count,
        syncs,
    );
}
