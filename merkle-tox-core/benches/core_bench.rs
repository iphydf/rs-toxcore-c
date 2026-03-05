use criterion::{Criterion, criterion_group, criterion_main};
use merkle_tox_core::dag::{
    Content, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::SyncHeads;
use std::hint::black_box;
use tox_proto::{deserialize, serialize};
use tox_reconcile::{IbltSketch, SyncRange, SyncSketch, Tier};

fn make_dummy_node(content: Content) -> MerkleNode {
    MerkleNode {
        parents: tox_proto::bounded_vec![NodeHash::from([1; 32]), NodeHash::from([2; 32])],
        author_pk: LogicalIdentityPk::from([3; 32]),
        sender_pk: PhysicalDevicePk::from([4; 32]),
        sequence_number: 42,
        topological_rank: 10,
        network_timestamp: 123456789,
        content,
        metadata: tox_proto::BoundedBytes::try_from_vec(vec![0; 64])
            .expect("test fixture under MAX_METADATA_SIZE"),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    }
}

fn bench_joiner_hot_path(c: &mut Criterion) {
    let mut g = c.benchmark_group("joiner_ops");

    let text_node = make_dummy_node(Content::Text("History message contents".to_string()));
    let pack_keys = merkle_tox_core::crypto::PackKeys::Exception;
    let wire_node = text_node.pack_wire(&pack_keys, true).unwrap();

    g.bench_function("unpack_wire_exception_text_compressed", |b| {
        b.iter(|| black_box(MerkleNode::unpack_wire_exception(black_box(&wire_node)).unwrap()))
    });

    let large_text = "a".repeat(2048);
    let large_node = make_dummy_node(Content::Text(large_text));
    let wire_large = large_node.pack_wire(&pack_keys, true).unwrap();

    g.bench_function("unpack_wire_exception_large_text_compressed", |b| {
        b.iter(|| black_box(MerkleNode::unpack_wire_exception(black_box(&wire_large)).unwrap()))
    });

    g.finish();
}

fn bench_blob_hot_path(c: &mut Criterion) {
    // The previous microbench measured `bao::encode::outboard` + a bao
    // slice verify, which mapped onto the old per-piece bao proof path.
    // That path has been replaced by the domain-separated ChunkMerkleTree
    // scheme (see `doc/merkle-tox-cas.md` §3); a new bench will land with
    // the ChunkMerkleTree implementation.
    let _ = c;
}

fn bench_merkle_node(c: &mut Criterion) {
    let mut g = c.benchmark_group("merkle_node");

    let text_node = make_dummy_node(Content::Text("Hello, Merkle-Tox!".to_string()));
    g.bench_function("serialize_text_node", |b| {
        b.iter(|| black_box(serialize(black_box(&text_node)).unwrap()))
    });

    let encoded = serialize(&text_node).unwrap();
    g.bench_function("deserialize_text_node", |b| {
        b.iter(|| black_box(deserialize::<MerkleNode>(black_box(&encoded)).unwrap()))
    });

    let blob_node = make_dummy_node(Content::Blob {
        hash: NodeHash::from([7; 32]),
        name: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        size: 1024 * 1024,
        metadata: tox_proto::BoundedBytes::try_from_vec(vec![0; 32])
            .expect("test fixture under MAX_METADATA_SIZE"),
    });
    g.bench_function("serialize_blob_node", |b| {
        b.iter(|| black_box(serialize(black_box(&blob_node)).unwrap()))
    });

    g.finish();
}

fn bench_sync_messages(c: &mut Criterion) {
    let mut g = c.benchmark_group("sync_messages");

    let heads = SyncHeads {
        conversation_id: ConversationId::from([9; 32]),
        heads: tox_proto::BoundedVec::try_from_iter(std::iter::repeat_n(
            NodeHash::from([10; 32]),
            16,
        ))
        .expect("16 < MAX_HEADS_SYNC"),
        flags: 0,
        anchor_hash: None,
    };
    g.bench_function("serialize_sync_heads_16", |b| {
        b.iter(|| black_box(serialize(black_box(&heads)).unwrap()))
    });

    let tier = Tier::Small;
    let mut iblt = IbltSketch::new(tier.cell_count());
    for i in 0..(tier.cell_count() / 2) {
        let mut h = [0u8; 32];
        h[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        iblt.insert(&h);
    }
    let sketch = SyncSketch {
        conversation_id: ConversationId::from([11; 32]),
        cells: tox_proto::BoundedVec::try_from_iter(iblt.into_cells()).expect("Tier-bounded"),
        range: SyncRange {
            min_rank: 0,
            max_rank: 1000,
        },
    };

    g.bench_function("serialize_sync_sketch_small", |b| {
        b.iter(|| black_box(serialize(black_box(&sketch)).unwrap()))
    });

    let encoded_sketch = serialize(&sketch).unwrap();
    g.bench_function("deserialize_sync_sketch_small", |b| {
        b.iter(|| black_box(deserialize::<SyncSketch>(black_box(&encoded_sketch)).unwrap()))
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_merkle_node,
    bench_sync_messages,
    bench_joiner_hot_path,
    bench_blob_hot_path
);
criterion_main!(benches);
