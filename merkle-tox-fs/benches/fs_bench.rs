use criterion::{Criterion, criterion_group, criterion_main};
use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::{BlobStore, NodeStore};
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;

fn make_node(i: u64) -> MerkleNode {
    MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1; 32]),
        sender_pk: PhysicalDevicePk::from([1; 32]),
        sequence_number: i,
        topological_rank: i,
        network_timestamp: i as i64,
        content: Content::Text(format!("Message number {}", i)),
        metadata: vec![0; 64],
        authentication: NodeAuth::Mac(NodeMac::from([2; 32])),
    }
}

fn bench_node_ops(c: &mut Criterion) {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let store = FsStore::new(tmp_dir.path().to_path_buf(), fs.clone()).unwrap();
    let conv_id = ConversationId::from([0xAA; 32]);

    let mut g = c.benchmark_group("fs_node_ops");

    g.bench_function("put_node_journal", |b| {
        let mut i = 0;
        b.iter(|| {
            let node = make_node(i);
            store.put_node(&conv_id, node, true).unwrap();
            i += 1;
        })
    });

    // We'll put some nodes for get_node bench
    for i in 1000..1100 {
        let node = make_node(i);
        store.put_node(&conv_id, node, true).unwrap();
    }
    let node_to_get = make_node(1050).hash();

    g.bench_function("get_node_journal", |b| {
        b.iter(|| black_box(store.get_node(black_box(&node_to_get)).unwrap()))
    });

    // Now compact them
    store.compact(&conv_id).unwrap();

    g.bench_function("get_node_packed", |b| {
        b.iter(|| black_box(store.get_node(black_box(&node_to_get)).unwrap()))
    });

    g.finish();
}

fn bench_index_load(c: &mut Criterion) {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([0xBB; 32]);

    // Create 500 nodes in journal
    {
        let store = FsStore::new(root.clone(), fs.clone()).unwrap();
        for i in 0..500 {
            let node = make_node(i);
            store.put_node(&conv_id, node, true).unwrap();
        }
    }

    let mut g = c.benchmark_group("fs_startup_load");
    g.bench_function("load_500_journal", |b| {
        b.iter(|| {
            let store = FsStore::new(black_box(root.clone()), fs.clone()).unwrap();
            black_box(store.get_heads(black_box(&conv_id)));
        })
    });

    // Now compact them and see the difference
    {
        let store = FsStore::new(root.clone(), fs.clone()).unwrap();
        store.compact(&conv_id).unwrap();
    }

    g.bench_function("load_500_packed", |b| {
        b.iter(|| {
            let store = FsStore::new(black_box(root.clone()), fs.clone()).unwrap();
            black_box(store.get_heads(black_box(&conv_id)));
        })
    });

    g.finish();
}

fn bench_blob_ops(c: &mut Criterion) {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let store = FsStore::new(tmp_dir.path().to_path_buf(), fs.clone()).unwrap();
    let conv_id = ConversationId::from([0xCC; 32]);

    let mut g = c.benchmark_group("fs_blob_ops");

    let blob_data = vec![0xEEu8; 64 * 1024];
    let blob_hash = NodeHash::from(*blake3::hash(&blob_data).as_bytes());

    use merkle_tox_core::cas::{BlobInfo, BlobStatus};
    let info = BlobInfo {
        hash: blob_hash,
        size: 64 * 1024,
        status: BlobStatus::Pending,
        received_mask: None,
        bao_root: None,
    };
    store.put_blob_info(info).unwrap();

    g.bench_function("put_chunk_64kb", |b| {
        b.iter(|| {
            store
                .put_chunk(&conv_id, &blob_hash, 0, &blob_data, None)
                .unwrap();
        })
    });

    g.bench_function("get_chunk_64kb", |b| {
        b.iter(|| black_box(store.get_chunk(&blob_hash, 0, 64 * 1024).unwrap()))
    });

    g.finish();
}

criterion_group!(benches, bench_node_ops, bench_index_load, bench_blob_ops);
criterion_main!(benches);
