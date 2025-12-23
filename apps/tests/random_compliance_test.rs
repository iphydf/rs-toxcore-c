use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::{
    Content, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac,
    PhysicalDevicePk,
};
use merkle_tox_core::testing::{ManagedStore, delegate_store};
use merkle_tox_core::vfs::MemFileSystem;
use merkle_tox_fs::FsStore;
use merkle_tox_sqlite::Storage as SqliteStore;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

struct SqliteManaged {
    store: SqliteStore,
}

delegate_store!(SqliteManaged, store);

impl ManagedStore for SqliteManaged {
    fn name(&self) -> &str {
        "sqlite"
    }
    fn reopen(&mut self) {
        // SQLite backend currently handles persistence within the same connection for this test.
    }
}

struct FsManaged {
    store: FsStore<MemFileSystem>,
    vfs: Arc<MemFileSystem>,
}

delegate_store!(FsManaged, store);

impl ManagedStore for FsManaged {
    fn name(&self) -> &str {
        "fs"
    }
    fn reopen(&mut self) {
        let vfs = self.vfs.clone();
        // Drop the old store first to flush MemFileSystem handles
        let mut old_store = FsStore::new(PathBuf::from("/dev/null"), vfs.clone()).unwrap();
        std::mem::swap(&mut self.store, &mut old_store);
        drop(old_store);

        self.store = FsStore::new(PathBuf::from("/virtual/fs_root"), vfs).unwrap();
    }
}

#[derive(Debug, Clone)]
enum Op {
    PutNode {
        conv_idx: usize,
        parents: Vec<usize>,
        sender_pk: PhysicalDevicePk,
        seq: u64,
        rank: u64,
        verified: bool,
    },
    SetHeads {
        conv_idx: usize,
        heads: Vec<usize>,
    },
    MarkVerified {
        conv_idx: usize,
        node_idx: usize,
    },
    PutKey {
        conv_idx: usize,
        epoch: u64,
        k: KConv,
    },
    UpdateMeta {
        conv_idx: usize,
        count: u32,
        time: i64,
    },
    Pack {
        conv_idx: usize,
    },
    PutBlobInfo {
        size: u64,
    },
    PutChunk {
        blob_idx: usize,
        chunk_idx: usize,
        conv_idx: usize,
    },
    SetGlobalOffset {
        offset: i64,
    },
    Reopen,
}

#[test]
fn test_store_random_compliance() {
    let tmp = TempDir::new().unwrap();
    let vfs = Arc::new(MemFileSystem::new());

    let sqlite_managed = Box::new(SqliteManaged {
        store: SqliteStore::open(tmp.path().join("test.db")).unwrap(),
    });
    let fs_managed = Box::new(FsManaged {
        store: FsStore::new(PathBuf::from("/virtual/fs_root"), vfs.clone()).unwrap(),
        vfs,
    });

    let mut stores: Vec<Box<dyn ManagedStore>> = vec![sqlite_managed, fs_managed];

    let mut rng = StdRng::seed_from_u64(42);

    let conv_ids = [
        ConversationId::from([1u8; 32]),
        ConversationId::from([2u8; 32]),
        ConversationId::from([3u8; 32]),
        ConversationId::from([4u8; 32]),
        ConversationId::from([5u8; 32]),
    ];
    let mut known_nodes: Vec<Vec<NodeHash>> = vec![vec![], vec![], vec![], vec![], vec![]];
    let mut known_blobs: Vec<NodeHash> = Vec::new();
    let mut blob_expected_data: HashMap<NodeHash, Vec<u8>> = HashMap::new();

    for i in 0..300 {
        let op = match rng.gen_range(0..11) {
            0 => {
                let conv_idx = rng.gen_range(0..conv_ids.len());
                let num_parents = rng.gen_range(0..3).min(known_nodes[conv_idx].len());
                let mut parents = Vec::new();
                for _ in 0..num_parents {
                    parents.push(rng.gen_range(0..known_nodes[conv_idx].len()));
                }
                let mut sender_pk = [0u8; 32];
                sender_pk[0] = rng.gen_range(0..5);
                Op::PutNode {
                    conv_idx,
                    parents,
                    sender_pk: PhysicalDevicePk::from(sender_pk),
                    seq: rng.gen_range(1..1000),
                    rank: rng.gen_range(0..100),
                    verified: rng.gen_bool(0.7),
                }
            }
            1 => Op::SetHeads {
                conv_idx: rng.gen_range(0..conv_ids.len()),
                heads: (0..rng.gen_range(1..3))
                    .map(|_| rng.gen_range(0..known_nodes[0].len().max(1)))
                    .collect(),
            },
            2 => Op::MarkVerified {
                conv_idx: rng.gen_range(0..conv_ids.len()),
                node_idx: rng.gen_range(0..known_nodes[0].len().max(1)),
            },
            3 => {
                let mut k = [0u8; 32];
                rng.fill(&mut k);
                Op::PutKey {
                    conv_idx: rng.gen_range(0..conv_ids.len()),
                    epoch: rng.gen_range(0..10),
                    k: KConv::from(k),
                }
            }
            4 => Op::UpdateMeta {
                conv_idx: rng.gen_range(0..conv_ids.len()),
                count: rng.gen_range(0..10000),
                time: rng.gen_range(0..1000000),
            },
            5 => Op::Pack {
                conv_idx: rng.gen_range(0..conv_ids.len()),
            },
            6 => Op::PutBlobInfo {
                size: rng.gen_range(1..CHUNK_SIZE * 3),
            },
            7 => Op::PutChunk {
                blob_idx: if known_blobs.is_empty() {
                    0
                } else {
                    rng.gen_range(0..known_blobs.len())
                },
                chunk_idx: rng.gen_range(0..5),
                conv_idx: rng.gen_range(0..conv_ids.len()),
            },
            8 => Op::SetGlobalOffset {
                offset: rng.gen_range(-1000..1000),
            },
            9 => Op::Reopen,
            _ => Op::MarkVerified {
                conv_idx: rng.gen_range(0..conv_ids.len()),
                node_idx: rng.gen_range(0..known_nodes[0].len().max(1)),
            },
        };

        match op {
            Op::PutNode {
                conv_idx,
                parents: parent_indices,
                sender_pk,
                seq,
                rank,
                verified,
            } => {
                let cid = conv_ids[conv_idx];
                let parents: Vec<NodeHash> = parent_indices
                    .iter()
                    .map(|&i| known_nodes[conv_idx][i])
                    .collect();
                let node = MerkleNode {
                    parents,
                    author_pk: LogicalIdentityPk::from([1u8; 32]),
                    sender_pk,
                    sequence_number: seq,
                    topological_rank: rank,
                    network_timestamp: 1000 + i as i64,
                    content: Content::Text(format!("Node {}", i)),
                    metadata: vec![],
                    authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
                };
                let hash = node.hash();
                for s in &stores {
                    s.put_node(&cid, node.clone(), verified).unwrap();
                }
                known_nodes[conv_idx].push(hash);
            }
            Op::SetHeads {
                conv_idx,
                heads: head_indices,
            } => {
                let cid = conv_ids[conv_idx];
                if !known_nodes[conv_idx].is_empty() {
                    let heads: Vec<NodeHash> = head_indices
                        .iter()
                        .map(|&i| known_nodes[conv_idx][i % known_nodes[conv_idx].len()])
                        .collect();
                    for s in &stores {
                        s.set_heads(&cid, heads.clone()).unwrap();
                    }
                }
            }
            Op::MarkVerified { conv_idx, node_idx } => {
                let cid = conv_ids[conv_idx];
                if !known_nodes[conv_idx].is_empty() {
                    let hash = known_nodes[conv_idx][node_idx % known_nodes[conv_idx].len()];
                    for s in &stores {
                        s.mark_verified(&cid, &hash).unwrap();
                    }
                }
            }
            Op::PutKey { conv_idx, epoch, k } => {
                let cid = conv_ids[conv_idx];
                for s in &stores {
                    s.put_conversation_key(&cid, epoch, k.clone()).unwrap();
                }
            }
            Op::UpdateMeta {
                conv_idx,
                count,
                time,
            } => {
                let cid = conv_ids[conv_idx];
                for s in &stores {
                    s.update_epoch_metadata(&cid, count, time).unwrap();
                }
            }
            Op::Pack { conv_idx } => {
                let _cid = conv_ids[conv_idx];
                // FsStore specific pack is not in the trait, we can skip it or add to ManagedStore if needed.
            }
            Op::PutBlobInfo { size } => {
                let mut hash_bytes = [0u8; 32];
                rng.fill(&mut hash_bytes);
                let blob_hash = NodeHash::from(hash_bytes);
                let info = BlobInfo {
                    hash: blob_hash,
                    size,
                    bao_root: None,
                    status: BlobStatus::Pending,
                    received_mask: None,
                };
                for s in &stores {
                    s.put_blob_info(info.clone()).unwrap();
                }
                known_blobs.push(blob_hash);
                blob_expected_data.insert(blob_hash, vec![0u8; size as usize]);
            }
            Op::PutChunk {
                blob_idx,
                chunk_idx,
                conv_idx,
            } => {
                if !known_blobs.is_empty() {
                    let hash = known_blobs[blob_idx % known_blobs.len()];
                    let cid = conv_ids[conv_idx];
                    let expected = blob_expected_data.get_mut(&hash).unwrap();
                    let size = expected.len() as u64;

                    let offset = (chunk_idx as u64 * CHUNK_SIZE).min(size);
                    let len = (CHUNK_SIZE).min(size - offset);

                    if len > 0 {
                        let mut data = vec![0u8; len as usize];
                        rng.fill(&mut data[..]);

                        for s in &stores {
                            s.put_chunk(&cid, &hash, offset, &data, None).unwrap();
                        }

                        expected[offset as usize..(offset as usize + len as usize)]
                            .copy_from_slice(&data);
                    }
                }
            }
            Op::SetGlobalOffset { offset } => {
                for s in &stores {
                    s.set_global_offset(offset).unwrap();
                }
            }
            Op::Reopen => {
                for s in &mut stores {
                    s.reopen();
                }
            }
        }

        // Verification Step
        let v_idx = rng.gen_range(0..conv_ids.len());
        let v_cid = conv_ids[v_idx];

        for pair in stores.windows(2) {
            let s1 = &pair[0];
            let s2 = &pair[1];

            assert_eq!(
                s1.get_heads(&v_cid),
                s2.get_heads(&v_cid),
                "Heads mismatch in iteration {}",
                i
            );
            for s in 0..5 {
                let mut pk = [0u8; 32];
                pk[0] = s;
                let device_pk = PhysicalDevicePk::from(pk);
                assert_eq!(
                    s1.get_last_sequence_number(&v_cid, &device_pk),
                    s2.get_last_sequence_number(&v_cid, &device_pk),
                    "Seq mismatch for sender {} in iteration {}",
                    s,
                    i
                );
            }
            assert_eq!(
                s1.get_conversation_keys(&v_cid).unwrap(),
                s2.get_conversation_keys(&v_cid).unwrap(),
                "Keys mismatch in iteration {}",
                i
            );

            let m1 = s1
                .get_epoch_metadata(&v_cid)
                .unwrap()
                .filter(|&(c, t)| c != 0 || t != 0);
            let m2 = s2
                .get_epoch_metadata(&v_cid)
                .unwrap()
                .filter(|&(c, t)| c != 0 || t != 0);
            assert_eq!(m1, m2, "Meta mismatch in iteration {}", i);

            assert_eq!(
                s1.get_global_offset(),
                s2.get_global_offset(),
                "Global offset mismatch in iteration {}",
                i
            );

            let spec1: HashSet<_> = s1
                .get_speculative_nodes(&v_cid)
                .into_iter()
                .map(|n| n.hash())
                .collect();
            let spec2: HashSet<_> = s2
                .get_speculative_nodes(&v_cid)
                .into_iter()
                .map(|n| n.hash())
                .collect();
            assert_eq!(
                spec1, spec2,
                "Speculative nodes mismatch in iteration {}",
                i
            );

            if !known_nodes[v_idx].is_empty() {
                let n_idx = rng.gen_range(0..known_nodes[v_idx].len());
                let hash = known_nodes[v_idx][n_idx];
                assert_eq!(s1.get_node(&hash), s2.get_node(&hash), "Node mismatch");
                assert_eq!(s1.get_rank(&hash), s2.get_rank(&hash), "Rank mismatch");
                assert_eq!(
                    s1.get_node_type(&hash),
                    s2.get_node_type(&hash),
                    "Node type mismatch"
                );
                assert_eq!(
                    s1.contains_node(&hash),
                    s2.contains_node(&hash),
                    "Contains node mismatch"
                );
            }

            if !known_blobs.is_empty() {
                let b_idx = rng.gen_range(0..known_blobs.len());
                let hash = known_blobs[b_idx];
                assert_eq!(s1.has_blob(&hash), s2.has_blob(&hash), "Has blob mismatch");
                let info1 = s1.get_blob_info(&hash);
                let info2 = s2.get_blob_info(&hash);
                assert_eq!(info1, info2, "Blob info mismatch");

                if let Some(info) = info1
                    && info.status == BlobStatus::Available
                {
                    let d1 = s1.get_chunk(&hash, 0, info.size as u32).unwrap();
                    let d2 = s2.get_chunk(&hash, 0, info.size as u32).unwrap();
                    assert_eq!(d1, d2, "Blob data mismatch");
                }
            }
        }
    }
}
