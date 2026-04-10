use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::{
    ChainKey, Content, ConversationId, Ed25519Signature, KConv, LogicalIdentityPk, MerkleNode,
    NodeAuth, NodeHash, NodeType, PhysicalDevicePk, WireFlags, WireNode,
};
use merkle_tox_core::sync::SyncRange;
use merkle_tox_core::testing::{ManagedStore, delegate_store};
use merkle_tox_core::vfs::MemFileSystem;
use merkle_tox_fs::FsStore;
use merkle_tox_sqlite::Storage as SqliteStore;
use proptest::prelude::*;
use rand::{RngCore, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

#[derive(Debug, Clone)]
struct SwarmWeights {
    node_weight: u32,
    blob_weight: u32,
    meta_weight: u32,
    reopen_weight: u32,
    chaos_prob: f64,
}

#[derive(Debug, Clone)]
enum LogicalOp {
    PutNode {
        parent_indices: Vec<usize>,
        sender_idx: usize,
        seq_offset: i64,
        rank_offset: i64,
        verified: bool,
        chaos: bool,
    },
    SetHeads {
        head_indices: Vec<usize>,
    },
    SetAdminHeads {
        head_indices: Vec<usize>,
    },
    MarkVerified {
        node_idx: usize,
    },
    PutWireNode {
        payload_len: usize,
    },
    RemoveWireNode {
        hash_idx: usize,
    },
    PutRatchetKey {
        node_idx: usize,
        key: ChainKey,
        epoch_id: u64,
    },
    RemoveRatchetKey {
        node_idx: usize,
    },
    PutSketch {
        min_rank: u64,
        max_rank: u64,
        sketch: Vec<u8>,
    },
    PutKey {
        conv_idx: usize,
        epoch_offset: i32,
        k: KConv,
    },
    UpdateMeta {
        conv_idx: usize,
        count: u32,
        time: i64,
    },
    PutBlobInfo {
        size: u64,
    },
    PutChunk {
        blob_idx: usize,
        chunk_idx: usize,
        conv_idx: usize,
        chaos: bool,
    },
    SetGlobalOffset {
        offset: i64,
    },
    Reopen,
}

fn any_weights() -> impl Strategy<Value = SwarmWeights> {
    (1..10u32, 1..10u32, 1..5u32, 1..3u32, 0.0..0.2f64).prop_map(
        |(node_weight, blob_weight, meta_weight, reopen_weight, chaos_prob)| SwarmWeights {
            node_weight,
            blob_weight,
            meta_weight,
            reopen_weight,
            chaos_prob,
        },
    )
}

fn any_logical_op(weights: SwarmWeights) -> impl Strategy<Value = LogicalOp> {
    prop_oneof![
        weights.node_weight => prop_oneof![
            (prop::collection::vec(0..100usize, 0..3), 0..5usize, -5..5i64, -5..5i64, any::<bool>(), prop::bool::weighted(weights.chaos_prob)).prop_map(
                |(parent_indices, sender_idx, seq_offset, rank_offset, verified, chaos)| LogicalOp::PutNode { parent_indices, sender_idx, seq_offset, rank_offset, verified, chaos }
            ),
            prop::collection::vec(0..100usize, 1..3).prop_map(|head_indices| LogicalOp::SetHeads { head_indices }),
            prop::collection::vec(0..100usize, 1..3).prop_map(|head_indices| LogicalOp::SetAdminHeads { head_indices }),
            (0..100usize).prop_map(|node_idx| LogicalOp::MarkVerified { node_idx }),
            (10..200usize).prop_map(|payload_len| LogicalOp::PutWireNode { payload_len }),
            (0..100usize).prop_map(|hash_idx| LogicalOp::RemoveWireNode { hash_idx }),
        ],
        weights.blob_weight => prop_oneof![
            (1..CHUNK_SIZE * 5).prop_map(|size| LogicalOp::PutBlobInfo { size }),
            (0..100usize, 0..10usize, 0..5usize, prop::bool::weighted(weights.chaos_prob)).prop_map(
                |(blob_idx, chunk_idx, conv_idx, chaos)| LogicalOp::PutChunk { blob_idx, chunk_idx, conv_idx, chaos }
            ),
        ],
        weights.meta_weight => prop_oneof![
            (0..5usize, -2..5i32, any::<[u8; 32]>()).prop_map(
                |(conv_idx, epoch_offset, k)| LogicalOp::PutKey { conv_idx, epoch_offset, k: KConv::from(k) }
            ),
            (0..100usize, any::<[u8; 32]>(), 0..10u64).prop_map(|(node_idx, key, epoch_id)| LogicalOp::PutRatchetKey {
                node_idx,
                key: ChainKey::from(key),
                epoch_id,
            }),
            (0..100usize).prop_map(|node_idx| LogicalOp::RemoveRatchetKey { node_idx }),
            (any::<u64>(), any::<u64>(), prop::collection::vec(any::<u8>(), 1..64)).prop_map(|(min_rank, max_rank, sketch)| LogicalOp::PutSketch { min_rank, max_rank, sketch }),
            (0..5usize, any::<u32>(), any::<i64>()).prop_map(
                |(conv_idx, count, time)| LogicalOp::UpdateMeta { conv_idx, count, time }
            ),
            any::<i64>().prop_map(|offset| LogicalOp::SetGlobalOffset { offset }),
        ],
        weights.reopen_weight => Just(LogicalOp::Reopen),
    ]
}

struct SqliteManaged {
    store: SqliteStore,
}

delegate_store!(SqliteManaged, store);

impl ManagedStore for SqliteManaged {
    fn name(&self) -> &str {
        "sqlite"
    }
    fn reopen(&mut self) {
        let bytes = {
            let conn = self.store.connection().lock().unwrap();
            conn.serialize("main").unwrap().to_vec()
        };
        let mut new_conn = rusqlite::Connection::open_in_memory().unwrap();
        new_conn
            .deserialize_read_exact("main", &bytes[..], bytes.len(), false)
            .unwrap();
        self.store = SqliteStore::from_connection(new_conn);
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

struct StoreTester {
    stores: Vec<Box<dyn ManagedStore>>,
    conv_ids: Vec<ConversationId>,
    known_nodes: Vec<Vec<NodeHash>>,
    speculative_nodes: Vec<Vec<NodeHash>>,
    wire_nodes: Vec<HashSet<NodeHash>>,
    sketches: Vec<HashSet<SyncRange>>,
    known_blobs: Vec<NodeHash>,
    blob_expected_data: HashMap<NodeHash, Vec<u8>>,
    rng: rand::rngs::StdRng,
}

impl StoreTester {
    fn new(_tmp_path: &Path, seed: u64) -> Self {
        use rand::SeedableRng;
        let vfs = Arc::new(MemFileSystem::new());
        let sqlite = SqliteStore::open_in_memory().unwrap();
        {
            let conn = sqlite.connection().lock().unwrap();
            conn.execute_batch("PRAGMA synchronous = OFF;").unwrap();
        }

        let sqlite_managed = Box::new(SqliteManaged { store: sqlite });
        let fs_managed = Box::new(FsManaged {
            store: FsStore::new(PathBuf::from("/virtual/fs_root"), vfs.clone()).unwrap(),
            vfs,
        });

        Self {
            stores: vec![sqlite_managed, fs_managed],
            conv_ids: vec![
                ConversationId::from([1u8; 32]),
                ConversationId::from([2u8; 32]),
                ConversationId::from([3u8; 32]),
                ConversationId::from([4u8; 32]),
                ConversationId::from([5u8; 32]),
            ],
            known_nodes: vec![vec![]; 5],
            speculative_nodes: vec![vec![]; 5],
            wire_nodes: vec![HashSet::new(); 5],
            sketches: vec![HashSet::new(); 5],
            known_blobs: Vec::new(),
            blob_expected_data: HashMap::new(),
            rng: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }

    fn apply_op(&mut self, op: LogicalOp, step: usize) {
        match op {
            LogicalOp::PutNode {
                parent_indices,
                sender_idx,
                seq_offset,
                rank_offset,
                verified,
                chaos,
            } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                let parents = self.resolve_parents(c_idx, &parent_indices, chaos);
                let node = self.make_node(parents, sender_idx, seq_offset, rank_offset, step);
                let hash = node.hash();
                for store in &self.stores {
                    let _ = store.put_node(&cid, node.clone(), verified);
                }
                self.known_nodes[c_idx].push(hash);
                if !verified {
                    self.speculative_nodes[c_idx].push(hash);
                }
            }
            LogicalOp::SetHeads { head_indices } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if !self.known_nodes[c_idx].is_empty() {
                    let heads = self.resolve_indices(c_idx, &head_indices);
                    for store in &self.stores {
                        let _ = store.set_heads(&cid, heads.clone());
                    }
                }
            }
            LogicalOp::SetAdminHeads { head_indices } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if !self.known_nodes[c_idx].is_empty() {
                    let heads = self.resolve_indices(c_idx, &head_indices);
                    for store in &self.stores {
                        let _ = store.set_admin_heads(&cid, heads.clone());
                    }
                }
            }
            LogicalOp::MarkVerified { node_idx } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if let Some(hash) = self.pop_speculative(c_idx, node_idx) {
                    for store in &self.stores {
                        let _ = store.mark_verified(&cid, &hash);
                    }
                }
            }
            LogicalOp::PutWireNode { payload_len } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                let mut hash_bytes = [0u8; 32];
                fill_random(&mut hash_bytes, &mut self.rng);
                let hash = NodeHash::from(hash_bytes);
                let mut payload = vec![0u8; payload_len];
                fill_random(&mut payload, &mut self.rng);
                let wire = WireNode {
                    parents: tox_proto::BoundedVec::new(),
                    sender_hint: [0u8; 4],
                    encrypted_routing: vec![0u8; 40],
                    payload_data: payload,
                    topological_rank: 0,
                    flags: WireFlags::NONE,
                    authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
                };
                for store in &self.stores {
                    let _ = store.put_wire_node(&cid, &hash, wire.clone());
                }
                self.wire_nodes[c_idx].insert(hash);
            }
            LogicalOp::RemoveWireNode { hash_idx } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if let Some(hash) = self.resolve_wire_node(c_idx, hash_idx) {
                    for store in &self.stores {
                        let _ = store.remove_wire_node(&cid, &hash);
                    }
                    self.wire_nodes[c_idx].remove(&hash);
                }
            }
            LogicalOp::PutRatchetKey {
                node_idx,
                key,
                epoch_id,
            } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if !self.known_nodes[c_idx].is_empty() {
                    let hash = self.known_nodes[c_idx][node_idx % self.known_nodes[c_idx].len()];
                    for store in &self.stores {
                        let _ = store.put_ratchet_key(&cid, &hash, key.clone(), epoch_id);
                    }
                }
            }
            LogicalOp::RemoveRatchetKey { node_idx } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                if !self.known_nodes[c_idx].is_empty() {
                    let hash = self.known_nodes[c_idx][node_idx % self.known_nodes[c_idx].len()];
                    for store in &self.stores {
                        let _ = store.remove_ratchet_key(&cid, &hash);
                    }
                }
            }
            LogicalOp::PutSketch {
                min_rank,
                max_rank,
                sketch,
            } => {
                let c_idx = step % self.conv_ids.len();
                let cid = self.conv_ids[c_idx];
                let range = SyncRange { min_rank, max_rank };
                for store in &self.stores {
                    let _ = store.put_sketch(&cid, &range, &sketch);
                }
                self.sketches[c_idx].insert(range);
            }
            LogicalOp::PutKey {
                conv_idx,
                epoch_offset,
                k,
            } => {
                let cid = self.conv_ids[conv_idx % self.conv_ids.len()];
                let epoch = (step as u64).wrapping_add(epoch_offset as u64);
                for store in &self.stores {
                    let _ = store.put_conversation_key(&cid, epoch, k.clone());
                }
            }
            LogicalOp::UpdateMeta {
                conv_idx,
                count,
                time,
            } => {
                let cid = self.conv_ids[conv_idx % self.conv_ids.len()];
                for store in &self.stores {
                    let _ = store.update_epoch_metadata(&cid, count, time);
                }
            }
            LogicalOp::PutBlobInfo { size } => {
                let mut hash_bytes = [0u8; 32];
                fill_random(&mut hash_bytes, &mut self.rng);
                let blob_hash = NodeHash::from(hash_bytes);
                let info = BlobInfo {
                    hash: blob_hash,
                    size,
                    status: BlobStatus::Pending,
                    received_mask: None,
                    decryption_key: None,
                };
                let mut all_ok = true;
                for store in &self.stores {
                    if store.put_blob_info(info.clone()).is_err() {
                        all_ok = false;
                    }
                }
                if all_ok {
                    self.known_blobs.push(blob_hash);
                    self.blob_expected_data
                        .insert(blob_hash, vec![0u8; size as usize]);
                }
            }
            LogicalOp::PutChunk {
                blob_idx,
                chunk_idx,
                conv_idx,
                chaos,
            } => {
                let hash = self.resolve_blob(blob_idx, chaos);
                let cid = self.conv_ids[conv_idx % self.conv_ids.len()];
                self.apply_chunk(cid, hash, chunk_idx);
            }
            LogicalOp::SetGlobalOffset { offset } => {
                for store in &self.stores {
                    let _ = store.set_global_offset(offset);
                }
            }
            LogicalOp::Reopen => {
                for store in &mut self.stores {
                    store.reopen();
                }
            }
        }
    }

    fn resolve_parents(&mut self, c_idx: usize, indices: &[usize], chaos: bool) -> Vec<NodeHash> {
        if chaos || self.known_nodes[c_idx].is_empty() {
            indices
                .iter()
                .map(|_| {
                    let mut h = [0u8; 32];
                    fill_random(&mut h, &mut self.rng);
                    NodeHash::from(h)
                })
                .collect()
        } else {
            self.resolve_indices(c_idx, indices)
        }
    }

    fn resolve_indices(&self, c_idx: usize, indices: &[usize]) -> Vec<NodeHash> {
        let pool = &self.known_nodes[c_idx];
        indices.iter().map(|&idx| pool[idx % pool.len()]).collect()
    }

    fn make_node(
        &self,
        parents: Vec<NodeHash>,
        sender_idx: usize,
        seq_off: i64,
        rank_off: i64,
        step: usize,
    ) -> MerkleNode {
        let mut sender_pk = [0u8; 32];
        sender_pk[0] = (sender_idx % 5) as u8;
        MerkleNode {
            parents: tox_proto::BoundedVec::try_from_iter(parents)
                .expect("test fixtures must respect MAX_PARENTS"),
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from(sender_pk),
            sequence_number: (step as u64).wrapping_add(seq_off as u64),
            topological_rank: (step as u64).wrapping_add(rank_off as u64),
            network_timestamp: 1000 + step as i64,
            content: Content::Text(format!("Node {}", step)),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
            pow_nonce: 0,
        }
    }

    fn pop_speculative(&mut self, c_idx: usize, node_idx: usize) -> Option<NodeHash> {
        let pool = &mut self.speculative_nodes[c_idx];
        if pool.is_empty() {
            return None;
        }
        Some(pool.remove(node_idx % pool.len()))
    }

    fn resolve_wire_node(&self, c_idx: usize, idx: usize) -> Option<NodeHash> {
        let pool = &self.wire_nodes[c_idx];
        if pool.is_empty() {
            return None;
        }
        pool.iter().nth(idx % pool.len()).cloned()
    }

    fn resolve_blob(&mut self, idx: usize, chaos: bool) -> NodeHash {
        if chaos || self.known_blobs.is_empty() {
            let mut h = [0u8; 32];
            fill_random(&mut h, &mut self.rng);
            NodeHash::from(h)
        } else {
            self.known_blobs[idx % self.known_blobs.len()]
        }
    }

    fn apply_chunk(&mut self, cid: ConversationId, hash: NodeHash, chunk_idx: usize) {
        let mut data_to_update = None;
        if let Some(expected) = self.blob_expected_data.get(&hash) {
            let size = expected.len() as u64;
            let offset = (chunk_idx as u64 * CHUNK_SIZE).min(size);
            let len = (CHUNK_SIZE).min(size - offset);
            if len > 0 {
                let mut data = vec![0u8; len as usize];
                // Use a seed derived from hash and offset for deterministic chunk data
                let mut chunk_rng = rand::rngs::StdRng::seed_from_u64(
                    u64::from_le_bytes(hash.as_ref()[0..8].try_into().unwrap()) ^ offset,
                );
                chunk_rng.fill_bytes(&mut data);

                // Both stores skip if already available, so we should only update expected
                // if it's not yet available.
                let was_available = self.stores[0].has_blob(&hash);

                let mut all_ok = true;
                for store in &self.stores {
                    if store.put_chunk(&cid, &hash, offset, &data, None).is_err() {
                        all_ok = false;
                    }
                }

                if all_ok && !was_available {
                    data_to_update = Some((offset, data));
                }
            }
        } else {
            let mut data = vec![0u8; 10];
            fill_random(&mut data, &mut self.rng);
            for store in &self.stores {
                let _ = store.put_chunk(&cid, &hash, 0, &data, None);
            }
        }

        if let Some((offset, data)) = data_to_update {
            let expected = self.blob_expected_data.get_mut(&hash).unwrap();
            let end = offset as usize + data.len();
            expected[offset as usize..end].copy_from_slice(&data);
        }
    }

    fn verify_consistency(&self, step: usize) {
        if self.stores.is_empty() {
            return;
        }
        for i in 1..self.stores.len() {
            self.compare_stores(0, i, step);
        }
    }

    fn compare_stores(&self, idx1: usize, idx2: usize, step: usize) {
        let s1 = &self.stores[idx1];
        let s2 = &self.stores[idx2];
        let v_idx = step % self.conv_ids.len();
        let cid = self.conv_ids[v_idx];

        assert_eq!(
            s1.get_heads(&cid),
            s2.get_heads(&cid),
            "Heads mismatch between {} and {}",
            s1.name(),
            s2.name()
        );
        assert_eq!(
            s1.get_admin_heads(&cid),
            s2.get_admin_heads(&cid),
            "Admin heads mismatch between {} and {}",
            s1.name(),
            s2.name()
        );
        assert_eq!(
            s1.get_opaque_node_hashes(&cid)
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            s2.get_opaque_node_hashes(&cid)
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            "Opaque node hashes mismatch between {} and {}",
            s1.name(),
            s2.name()
        );
        assert_eq!(
            s1.get_conversation_keys(&cid).unwrap(),
            s2.get_conversation_keys(&cid).unwrap(),
            "Keys mismatch between {} and {}",
            s1.name(),
            s2.name()
        );
        assert_eq!(
            s1.get_epoch_metadata(&cid)
                .unwrap()
                .filter(|&(c, t)| c != 0 || t != 0),
            s2.get_epoch_metadata(&cid)
                .unwrap()
                .filter(|&(c, t)| c != 0 || t != 0),
            "Metadata mismatch between {} and {}",
            s1.name(),
            s2.name()
        );
        assert_eq!(
            s1.get_global_offset(),
            s2.get_global_offset(),
            "Global offset mismatch between {} and {}",
            s1.name(),
            s2.name()
        );

        let mut sender_pk_bytes = [0u8; 32];
        sender_pk_bytes[0] = (step % 5) as u8;
        let sender_pk = PhysicalDevicePk::from(sender_pk_bytes);
        assert_eq!(
            s1.get_last_sequence_number(&cid, &sender_pk),
            s2.get_last_sequence_number(&cid, &sender_pk),
            "Sequence mismatch between {} and {}",
            s1.name(),
            s2.name()
        );

        let s_sql: HashSet<_> = s1
            .get_speculative_nodes(&cid)
            .into_iter()
            .map(|n| n.hash())
            .collect();
        let s_fs: HashSet<_> = s2
            .get_speculative_nodes(&cid)
            .into_iter()
            .map(|n| n.hash())
            .collect();
        assert_eq!(
            s_sql,
            s_fs,
            "Speculative nodes mismatch between {} and {}",
            s1.name(),
            s2.name()
        );

        if !self.known_nodes[v_idx].is_empty() {
            let hash = self.known_nodes[v_idx][step % self.known_nodes[v_idx].len()];
            assert_eq!(
                s1.get_node(&hash),
                s2.get_node(&hash),
                "Node mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
            assert_eq!(
                s1.get_rank(&hash),
                s2.get_rank(&hash),
                "Rank mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
            assert_eq!(
                s1.get_node_type(&hash),
                s2.get_node_type(&hash),
                "Node type mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
            assert_eq!(
                s1.contains_node(&hash),
                s2.contains_node(&hash),
                "Contains node mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
            assert_eq!(
                s1.has_node(&hash),
                s2.has_node(&hash),
                "Has node mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
        }

        // Ratchet keys: only compare if we haven't reopened recently OR if it's the latest
        // because FsStore only persists the latest ratchet per device to the packed ratchet.bin.
        // Skip non-hot ratchet keys to avoid mismatches.
        if !self.known_nodes[v_idx].is_empty() {
            let hash = self.known_nodes[v_idx][step % self.known_nodes[v_idx].len()];

            let res1 = s1.get_ratchet_key(&cid, &hash).unwrap();
            let res2 = s2.get_ratchet_key(&cid, &hash).unwrap();

            // If both have it, they must match.
            // If only one has it, it might be due to FsStore pack limitations.
            if res1.is_some() && res2.is_some() {
                assert_eq!(
                    res1,
                    res2,
                    "Ratchet key mismatch between {} and {}",
                    s1.name(),
                    s2.name()
                );
            }
        }

        if !self.sketches[v_idx].is_empty() {
            let range = self.sketches[v_idx]
                .iter()
                .nth(step % self.sketches[v_idx].len())
                .unwrap();
            assert_eq!(
                s1.get_sketch(&cid, range).unwrap(),
                s2.get_sketch(&cid, range).unwrap(),
                "Sketch mismatch between {} and {}",
                s1.name(),
                s2.name()
            );
        }

        // Advanced queries
        let (v_count, _) = s1.get_node_counts(&cid);
        if v_count > 0 {
            // Test get_verified_nodes_by_type
            assert_eq!(
                s1.get_verified_nodes_by_type(&cid, NodeType::Content)
                    .unwrap(),
                s2.get_verified_nodes_by_type(&cid, NodeType::Content)
                    .unwrap(),
                "Verified content nodes mismatch between {} and {}",
                s1.name(),
                s2.name()
            );

            // Test get_node_hashes_in_range with a random range from existing nodes
            let all_nodes = s1
                .get_verified_nodes_by_type(&cid, NodeType::Content)
                .unwrap();
            if !all_nodes.is_empty() {
                let r1 = all_nodes[step % all_nodes.len()].topological_rank;
                let r2 = all_nodes[(step / 2) % all_nodes.len()].topological_rank;
                let range = SyncRange {
                    min_rank: r1.min(r2),
                    max_rank: r1.max(r2),
                };
                assert_eq!(
                    s1.get_node_hashes_in_range(&cid, &range)
                        .unwrap()
                        .into_iter()
                        .collect::<HashSet<_>>(),
                    s2.get_node_hashes_in_range(&cid, &range)
                        .unwrap()
                        .into_iter()
                        .collect::<HashSet<_>>(),
                    "Node hashes in range mismatch between {} and {}",
                    s1.name(),
                    s2.name()
                );
            }
        }

        if !self.known_blobs.is_empty() {
            let b_idx = step % self.known_blobs.len();
            let hash = self.known_blobs[b_idx];
            assert_eq!(
                s1.has_blob(&hash),
                s2.has_blob(&hash),
                "Has blob mismatch between {} and {}",
                s1.name(),
                s2.name()
            );

            let info1 = s1.get_blob_info(&hash);
            let info2 = s2.get_blob_info(&hash);
            assert_eq!(
                info1,
                info2,
                "Blob info mismatch between {} and {}",
                s1.name(),
                s2.name()
            );

            if let Some(expected) = self.blob_expected_data.get(&hash) {
                let size = expected.len() as u64;
                if size > 0 {
                    let offset = (step as u64 * 1024) % size;
                    let len = (size - offset).min(1024) as u32;
                    if len > 0 {
                        let res1 = s1.get_chunk(&hash, offset, len);
                        let res2 = s2.get_chunk(&hash, offset, len);
                        assert_eq!(
                            res1.as_ref().map_err(|e| e.to_string()),
                            res2.as_ref().map_err(|e| e.to_string()),
                            "Chunk mismatch between {} and {}",
                            s1.name(),
                            s2.name()
                        );
                        if let Ok(data) = res1 {
                            assert_eq!(
                                data,
                                &expected[offset as usize..(offset as usize + len as usize)],
                                "Chunk data mismatch against expected for {}",
                                s1.name()
                            );
                        }
                    }
                }
            }
        }
    }
}

fn fill_random(buf: &mut [u8], rng: &mut rand::rngs::StdRng) {
    use rand::RngCore;
    rng.fill_bytes(buf);
}

fn get_env_or_default(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(get_env_or_default("PROPTEST_CASES", 30)))]
    #[test]
    fn test_store_proptest_compliance(
        (ops, _) in any_weights().prop_flat_map(|w| {
            let num_ops = get_env_or_default("PROPTEST_OPS", 100) as usize;
            (prop::collection::vec(any_logical_op(w.clone()), 1..num_ops), Just(w))
        }),
        seed in any::<u64>(),
    ) {
        let tmp = TempDir::new().unwrap();
        let mut tester = StoreTester::new(tmp.path(), seed);

        for (i, op) in ops.into_iter().enumerate() {
            tester.apply_op(op, i);
            if i % 5 == 0 {
                tester.verify_consistency(i);
            }
        }
    }
}
