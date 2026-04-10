use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{
    ChainKey, Content, ConversationId, Ed25519Signature, KConv, MerkleNode, NodeHash, NodeType,
    PhysicalDevicePk,
};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::error::{MerkleToxError, MerkleToxResult};
use merkle_tox_core::node::MerkleToxNode;
use merkle_tox_core::sync::{BlobStore, NodeStore, SyncRange};
use merkle_tox_core::testing::{InMemoryStore, TestIdentity};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

struct DummyTransport(PhysicalDevicePk);
impl merkle_tox_core::Transport for DummyTransport {
    fn local_pk(&self) -> PhysicalDevicePk {
        self.0
    }
    fn send_raw(
        &self,
        _to: PhysicalDevicePk,
        _data: Vec<u8>,
    ) -> Result<(), merkle_tox_core::TransportError> {
        Ok(())
    }
}

struct FailingStore {
    inner: InMemoryStore,
    should_fail: Arc<AtomicBool>,
}

impl FailingStore {
    fn new() -> (Self, Arc<AtomicBool>) {
        let should_fail = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner: InMemoryStore::new(),
                should_fail: should_fail.clone(),
            },
            should_fail,
        )
    }
}

impl merkle_tox_core::dag::NodeLookup for FailingStore {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType> {
        self.inner.get_node_type(hash)
    }
    fn get_rank(&self, hash: &NodeHash) -> Option<u64> {
        self.inner.get_rank(hash)
    }
    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64> {
        self.inner.get_admin_distance(hash)
    }
    fn contains_node(&self, hash: &NodeHash) -> bool {
        self.inner.contains_node(hash)
    }
    fn has_children(&self, hash: &NodeHash) -> bool {
        self.inner.has_children(hash)
    }
    fn get_soft_anchor_chain_length(&self, hash: &NodeHash) -> Option<u64> {
        self.inner.get_soft_anchor_chain_length(hash)
    }
}

impl NodeStore for FailingStore {
    fn get_heads(&self, cid: &ConversationId) -> Vec<NodeHash> {
        self.inner.get_heads(cid)
    }
    fn set_heads(&self, cid: &ConversationId, h: Vec<NodeHash>) -> MerkleToxResult<()> {
        self.inner.set_heads(cid, h)
    }
    fn get_admin_heads(&self, cid: &ConversationId) -> Vec<NodeHash> {
        self.inner.get_admin_heads(cid)
    }
    fn set_admin_heads(&self, cid: &ConversationId, h: Vec<NodeHash>) -> MerkleToxResult<()> {
        self.inner.set_admin_heads(cid, h)
    }
    fn has_node(&self, hash: &NodeHash) -> bool {
        self.inner.has_node(hash)
    }
    fn is_verified(&self, hash: &NodeHash) -> bool {
        self.inner.is_verified(hash)
    }
    fn get_node(&self, hash: &NodeHash) -> Option<MerkleNode> {
        self.inner.get_node(hash)
    }
    fn get_wire_node(&self, hash: &NodeHash) -> Option<merkle_tox_core::dag::WireNode> {
        self.inner.get_wire_node(hash)
    }
    fn put_node(
        &self,
        cid: &ConversationId,
        node: MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()> {
        if self.should_fail.load(Ordering::SeqCst) {
            return Err(MerkleToxError::Storage("Simulated failure".to_string()));
        }
        self.inner.put_node(cid, node, verified)
    }
    fn put_wire_node(
        &self,
        cid: &ConversationId,
        hash: &NodeHash,
        node: merkle_tox_core::dag::WireNode,
    ) -> MerkleToxResult<()> {
        self.inner.put_wire_node(cid, hash, node)
    }
    fn remove_wire_node(&self, cid: &ConversationId, hash: &NodeHash) -> MerkleToxResult<()> {
        self.inner.remove_wire_node(cid, hash)
    }
    fn get_opaque_node_hashes(&self, cid: &ConversationId) -> MerkleToxResult<Vec<NodeHash>> {
        self.inner.get_opaque_node_hashes(cid)
    }

    fn get_speculative_nodes(&self, cid: &ConversationId) -> Vec<MerkleNode> {
        self.inner.get_speculative_nodes(cid)
    }
    fn mark_verified(&self, cid: &ConversationId, h: &NodeHash) -> MerkleToxResult<()> {
        self.inner.mark_verified(cid, h)
    }
    fn get_last_sequence_number(&self, cid: &ConversationId, p: &PhysicalDevicePk) -> u64 {
        self.inner.get_last_sequence_number(cid, p)
    }
    fn get_node_counts(&self, cid: &ConversationId) -> (usize, usize) {
        self.inner.get_node_counts(cid)
    }
    fn get_verified_nodes_by_type(
        &self,
        cid: &ConversationId,
        t: NodeType,
    ) -> MerkleToxResult<Vec<MerkleNode>> {
        self.inner.get_verified_nodes_by_type(cid, t)
    }
    fn get_node_hashes_in_range(
        &self,
        cid: &ConversationId,
        r: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        self.inner.get_node_hashes_in_range(cid, r)
    }
    fn size_bytes(&self) -> u64 {
        self.inner.size_bytes()
    }
    fn put_conversation_key(&self, cid: &ConversationId, e: u64, k: KConv) -> MerkleToxResult<()> {
        self.inner.put_conversation_key(cid, e, k)
    }
    fn get_conversation_keys(&self, cid: &ConversationId) -> MerkleToxResult<Vec<(u64, KConv)>> {
        self.inner.get_conversation_keys(cid)
    }
    fn update_epoch_metadata(&self, cid: &ConversationId, c: u32, t: i64) -> MerkleToxResult<()> {
        self.inner.update_epoch_metadata(cid, c, t)
    }
    fn get_epoch_metadata(&self, cid: &ConversationId) -> MerkleToxResult<Option<(u32, i64)>> {
        self.inner.get_epoch_metadata(cid)
    }
    fn put_ratchet_key(
        &self,
        cid: &ConversationId,
        h: &NodeHash,
        k: ChainKey,
        epoch_id: u64,
    ) -> MerkleToxResult<()> {
        self.inner.put_ratchet_key(cid, h, k, epoch_id)
    }
    fn get_ratchet_key(
        &self,
        cid: &ConversationId,
        h: &NodeHash,
    ) -> MerkleToxResult<Option<(ChainKey, u64)>> {
        self.inner.get_ratchet_key(cid, h)
    }
    fn remove_ratchet_key(&self, cid: &ConversationId, h: &NodeHash) -> MerkleToxResult<()> {
        self.inner.remove_ratchet_key(cid, h)
    }
}

impl BlobStore for FailingStore {
    fn has_blob(&self, h: &NodeHash) -> bool {
        self.inner.has_blob(h)
    }
    fn get_blob_info(&self, h: &NodeHash) -> Option<merkle_tox_core::cas::BlobInfo> {
        self.inner.get_blob_info(h)
    }
    fn put_blob_info(&self, i: merkle_tox_core::cas::BlobInfo) -> MerkleToxResult<()> {
        self.inner.put_blob_info(i)
    }
    fn put_chunk(
        &self,
        cid: &ConversationId,
        h: &NodeHash,
        o: u64,
        d: &[u8],
        p: Option<&[u8]>,
    ) -> MerkleToxResult<()> {
        self.inner.put_chunk(cid, h, o, d, p)
    }
    fn get_chunk(&self, h: &NodeHash, o: u64, l: u32) -> MerkleToxResult<Vec<u8>> {
        self.inner.get_chunk(h, o, l)
    }
}

#[test]
fn test_pending_cache_not_cleared_on_failure() {
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let (store, should_fail) = FailingStore::new();
    let transport = DummyTransport(alice.device_pk);

    let engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut node = MerkleToxNode::new(engine, transport, store, tp);

    let cid = ConversationId::from([1u8; 32]);
    let node_data = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text("Fail me".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: merkle_tox_core::dag::NodeAuth::EphemeralSignature(Ed25519Signature::from(
            [0u8; 64],
        )),
        pow_nonce: 0,
    };

    // Populate pending cache
    node.engine.put_pending_node(node_data.clone());

    assert_eq!(node.engine.pending_cache_len(), 1);

    should_fail.store(true, Ordering::SeqCst);
    let effect = Effect::WriteStore(cid, node_data, true);

    let mut next_wakeup = Instant::now();
    let res = node.process_effects(vec![effect], Instant::now(), 0, &mut next_wakeup);

    assert!(res.is_err());
    // Cache should NOT be cleared on failure
    assert_eq!(node.engine.pending_cache_len(), 1);
}

#[test]
fn test_pending_cache_cleared_on_success() {
    let alice = TestIdentity::new();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();
    let transport = DummyTransport(alice.device_pk);

    let engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    let mut node = MerkleToxNode::new(engine, transport, store, tp);

    let cid = ConversationId::from([1u8; 32]);
    let node_data = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: alice.master_pk,
        sender_pk: alice.device_pk,
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text("Success".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: merkle_tox_core::dag::NodeAuth::EphemeralSignature(Ed25519Signature::from(
            [0u8; 64],
        )),
        pow_nonce: 0,
    };

    node.engine.put_pending_node(node_data.clone());

    assert_eq!(node.engine.pending_cache_len(), 1);

    let effect = Effect::WriteStore(cid, node_data, true);

    let mut next_wakeup = Instant::now();
    let res = node.process_effects(vec![effect], Instant::now(), 0, &mut next_wakeup);

    assert!(res.is_ok());
    // Cache SHOULD be cleared on success
    assert_eq!(node.engine.pending_cache_len(), 0);
}
