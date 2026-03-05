use crate::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use crate::dag::{
    ChainKey, ConversationId, KConv, MerkleNode, NodeHash, NodeType, PhysicalDevicePk,
};
use crate::error::{MerkleToxError, MerkleToxResult};
use crate::sync::{FullStore, SyncRange};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::RwLock;

/// A thread-safe in-memory store for protocol nodes and blobs.
#[derive(Default)]
pub struct InMemoryStore {
    /// BTreeMap: iteration order matters because verification cascades and
    /// `get_verified_nodes_by_type` consume sibling nodes in sequence.
    pub nodes: RwLock<BTreeMap<NodeHash, (MerkleNode, bool)>>,
    /// BTreeSet for deterministic iteration order — reverify cascades
    /// pick nodes in iteration order, which propagates to wire-visible
    /// fetch and head-update sequencing.
    pub speculative_nodes: RwLock<BTreeSet<NodeHash>>,
    pub opaque_nodes: RwLock<BTreeSet<NodeHash>>,
    pub wire_nodes: RwLock<HashMap<NodeHash, (ConversationId, crate::dag::WireNode)>>,
    pub children: RwLock<HashMap<NodeHash, Vec<NodeHash>>>,
    pub admin_distance_cache: RwLock<HashMap<NodeHash, u64>>,
    pub last_sequence_numbers: RwLock<HashMap<PhysicalDevicePk, u64>>,
    pub heads: RwLock<HashMap<ConversationId, Vec<NodeHash>>>,
    pub admin_heads: RwLock<HashMap<ConversationId, Vec<NodeHash>>>,
    pub blobs: RwLock<HashMap<NodeHash, (BlobInfo, Vec<u8>)>>,
    pub keys: RwLock<HashMap<(ConversationId, u64), KConv>>,
    pub ratchet_keys: RwLock<HashMap<(ConversationId, NodeHash), (ChainKey, u64)>>,
    pub meta: RwLock<HashMap<ConversationId, (u32, i64)>>,
    pub sketches: RwLock<HashMap<(ConversationId, SyncRange), Vec<u8>>>,
    pub global_offset: RwLock<Option<i64>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::dag::NodeLookup for InMemoryStore {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType> {
        self.nodes
            .read()
            .unwrap()
            .get(hash)
            .map(|(n, _)| n.node_type())
    }
    fn get_rank(&self, hash: &NodeHash) -> Option<u64> {
        self.nodes
            .read()
            .unwrap()
            .get(hash)
            .map(|(n, _)| n.topological_rank)
    }
    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64> {
        if let Some(&dist) = self.admin_distance_cache.read().unwrap().get(hash) {
            return Some(dist);
        }

        // For testing, calculate it on the fly recursively
        let node = self
            .nodes
            .read()
            .unwrap()
            .get(hash)
            .map(|(n, _)| n.clone())?;
        if node.node_type() == crate::dag::NodeType::Admin {
            self.admin_distance_cache.write().unwrap().insert(*hash, 0);
            return Some(0);
        }
        let mut min_dist = u64::MAX;
        for parent in &node.parents {
            if let Some(dist) = self.get_admin_distance(parent) {
                min_dist = min_dist.min(dist);
            }
        }
        let result = if min_dist == u64::MAX {
            Some(10) // For unit tests, assume isolated nodes have a valid distance.
        } else {
            Some(min_dist + 1)
        };
        if let Some(d) = result {
            self.admin_distance_cache.write().unwrap().insert(*hash, d);
        }
        result
    }
    fn contains_node(&self, hash: &NodeHash) -> bool {
        self.nodes.read().unwrap().contains_key(hash)
    }
    fn has_children(&self, hash: &NodeHash) -> bool {
        self.children
            .read()
            .unwrap()
            .get(hash)
            .is_some_and(|c| !c.is_empty())
    }
    fn get_soft_anchor_chain_length(&self, hash: &NodeHash) -> Option<u64> {
        let node = self
            .nodes
            .read()
            .unwrap()
            .get(hash)
            .map(|(n, _)| n.clone())?;
        if let crate::dag::Content::Control(crate::dag::ControlAction::SoftAnchor {
            basis_hash,
            ..
        }) = &node.content
        {
            let parent_count = self.get_soft_anchor_chain_length(basis_hash).unwrap_or(0);
            Some(1 + parent_count)
        } else {
            Some(0)
        }
    }
}

impl crate::sync::NodeStore for InMemoryStore {
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        self.heads
            .read()
            .unwrap()
            .get(conversation_id)
            .cloned()
            .unwrap_or_default()
    }
    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        self.heads.write().unwrap().insert(*conversation_id, heads);
        Ok(())
    }
    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        self.admin_heads
            .read()
            .unwrap()
            .get(conversation_id)
            .cloned()
            .unwrap_or_default()
    }
    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        self.admin_heads
            .write()
            .unwrap()
            .insert(*conversation_id, heads);
        Ok(())
    }
    fn has_node(&self, hash: &NodeHash) -> bool {
        self.nodes.read().unwrap().contains_key(hash)
    }
    fn is_verified(&self, hash: &NodeHash) -> bool {
        self.nodes
            .read()
            .unwrap()
            .get(hash)
            .is_some_and(|(_, v)| *v)
    }
    fn get_node(&self, hash: &NodeHash) -> Option<MerkleNode> {
        self.nodes.read().unwrap().get(hash).map(|(n, _)| n.clone())
    }
    fn get_wire_node(&self, hash: &NodeHash) -> Option<crate::dag::WireNode> {
        self.wire_nodes
            .read()
            .unwrap()
            .get(hash)
            .map(|(_, w)| w.clone())
    }
    fn put_node(
        &self,
        _conv_id: &ConversationId,
        node: MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()> {
        let hash = node.hash();

        let mut min_dist = u64::MAX;
        if node.node_type() == crate::dag::NodeType::Admin {
            self.admin_distance_cache.write().unwrap().insert(hash, 0);
        } else {
            for parent in &node.parents {
                if let Some(&dist) = self.admin_distance_cache.read().unwrap().get(parent) {
                    min_dist = min_dist.min(dist);
                }
            }
            let dist = if min_dist == u64::MAX {
                10
            } else {
                min_dist + 1
            };
            self.admin_distance_cache
                .write()
                .unwrap()
                .insert(hash, dist);
        }

        for parent in &node.parents {
            self.children
                .write()
                .unwrap()
                .entry(*parent)
                .or_default()
                .push(hash);
        }
        if verified {
            self.speculative_nodes.write().unwrap().remove(&hash);
            let mut lsn = self.last_sequence_numbers.write().unwrap();
            let current = lsn.entry(node.sender_pk).or_insert(0);
            if node.sequence_number > *current {
                *current = node.sequence_number;
            }
        } else {
            self.speculative_nodes.write().unwrap().insert(hash);
        }
        self.opaque_nodes.write().unwrap().remove(&hash);
        self.nodes.write().unwrap().insert(hash, (node, verified));
        Ok(())
    }
    fn put_wire_node(
        &self,
        conv_id: &ConversationId,
        hash: &NodeHash,
        node: crate::dag::WireNode,
    ) -> MerkleToxResult<()> {
        self.wire_nodes
            .write()
            .unwrap()
            .insert(*hash, (*conv_id, node));
        if !self.nodes.read().unwrap().contains_key(hash) {
            self.opaque_nodes.write().unwrap().insert(*hash);
        }
        Ok(())
    }
    fn remove_wire_node(&self, _conv_id: &ConversationId, hash: &NodeHash) -> MerkleToxResult<()> {
        self.wire_nodes.write().unwrap().remove(hash);
        self.opaque_nodes.write().unwrap().remove(hash);
        Ok(())
    }
    fn get_opaque_node_hashes(
        &self,
        _conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let opaque = self.opaque_nodes.read().unwrap();
        Ok(opaque.iter().cloned().collect())
    }

    fn get_speculative_nodes(&self, _conv_id: &ConversationId) -> Vec<MerkleNode> {
        let speculative = self.speculative_nodes.read().unwrap();
        let nodes = self.nodes.read().unwrap();
        let mut result = Vec::new();
        for hash in speculative.iter() {
            if let Some((node, _)) = nodes.get(hash) {
                result.push(node.clone());
            }
        }
        result
    }
    fn mark_verified(&self, _conv_id: &ConversationId, hash: &NodeHash) -> MerkleToxResult<()> {
        let mut sender_seq = None;
        if let Some((node, v)) = self.nodes.write().unwrap().get_mut(hash) {
            *v = true;
            sender_seq = Some((node.sender_pk, node.sequence_number));
        }
        if let Some((sender_pk, seq)) = sender_seq {
            let mut lsn = self.last_sequence_numbers.write().unwrap();
            let current = lsn.entry(sender_pk).or_insert(0);
            if seq > *current {
                *current = seq;
            }
        }
        self.speculative_nodes.write().unwrap().remove(hash);
        Ok(())
    }
    fn get_last_sequence_number(
        &self,
        _conv_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64 {
        *self
            .last_sequence_numbers
            .read()
            .unwrap()
            .get(sender_pk)
            .unwrap_or(&0)
    }
    fn get_node_counts(&self, _cid: &ConversationId) -> (usize, usize) {
        let nodes = self.nodes.read().unwrap();
        let ver = nodes.values().filter(|(_, v)| *v).count();
        let spec = nodes.values().filter(|(_, v)| !*v).count();
        (ver, spec)
    }
    fn get_verified_nodes_by_type(
        &self,
        _conversation_id: &ConversationId,
        node_type: NodeType,
    ) -> MerkleToxResult<Vec<MerkleNode>> {
        let nodes = self.nodes.read().unwrap();
        let mut res: Vec<_> = nodes
            .values()
            .filter(|(n, v)| *v && n.node_type() == node_type)
            .map(|(n, _)| n.clone())
            .collect();
        // Total order: rank then hash. Without the hash tiebreaker, sibling
        // nodes with the same rank kept their HashMap iteration order, which
        // randomizes per process and makes the verification cascade
        // non-deterministic.
        res.sort_by_key(|n| (n.topological_rank, n.hash()));
        Ok(res)
    }
    fn get_node_hashes_in_range(
        &self,
        _conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let nodes = self.nodes.read().unwrap();
        Ok(nodes
            .values()
            .filter(|(n, v)| {
                *v && n.topological_rank >= range.min_rank && n.topological_rank <= range.max_rank
            })
            .map(|(n, _)| n.hash())
            .collect())
    }
    fn size_bytes(&self) -> u64 {
        let mut total = 0;
        total += self.nodes.read().unwrap().len() as u64 * 512; // Approx size per node
        total += self
            .blobs
            .read()
            .unwrap()
            .values()
            .map(|(_, b)| b.len() as u64)
            .sum::<u64>();
        total
    }
    fn put_conversation_key(
        &self,
        cid: &ConversationId,
        epoch: u64,
        k: KConv,
    ) -> MerkleToxResult<()> {
        self.keys.write().unwrap().insert((*cid, epoch), k);
        Ok(())
    }
    fn get_conversation_keys(&self, cid: &ConversationId) -> MerkleToxResult<Vec<(u64, KConv)>> {
        let keys = self.keys.read().unwrap();
        let mut res: Vec<_> = keys
            .iter()
            .filter(|((c, _), _)| c == cid)
            .map(|((_, e), k)| (*e, k.clone()))
            .collect();
        res.sort_by_key(|(e, _)| *e);
        Ok(res)
    }
    fn update_epoch_metadata(
        &self,
        cid: &ConversationId,
        count: u32,
        time: i64,
    ) -> MerkleToxResult<()> {
        self.meta.write().unwrap().insert(*cid, (count, time));
        Ok(())
    }
    fn get_epoch_metadata(&self, cid: &ConversationId) -> MerkleToxResult<Option<(u32, i64)>> {
        Ok(self.meta.read().unwrap().get(cid).copied())
    }
    fn put_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
        chain_key: ChainKey,
        epoch_id: u64,
    ) -> MerkleToxResult<()> {
        self.ratchet_keys
            .write()
            .unwrap()
            .insert((*conversation_id, *node_hash), (chain_key, epoch_id));
        Ok(())
    }
    fn get_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<Option<(ChainKey, u64)>> {
        Ok(self
            .ratchet_keys
            .read()
            .unwrap()
            .get(&(*conversation_id, *node_hash))
            .cloned())
    }
    fn remove_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        self.ratchet_keys
            .write()
            .unwrap()
            .remove(&(*conversation_id, *node_hash));
        Ok(())
    }
}

impl crate::sync::BlobStore for InMemoryStore {
    fn has_blob(&self, hash: &NodeHash) -> bool {
        self.blobs
            .read()
            .unwrap()
            .get(hash)
            .is_some_and(|(i, _)| i.status == BlobStatus::Available)
    }
    fn get_blob_info(&self, hash: &NodeHash) -> Option<BlobInfo> {
        self.blobs.read().unwrap().get(hash).map(|(i, _)| i.clone())
    }
    fn put_blob_info(&self, info: BlobInfo) -> MerkleToxResult<()> {
        let mut blobs = self.blobs.write().unwrap();
        let hash = info.hash;
        if let Some((i, _)) = blobs.get_mut(&hash) {
            *i = info;
        } else {
            blobs.insert(hash, (info, Vec::new()));
        }
        Ok(())
    }
    fn put_chunk(
        &self,
        _cid: &ConversationId,
        hash: &NodeHash,
        offset: u64,
        data: &[u8],
        _proof: Option<&[u8]>,
    ) -> MerkleToxResult<()> {
        let mut blobs = self.blobs.write().unwrap();
        if let Some((info, buffer)) = blobs.get_mut(hash) {
            let first_write = buffer.is_empty();
            if first_write {
                *buffer = vec![0u8; info.size as usize];
            }
            let end = (offset as usize + data.len()).min(buffer.len());
            buffer[offset as usize..end].copy_from_slice(&data[..end - offset as usize]);

            // Update mask — mark ALL chunks covered by this write.
            let first_chunk = offset / CHUNK_SIZE;
            let last_byte = offset + data.len() as u64;
            let last_chunk = if last_byte == 0 {
                0
            } else {
                (last_byte - 1) / CHUNK_SIZE
            };
            let num_chunks = info.size.div_ceil(CHUNK_SIZE);
            let mut mask = if first_write {
                vec![0u8; num_chunks.div_ceil(8) as usize]
            } else {
                info.received_mask
                    .take()
                    .unwrap_or_else(|| vec![0u8; num_chunks.div_ceil(8) as usize])
            };
            for chunk_idx in first_chunk..=last_chunk {
                let byte_idx = (chunk_idx / 8) as usize;
                let bit_idx = (chunk_idx % 8) as u8;
                if byte_idx < mask.len() {
                    mask[byte_idx] |= 1 << bit_idx;
                }
            }

            // Check if complete
            let mut complete = true;
            for i in 0..num_chunks {
                let b_idx = (i / 8) as usize;
                let bit = (i % 8) as u8;
                if (mask[b_idx] & (1 << bit)) == 0 {
                    complete = false;
                    break;
                }
            }

            if complete {
                info.status = BlobStatus::Available;
            } else {
                info.status = BlobStatus::Downloading;
            }
            info.received_mask = Some(mask);
        }
        Ok(())
    }
    fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> MerkleToxResult<Vec<u8>> {
        let blobs = self.blobs.read().unwrap();
        let (_, buffer) = blobs.get(hash).ok_or(MerkleToxError::BlobNotFound(*hash))?;
        let start = offset as usize;
        if start >= buffer.len() {
            return Err(MerkleToxError::BlobNotFound(*hash));
        }
        let end = (start + length as usize).min(buffer.len());
        Ok(buffer[start..end].to_vec())
    }
}

impl crate::sync::GlobalStore for InMemoryStore {
    fn get_global_offset(&self) -> Option<i64> {
        *self.global_offset.read().unwrap()
    }
    fn set_global_offset(&self, offset: i64) -> MerkleToxResult<()> {
        *self.global_offset.write().unwrap() = Some(offset);
        Ok(())
    }
}

impl crate::sync::ReconciliationStore for InMemoryStore {
    fn put_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
        sketch: &[u8],
    ) -> MerkleToxResult<()> {
        self.sketches
            .write()
            .unwrap()
            .insert((*conversation_id, range.clone()), sketch.to_vec());
        Ok(())
    }

    fn get_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Option<Vec<u8>>> {
        Ok(self
            .sketches
            .read()
            .unwrap()
            .get(&(*conversation_id, range.clone()))
            .cloned())
    }
}

/// A trait for stores managed by a test runner.
pub trait ManagedStore: FullStore {
    fn name(&self) -> &str;
    fn reopen(&mut self);
}

#[macro_export]
#[doc(hidden)]
macro_rules! __delegate_store {
    ($target:ident, $field:ident) => {
        impl $crate::dag::NodeLookup for $target {
            fn get_node_type(&self, hash: &$crate::dag::NodeHash) -> Option<$crate::dag::NodeType> {
                self.$field.get_node_type(hash)
            }
            fn get_rank(&self, hash: &$crate::dag::NodeHash) -> Option<u64> {
                self.$field.get_rank(hash)
            }
            fn get_admin_distance(&self, hash: &$crate::dag::NodeHash) -> Option<u64> {
                self.$field.get_admin_distance(hash)
            }
            fn contains_node(&self, hash: &$crate::dag::NodeHash) -> bool {
                self.$field.contains_node(hash)
            }
            fn has_children(&self, hash: &$crate::dag::NodeHash) -> bool {
                self.$field.has_children(hash)
            }
            fn get_soft_anchor_chain_length(&self, hash: &$crate::dag::NodeHash) -> Option<u64> {
                self.$field.get_soft_anchor_chain_length(hash)
            }
        }

        impl $crate::sync::NodeStore for $target {
            fn get_heads(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> Vec<$crate::dag::NodeHash> {
                self.$field.get_heads(conversation_id)
            }
            fn set_heads(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                heads: Vec<$crate::dag::NodeHash>,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.set_heads(conversation_id, heads)
            }
            fn get_admin_heads(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> Vec<$crate::dag::NodeHash> {
                self.$field.get_admin_heads(conversation_id)
            }
            fn set_admin_heads(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                heads: Vec<$crate::dag::NodeHash>,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.set_admin_heads(conversation_id, heads)
            }
            fn has_node(&self, hash: &$crate::dag::NodeHash) -> bool {
                self.$field.has_node(hash)
            }
            fn is_verified(&self, hash: &$crate::dag::NodeHash) -> bool {
                self.$field.is_verified(hash)
            }
            fn get_node(&self, hash: &$crate::dag::NodeHash) -> Option<$crate::dag::MerkleNode> {
                self.$field.get_node(hash)
            }
            fn get_wire_node(&self, hash: &$crate::dag::NodeHash) -> Option<$crate::dag::WireNode> {
                self.$field.get_wire_node(hash)
            }
            fn put_node(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                node: $crate::dag::MerkleNode,
                verified: bool,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.put_node(conversation_id, node, verified)
            }
            fn put_wire_node(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                hash: &$crate::dag::NodeHash,
                node: $crate::dag::WireNode,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.put_wire_node(conversation_id, hash, node)
            }
            fn remove_wire_node(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                hash: &$crate::dag::NodeHash,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.remove_wire_node(conversation_id, hash)
            }
            fn get_speculative_nodes(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> Vec<$crate::dag::MerkleNode> {
                self.$field.get_speculative_nodes(conversation_id)
            }
            fn mark_verified(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                hash: &$crate::dag::NodeHash,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.mark_verified(conversation_id, hash)
            }
            fn get_last_sequence_number(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                sender_pk: &$crate::dag::PhysicalDevicePk,
            ) -> u64 {
                self.$field
                    .get_last_sequence_number(conversation_id, sender_pk)
            }
            fn get_node_counts(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> (usize, usize) {
                self.$field.get_node_counts(conversation_id)
            }
            fn get_verified_nodes_by_type(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                node_type: $crate::dag::NodeType,
            ) -> $crate::error::MerkleToxResult<Vec<$crate::dag::MerkleNode>> {
                self.$field
                    .get_verified_nodes_by_type(conversation_id, node_type)
            }
            fn get_node_hashes_in_range(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                range: &$crate::sync::SyncRange,
            ) -> $crate::error::MerkleToxResult<Vec<$crate::dag::NodeHash>> {
                self.$field.get_node_hashes_in_range(conversation_id, range)
            }
            fn get_opaque_node_hashes(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> $crate::error::MerkleToxResult<Vec<$crate::dag::NodeHash>> {
                self.$field.get_opaque_node_hashes(conversation_id)
            }
            fn size_bytes(&self) -> u64 {
                self.$field.size_bytes()
            }
            fn put_conversation_key(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                epoch: u64,
                k_conv: $crate::dag::KConv,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field
                    .put_conversation_key(conversation_id, epoch, k_conv)
            }
            fn get_conversation_keys(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> $crate::error::MerkleToxResult<Vec<(u64, $crate::dag::KConv)>> {
                self.$field.get_conversation_keys(conversation_id)
            }
            fn update_epoch_metadata(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                message_count: u32,
                last_rotation_time: i64,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.update_epoch_metadata(
                    conversation_id,
                    message_count,
                    last_rotation_time,
                )
            }
            fn get_epoch_metadata(
                &self,
                conversation_id: &$crate::dag::ConversationId,
            ) -> $crate::error::MerkleToxResult<Option<(u32, i64)>> {
                self.$field.get_epoch_metadata(conversation_id)
            }
            fn put_ratchet_key(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                node_hash: &$crate::dag::NodeHash,
                chain_key: $crate::dag::ChainKey,
                epoch_id: u64,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field
                    .put_ratchet_key(conversation_id, node_hash, chain_key, epoch_id)
            }
            fn get_ratchet_key(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                node_hash: &$crate::dag::NodeHash,
            ) -> $crate::error::MerkleToxResult<Option<($crate::dag::ChainKey, u64)>> {
                self.$field.get_ratchet_key(conversation_id, node_hash)
            }
            fn remove_ratchet_key(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                node_hash: &$crate::dag::NodeHash,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.remove_ratchet_key(conversation_id, node_hash)
            }
        }

        impl $crate::sync::BlobStore for $target {
            fn has_blob(&self, hash: &$crate::dag::NodeHash) -> bool {
                self.$field.has_blob(hash)
            }
            fn get_blob_info(&self, hash: &$crate::dag::NodeHash) -> Option<$crate::cas::BlobInfo> {
                self.$field.get_blob_info(hash)
            }
            fn put_blob_info(
                &self,
                info: $crate::cas::BlobInfo,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.put_blob_info(info)
            }
            fn put_chunk(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                hash: &$crate::dag::NodeHash,
                offset: u64,
                data: &[u8],
                proof: Option<&[u8]>,
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field
                    .put_chunk(conversation_id, hash, offset, data, proof)
            }
            fn get_chunk(
                &self,
                hash: &$crate::dag::NodeHash,
                offset: u64,
                length: u32,
            ) -> $crate::error::MerkleToxResult<Vec<u8>> {
                self.$field.get_chunk(hash, offset, length)
            }
        }

        impl $crate::sync::GlobalStore for $target {
            fn get_global_offset(&self) -> Option<i64> {
                self.$field.get_global_offset()
            }
            fn set_global_offset(&self, offset: i64) -> $crate::error::MerkleToxResult<()> {
                self.$field.set_global_offset(offset)
            }
        }

        impl $crate::sync::ReconciliationStore for $target {
            fn put_sketch(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                range: &$crate::sync::SyncRange,
                sketch: &[u8],
            ) -> $crate::error::MerkleToxResult<()> {
                self.$field.put_sketch(conversation_id, range, sketch)
            }
            fn get_sketch(
                &self,
                conversation_id: &$crate::dag::ConversationId,
                range: &$crate::sync::SyncRange,
            ) -> $crate::error::MerkleToxResult<Option<Vec<u8>>> {
                self.$field.get_sketch(conversation_id, range)
            }
        }
    };
}

pub use __delegate_store as delegate_store;
