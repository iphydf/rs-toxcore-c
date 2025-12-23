use crate::crypto::{ConversationKeys, ratchet_merge};
use crate::dag::{
    ChainKey, ConversationId, KConv, MerkleNode, MessageKey, NodeAuth, NodeHash, PhysicalDevicePk,
    WireNode,
};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone)]
pub struct Pending {
    pub speculative_nodes: HashSet<NodeHash>,
    pub vouchers: HashMap<NodeHash, HashSet<PhysicalDevicePk>>,
}

#[derive(Clone)]
pub struct Established {
    pub epochs: HashMap<u64, ConversationKeys>,
    pub head_chains: HashMap<NodeHash, ChainKey>,
    /// Recent historical keys kept in memory to support concurrent branching.
    /// Maps Hash -> ChainKey.
    pub historical_chains: HashMap<NodeHash, ChainKey>,
    /// FIFO queue of hashes in historical_chains to enforce a size limit.
    pub historical_order: VecDeque<NodeHash>,
    pub current_epoch: u64,
    pub message_count: u32,
    pub last_rotation_time_ms: i64,
    pub vouchers: HashMap<NodeHash, HashSet<PhysicalDevicePk>>,
}

const MAX_HISTORICAL_KEYS: usize = 64;

#[derive(Clone)]
pub struct ConversationData<S> {
    pub id: ConversationId,
    pub state: S,
}

#[derive(Clone)]
pub enum Conversation {
    Pending(ConversationData<Pending>),
    Established(ConversationData<Established>),
}

impl Conversation {
    pub fn id(&self) -> ConversationId {
        match self {
            Conversation::Pending(c) => c.id,
            Conversation::Established(c) => c.id,
        }
    }

    pub fn is_established(&self) -> bool {
        matches!(self, Conversation::Established(_))
    }

    pub fn vouchers(&self) -> &HashMap<NodeHash, HashSet<PhysicalDevicePk>> {
        match self {
            Conversation::Pending(c) => &c.state.vouchers,
            Conversation::Established(c) => &c.state.vouchers,
        }
    }

    pub fn vouchers_mut(&mut self) -> &mut HashMap<NodeHash, HashSet<PhysicalDevicePk>> {
        match self {
            Conversation::Pending(c) => &mut c.state.vouchers,
            Conversation::Established(c) => &mut c.state.vouchers,
        }
    }
}

impl ConversationData<Pending> {
    pub fn new(id: ConversationId) -> Self {
        Self {
            id,
            state: Pending {
                speculative_nodes: HashSet::new(),
                vouchers: HashMap::new(),
            },
        }
    }

    pub fn establish(
        self,
        initial_k_conv: KConv,
        now_ms: i64,
        epoch: u64,
    ) -> ConversationData<Established> {
        let mut epochs = HashMap::new();
        epochs.insert(epoch, ConversationKeys::derive(&initial_k_conv));
        ConversationData {
            id: self.id,
            state: Established {
                epochs,
                head_chains: HashMap::new(),
                historical_chains: HashMap::new(),
                historical_order: VecDeque::new(),
                current_epoch: epoch,
                message_count: 0,
                last_rotation_time_ms: now_ms,
                vouchers: self.state.vouchers,
            },
        }
    }

    pub fn record_speculative(&mut self, hash: NodeHash) {
        self.state.speculative_nodes.insert(hash);
    }
}

impl ConversationData<Established> {
    pub fn new(id: ConversationId, initial_k_conv: KConv, now_ms: i64) -> Self {
        let mut epochs = HashMap::new();
        epochs.insert(0, ConversationKeys::derive(&initial_k_conv));
        Self {
            id,
            state: Established {
                epochs,
                head_chains: HashMap::new(),
                historical_chains: HashMap::new(),
                historical_order: VecDeque::new(),
                current_epoch: 0,
                message_count: 0,
                last_rotation_time_ms: now_ms,
                vouchers: HashMap::new(),
            },
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.state.current_epoch
    }

    pub fn get_keys(&self, epoch: u64) -> Option<&ConversationKeys> {
        self.state.epochs.get(&epoch)
    }

    pub fn rotate(&mut self, new_k_conv: KConv, now_ms: i64) -> u64 {
        self.state.current_epoch += 1;
        self.state.epochs.insert(
            self.state.current_epoch,
            ConversationKeys::derive(&new_k_conv),
        );
        self.state.head_chains.clear(); // Reset ratchets on epoch rotation
        self.state.historical_chains.clear();
        self.state.historical_order.clear();
        self.state.message_count = 0;
        self.state.last_rotation_time_ms = now_ms;
        self.state.current_epoch
    }

    pub fn add_epoch(&mut self, epoch: u64, k_conv: KConv) {
        self.state
            .epochs
            .insert(epoch, ConversationKeys::derive(&k_conv));
        if epoch > self.state.current_epoch {
            self.state.current_epoch = epoch;
            self.state.head_chains.clear();
            self.state.historical_chains.clear();
            self.state.historical_order.clear();
            self.state.message_count = 0;
        }
    }

    pub fn peek_keys(&self, parents: &[NodeHash]) -> Option<(MessageKey, ChainKey)> {
        let mut parent_keys = Vec::with_capacity(parents.len());
        tracing::debug!(
            "peek_keys: searching for {} parents. head_chains={}, historical_chains={}",
            parents.len(),
            self.state.head_chains.len(),
            self.state.historical_chains.len()
        );
        for p in parents {
            if let Some(key) = self.state.head_chains.get(p) {
                parent_keys.push(key.clone());
            } else if let Some(key) = self.state.historical_chains.get(p) {
                parent_keys.push(key.clone());
            } else {
                tracing::debug!("  Parent key not found for {}", hex::encode(p.as_bytes()));
            }
        }

        if !parent_keys.is_empty() && parent_keys.len() < parents.len() {
            tracing::debug!(
                "  Some parent keys missing (found {}/{}), cannot derive merged key",
                parent_keys.len(),
                parents.len()
            );
            return None;
        }

        let current_chain_key = if parent_keys.is_empty() {
            tracing::debug!(
                "No parent keys found for parents {:?}, using epoch root",
                parents
            );
            self.get_keys(self.state.current_epoch)?
                .k_conv
                .to_chain_key()
        } else if parent_keys.len() == 1 {
            tracing::debug!(
                "Found 1 parent key for parent {}",
                hex::encode(parents[0].as_bytes())
            );
            parent_keys[0].clone()
        } else {
            tracing::debug!("Merging {} parent keys", parent_keys.len());
            ratchet_merge(&parent_keys)
        };

        let k_msg = crate::crypto::ratchet_message_key(&current_chain_key);
        let k_next = crate::crypto::ratchet_step(&current_chain_key);

        Some((k_msg, k_next))
    }

    pub fn commit_node_key(
        &mut self,
        node_hash: NodeHash,
        parents: &[NodeHash],
        chain_key: ChainKey,
    ) {
        tracing::debug!(
            "Committing key for node {}: parents={:?}",
            hex::encode(node_hash.as_bytes()),
            parents
        );
        for p in parents {
            if let Some(key) = self.state.head_chains.remove(p) {
                // Move to historical cache
                if !self.state.historical_chains.contains_key(p) {
                    tracing::debug!(
                        "  Moving parent key {} to historical cache",
                        hex::encode(p.as_bytes())
                    );
                    self.state.historical_chains.insert(*p, key);
                    self.state.historical_order.push_back(*p);
                    if self.state.historical_order.len() > MAX_HISTORICAL_KEYS
                        && let Some(oldest) = self.state.historical_order.pop_front()
                    {
                        self.state.historical_chains.remove(&oldest);
                    }
                }
            }
        }
        self.state.head_chains.insert(node_hash, chain_key);
    }

    pub fn get_node_chain_key(&self, hash: &NodeHash) -> Option<&ChainKey> {
        self.state.head_chains.get(hash)
    }

    pub fn verify_node_mac(&self, conversation_id: &ConversationId, node: &MerkleNode) -> bool {
        let mac = match &node.authentication {
            NodeAuth::Mac(m) => m,
            _ => return true, // Signatures are "authentic" for this layer
        };

        if let Some((k_msg, _)) = self.peek_keys(&node.parents) {
            let keys = ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()));
            if keys.verify_mac(&node.serialize_for_auth(conversation_id), mac) {
                return true;
            }
        }

        let auth_data = node.serialize_for_auth(conversation_id);
        let mut epochs: Vec<_> = self.state.epochs.keys().copied().collect();
        epochs.sort_unstable_by(|a, b| b.cmp(a));

        for epoch in epochs {
            if let Some(keys) = self.state.epochs.get(&epoch) {
                // Try root key
                if keys.verify_mac(&auth_data, mac) {
                    return true;
                }

                // Try first message key
                let chain_key = keys.k_conv.to_chain_key();
                let k_msg = crate::crypto::ratchet_message_key(&chain_key);
                let msg_keys = ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()));
                if msg_keys.verify_mac(&auth_data, mac) {
                    return true;
                }
            }
        }

        false
    }

    pub fn unpack_node(
        &self,
        conversation_id: &ConversationId,
        wire: &WireNode,
    ) -> Option<MerkleNode> {
        if let Some((k_msg, _)) = self.peek_keys(&wire.parents) {
            let msg_keys = ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()));
            if let Ok(node) = MerkleNode::unpack_wire(wire, &msg_keys, conversation_id) {
                return Some(node);
            }
        }

        let mut epochs: Vec<_> = self.state.epochs.keys().copied().collect();
        epochs.sort_unstable_by(|a, b| b.cmp(a));

        for epoch in epochs {
            if let Some(keys) = self.state.epochs.get(&epoch) {
                // Try root key
                if let Ok(node) = MerkleNode::unpack_wire(wire, keys, conversation_id) {
                    return Some(node);
                }

                // Try first message key
                let chain_key = keys.k_conv.to_chain_key();
                let k_msg = crate::crypto::ratchet_message_key(&chain_key);
                let msg_keys = ConversationKeys::derive(&KConv::from(*k_msg.as_bytes()));
                if let Ok(node) = MerkleNode::unpack_wire(wire, &msg_keys, conversation_id) {
                    return Some(node);
                }
            }
        }

        None
    }
}
