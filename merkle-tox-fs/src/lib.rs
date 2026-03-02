pub mod blob;
pub mod journal;
pub mod opaque;
pub mod pack;
pub mod state;

use crate::blob::BlobStore;
use crate::journal::{Journal, JournalRecordType};
use crate::opaque::OpaqueStore;
use crate::pack::Pack;
use crate::state::{ConvState, RatchetFile, StateFile};

use merkle_tox_core::cas::{BlobInfo, BlobStatus};
use merkle_tox_core::dag::{
    ChainKey, ConversationId, KConv, MerkleNode, NodeHash, NodeLookup, NodeType, PhysicalDevicePk,
    WireNode,
};
use merkle_tox_core::error::{MerkleToxError, MerkleToxResult};
use merkle_tox_core::sync::{
    BlobStore as BlobStoreTrait, GlobalStore, NodeStore, ReconciliationStore, SyncRange,
};
use merkle_tox_core::vfs::{FileHandle, FileSystem, StdFileSystem};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io::{self, Error};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct FsStore<F: FileSystem = StdFileSystem> {
    root: PathBuf,
    fs: Arc<F>,
    inner: Arc<RwLock<FsInner<F>>>,
    blob_store: Arc<BlobStore<F>>,
}

const COMPACT_THRESHOLD: usize = 500;

struct FsInner<F: FileSystem> {
    conversations: HashMap<ConversationId, ConversationContext<F>>,
    node_to_conv: HashMap<NodeHash, ConversationId>,
    global_offset: Option<i64>,
    _lock_file: Box<dyn FileHandle>,
}

struct ConversationContext<F: FileSystem> {
    id: ConversationId,
    path: PathBuf,
    state: ConvState,
    journal: Mutex<Journal<F>>,
    ratchet: Mutex<RatchetFile<F>>,
    opaque: OpaqueStore<F>,
    packs: Vec<Pack<F>>,
    lock_file: Box<dyn FileHandle>,

    // Volatile index
    volatile_nodes: HashMap<NodeHash, JournalNodeInfo>,
    hot_ratchets: HashMap<NodeHash, (ChainKey, u64)>, // (key, epoch_id)
    latest_ratchets: HashMap<PhysicalDevicePk, (ChainKey, u64, NodeHash, u64)>, // (key, seq, hash, epoch_id)
    last_seq_numbers: HashMap<PhysicalDevicePk, u64>,
    child_index: HashMap<NodeHash, Vec<NodeHash>>,
}

struct JournalNodeInfo {
    node_type: NodeType,
    rank: u64,
    admin_distance: u16,
    sender_pk: PhysicalDevicePk,
    sequence_number: u64,
    verified: bool,
    offset: u64,
}

impl<F: FileSystem> FsStore<F> {
    pub fn new(root: PathBuf, fs: Arc<F>) -> MerkleToxResult<Self> {
        if !fs.exists(&root) {
            fs.create_dir_all(&root)?;
        } else if !fs.metadata(&root)?.is_dir {
            return Err(MerkleToxError::Io(Error::other(
                "Root path is not a directory",
            )));
        }

        fs.create_dir_all(&root.join("conversations"))?;
        fs.create_dir_all(&root.join("objects"))?;

        if !fs.exists(&root.join("blacklist.bin")) {
            fs.write(&root.join("blacklist.bin"), &[])?;
        }

        // Global lock
        let lock_file = fs.open(&root.join(".lock"), true, true, false)?;
        lock_file.try_lock_shared().map_err(|_| {
            MerkleToxError::Io(Error::other(
                "Storage root is locked exclusively by another process",
            ))
        })?;

        let blob_store = Arc::new(BlobStore::new(root.join("objects"), fs.clone()));

        let store = Self {
            root: root.clone(),
            fs,
            inner: Arc::new(RwLock::new(FsInner {
                conversations: HashMap::new(),
                node_to_conv: HashMap::new(),
                global_offset: None,
                _lock_file: lock_file,
            })),
            blob_store,
        };

        store.load_global_state()?;
        store.discover_conversations()?;

        Ok(store)
    }

    fn discover_conversations(&self) -> io::Result<()> {
        let conv_dir = self.root.join("conversations");
        if let Ok(entries) = self.fs.read_dir(&conv_dir) {
            for entry in entries {
                let name = entry.file_name().unwrap();
                let name_str = name.to_string_lossy();
                if let Some(id_bytes) = decode_hex_32(&name_str) {
                    let id = ConversationId::from(id_bytes);
                    let _ = self.ensure_conversation(&id);
                }
            }
        }
        Ok(())
    }

    fn load_global_state(&self) -> io::Result<()> {
        let path = self.root.join("global.bin");
        if self.fs.exists(&path) {
            let data = self.fs.read(&path)?;
            if data.len() >= 8 {
                let offset = i64::from_le_bytes(data[0..8].try_into().unwrap());
                self.inner.write().global_offset = Some(offset);
            }
        }
        Ok(())
    }

    pub fn compact(&self, id: &ConversationId) -> MerkleToxResult<()> {
        self.ensure_conversation(id)?;
        let mut inner = self.inner.write();
        {
            let ctx = inner.conversations.get_mut(id).unwrap();
            ctx.lock_file.try_lock_exclusive().map_err(|_| {
                MerkleToxError::Io(Error::other(
                    "Failed to upgrade to exclusive lock for compaction",
                ))
            })?;
        }
        let res = self.compact_internal(&mut inner, id);
        {
            if let Some(ctx) = inner.conversations.get_mut(id) {
                let _ = ctx.lock_file.try_lock_shared(); // downgrade back
            }
        }
        res
    }

    fn compact_internal(&self, inner: &mut FsInner<F>, id: &ConversationId) -> MerkleToxResult<()> {
        let ctx = inner.conversations.get_mut(id).unwrap();

        // 1. Shadow Write
        let records = ctx.journal.lock().read_all()?;
        let mut index_records = Vec::new();
        let mut nodes_to_pack = Vec::new();
        let mut ratchet_updates = HashMap::new();

        for rec in &records {
            if rec.record_type == JournalRecordType::Node {
                let (status, node): (u8, MerkleNode) = tox_proto::deserialize(&rec.payload)?;
                let node_hash = node.hash();
                nodes_to_pack.push((node_hash, node.clone()));

                // Track latest sequence number even if no ratchet advance
                let entry = ratchet_updates.entry(node.sender_pk).or_insert((
                    ChainKey::from([0u8; 32]),
                    0u64,
                    0u64,
                ));
                if node.sequence_number > entry.1 {
                    entry.1 = node.sequence_number;
                }

                index_records.push(pack::IndexRecord {
                    hash: node_hash,
                    offset: 0, // will be set during pack creation
                    rank: node.topological_rank,
                    payload_length: 0, // will be set during pack creation
                    node_type: if node.node_type() == NodeType::Admin {
                        0x01
                    } else {
                        0x02
                    },
                    status,
                    admin_distance: ctx
                        .volatile_nodes
                        .get(&node_hash)
                        .map(|i| i.admin_distance)
                        .unwrap_or(0),
                });
            } else if rec.record_type == JournalRecordType::RatchetAdvance {
                let (hash, key, epoch): (NodeHash, ChainKey, u64) =
                    tox_proto::deserialize(&rec.payload)?;
                if let Some(info) = ctx.volatile_nodes.get(&hash) {
                    let entry = ratchet_updates.entry(info.sender_pk).or_insert((
                        ChainKey::from([0u8; 32]),
                        0u64,
                        0u64,
                    ));
                    entry.0 = key;
                    entry.1 = info.sequence_number;
                    entry.2 = epoch;
                }
            }
        }

        if nodes_to_pack.is_empty() {
            return Ok(());
        }

        let pack_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let data_path = ctx
            .path
            .join("packs")
            .join(format!("{:016x}.pack", pack_id));
        let index_path = ctx.path.join("packs").join(format!("{:016x}.idx", pack_id));

        // Actually create the data.pack
        let mut data_file = self.fs.open(&data_path, true, true, true)?;
        for (i, (hash, node)) in nodes_to_pack.iter().enumerate() {
            let offset = data_file.stream_position()?;
            index_records[i].offset = offset;

            let status = index_records[i].status;
            let payload = tox_proto::serialize(&(status, node))?;
            index_records[i].payload_length = payload.len() as u32;

            let record_type = 0x01u8; // Node
            data_file.write_all(&(payload.len() as u32).to_le_bytes())?;
            data_file.write_all(hash.as_bytes())?;
            data_file.write_all(&[record_type])?;
            data_file.write_all(&payload)?;
        }

        let pack_index = pack::PackIndex::build(index_records, pack::DEFAULT_FANOUT_BITS, 2);
        pack_index.save(&*self.fs, &index_path)?;

        // 2. Commit
        ctx.state.active_packs.push(pack_id);

        let next_gen_id = pack_id; // use same timestamp for generation id
        ctx.journal.lock().truncate(next_gen_id)?;
        ctx.state.active_journal_id = next_gen_id;

        // Update ratchet.bin and in-memory caches
        let mut current_ratchets = ctx.ratchet.lock().load()?;
        for (pk, (key, seq, epoch)) in ratchet_updates {
            let entry = ctx.last_seq_numbers.entry(pk).or_insert(0);
            if seq > *entry {
                *entry = seq;
            }
            if key != ChainKey::from([0u8; 32]) {
                ctx.latest_ratchets
                    .insert(pk, (key.clone(), seq, NodeHash::from([0u8; 32]), epoch));
            }

            if let Some(slot) = current_ratchets.iter_mut().find(|s| s.device_pk == pk) {
                if seq > slot.last_sequence_number {
                    if key != ChainKey::from([0u8; 32]) {
                        slot.chain_key = key;
                        slot.epoch_id = epoch;
                    }
                    slot.last_sequence_number = seq;
                }
            } else {
                current_ratchets.push(state::RatchetSlot {
                    device_pk: pk,
                    chain_key: key,
                    last_sequence_number: seq,
                    epoch_id: epoch,
                });
            }
        }
        ctx.ratchet.lock().save(&current_ratchets)?;

        let state_file = StateFile::new(self.fs.clone(), ctx.path.join("state.bin"));
        state_file.save(&ctx.state)?;

        // Update ctx
        ctx.packs
            .push(Pack::open(self.fs.clone(), data_path, &index_path)?);
        ctx.volatile_nodes.clear();
        ctx.hot_ratchets.clear();

        Ok(())
    }

    fn ensure_conversation(&self, id: &ConversationId) -> MerkleToxResult<()> {
        let mut inner = self.inner.write();
        if inner.conversations.contains_key(id) {
            return Ok(());
        }

        let conv_dir = self
            .root
            .join("conversations")
            .join(encode_hex_32(id.as_bytes()));
        self.fs.create_dir_all(&conv_dir)?;
        self.fs.create_dir_all(&conv_dir.join("packs"))?;
        self.fs.create_dir_all(&conv_dir.join("opaque"))?;

        if !self.fs.exists(&conv_dir.join("permissions.bin")) {
            self.fs.write(&conv_dir.join("permissions.bin"), &[])?;
        }

        let state_file = StateFile::new(self.fs.clone(), conv_dir.join("state.bin"));
        let state = if self.fs.exists(&conv_dir.join("state.bin")) {
            state_file.load()?
        } else {
            ConvState {
                heads: Vec::new(),
                admin_heads: Vec::new(),
                message_count: 0,
                last_rotation_time: -1,
                active_packs: Vec::new(),
                active_journal_id: 0,
            }
        };

        let mut journal = Journal::open(self.fs.clone(), conv_dir.join("journal.bin"))?;

        // SPEC: Section 4.1 - Startup: If IDs mismatch, truncate the journal immediately.
        if state.active_journal_id != 0 && journal.generation_id() != state.active_journal_id {
            journal.truncate(state.active_journal_id)?;
        }

        let ratchet = RatchetFile::open(self.fs.clone(), conv_dir.join("ratchet.bin"))?;
        let opaque = OpaqueStore::new(conv_dir.join("opaque"), self.fs.clone());

        // Conversation lock
        let lock_file = self.fs.open(&conv_dir.join(".lock"), true, true, false)?;
        lock_file.try_lock_shared().map_err(|_| {
            MerkleToxError::Io(Error::other(
                "Conversation is locked exclusively by another process",
            ))
        })?;

        let mut packs = Vec::new();
        for &pack_id in &state.active_packs {
            let data_path = conv_dir
                .join("packs")
                .join(format!("{:016x}.pack", pack_id));
            let index_path = conv_dir.join("packs").join(format!("{:016x}.idx", pack_id));
            packs.push(Pack::open(self.fs.clone(), data_path, &index_path)?);
        }

        let mut ctx = ConversationContext {
            id: *id,
            path: conv_dir,
            state,
            journal: Mutex::new(journal),
            ratchet: Mutex::new(ratchet),
            opaque,
            packs,
            lock_file,
            volatile_nodes: HashMap::new(),
            hot_ratchets: HashMap::new(),
            latest_ratchets: HashMap::new(),
            last_seq_numbers: HashMap::new(),
            child_index: HashMap::new(),
        };

        // Load ratchet checkpoints
        {
            let mut r = ctx.ratchet.lock();
            let slots = r.load()?;
            for slot in slots {
                ctx.latest_ratchets.insert(
                    slot.device_pk,
                    (
                        slot.chain_key,
                        slot.last_sequence_number,
                        NodeHash::from([0u8; 32]),
                        slot.epoch_id,
                    ),
                );
                ctx.last_seq_numbers
                    .insert(slot.device_pk, slot.last_sequence_number);
            }
        }

        // Replay journal to build volatile index
        ctx.replay_journal(&mut inner.node_to_conv)?;

        // Also add packed nodes to node_to_conv
        for pack in &ctx.packs {
            for record in &pack.index.records {
                inner.node_to_conv.insert(record.hash, *id);
            }
        }

        inner.conversations.insert(*id, ctx);
        Ok(())
    }
}

impl<F: FileSystem> Drop for ConversationContext<F> {
    fn drop(&mut self) {
        let _ = self.journal.lock().write_footer();
    }
}

impl<F: FileSystem> ConversationContext<F> {
    fn replay_journal(
        &mut self,
        node_to_conv: &mut HashMap<NodeHash, ConversationId>,
    ) -> io::Result<()> {
        let mut journal = self.journal.lock();
        let records = journal.read_all()?;
        for rec in records {
            match rec.record_type {
                JournalRecordType::Node => {
                    let decoded: (u8, MerkleNode) = tox_proto::deserialize(&rec.payload)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    let (status, node) = decoded;
                    let node_hash = node.hash();

                    let mut admin_distance = 0u16;
                    if node.node_type() == merkle_tox_core::dag::NodeType::Content {
                        let mut min_dist = u64::MAX;
                        for parent in &node.parents {
                            let dist = if let Some(info) = self.volatile_nodes.get(parent) {
                                Some(info.admin_distance as u64)
                            } else {
                                let mut found = None;
                                for pack in &self.packs {
                                    if let Some(record) = pack.index.lookup(parent) {
                                        found = Some(record.admin_distance as u64);
                                        break;
                                    }
                                }
                                found
                            };
                            if let Some(d) = dist {
                                min_dist = min_dist.min(d);
                            }
                        }
                        if min_dist != u64::MAX {
                            admin_distance = (min_dist + 1).min(u16::MAX as u64) as u16;
                        } else {
                            admin_distance = u16::MAX;
                        }
                    }

                    self.volatile_nodes.insert(
                        node_hash,
                        JournalNodeInfo {
                            node_type: node.node_type(),
                            rank: node.topological_rank,
                            admin_distance,
                            sender_pk: node.sender_pk,
                            sequence_number: node.sequence_number,
                            verified: status == 0x01,
                            offset: rec.offset,
                        },
                    );
                    let entry = self.last_seq_numbers.entry(node.sender_pk).or_insert(0);
                    if node.sequence_number > *entry {
                        *entry = node.sequence_number;
                    }
                    for parent in &node.parents {
                        self.child_index.entry(*parent).or_default().push(node_hash);
                    }
                    node_to_conv.insert(node_hash, self.id);
                }
                JournalRecordType::Promotion => {
                    let node_hash: NodeHash = tox_proto::deserialize(&rec.payload)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    if let Some(info) = self.volatile_nodes.get_mut(&node_hash) {
                        info.verified = true;
                    }
                }
                JournalRecordType::RatchetAdvance => {
                    let decoded: (NodeHash, ChainKey, u64) =
                        tox_proto::deserialize(&rec.payload)
                            .map_err(|e| io::Error::other(e.to_string()))?;
                    let (node_hash, chain_key, epoch) = decoded;
                    self.hot_ratchets
                        .insert(node_hash, (chain_key.clone(), epoch));
                    if let Some(info) = self.volatile_nodes.get(&node_hash) {
                        self.latest_ratchets.insert(
                            info.sender_pk,
                            (chain_key, info.sequence_number, node_hash, epoch),
                        );
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl<F: FileSystem> NodeLookup for FsStore<F> {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType> {
        let inner = self.inner.read();
        let conv_id = inner.node_to_conv.get(hash)?;
        let ctx = inner.conversations.get(conv_id)?;

        if let Some(info) = ctx.volatile_nodes.get(hash) {
            return Some(info.node_type);
        }

        for pack in &ctx.packs {
            if let Some(record) = pack.index.lookup(hash) {
                return Some(if record.node_type == 0x01 {
                    NodeType::Admin
                } else {
                    NodeType::Content
                });
            }
        }
        None
    }

    fn get_rank(&self, hash: &NodeHash) -> Option<u64> {
        let inner = self.inner.read();
        let conv_id = inner.node_to_conv.get(hash)?;
        let ctx = inner.conversations.get(conv_id)?;

        if let Some(info) = ctx.volatile_nodes.get(hash) {
            return Some(info.rank);
        }

        for pack in &ctx.packs {
            if let Some(record) = pack.index.lookup(hash) {
                return Some(record.rank);
            }
        }
        None
    }

    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64> {
        let inner = self.inner.read();
        let conv_id = inner.node_to_conv.get(hash)?;
        let ctx = inner.conversations.get(conv_id)?;

        if let Some(info) = ctx.volatile_nodes.get(hash) {
            return Some(info.admin_distance as u64);
        }

        for pack in &ctx.packs {
            if let Some(record) = pack.index.lookup(hash) {
                return Some(record.admin_distance as u64);
            }
        }
        None
    }

    fn contains_node(&self, hash: &NodeHash) -> bool {
        self.inner.read().node_to_conv.contains_key(hash)
    }

    fn has_children(&self, hash: &NodeHash) -> bool {
        let inner = self.inner.read();
        if let Some(conv_id) = inner.node_to_conv.get(hash)
            && let Some(ctx) = inner.conversations.get(conv_id)
        {
            return ctx
                .child_index
                .get(hash)
                .map(|c| !c.is_empty())
                .unwrap_or(false);
        }
        false
    }
    fn get_soft_anchor_chain_length(&self, hash: &NodeHash) -> Option<u64> {
        let node = self.get_node(hash)?;
        if let merkle_tox_core::dag::Content::Control(
            merkle_tox_core::dag::ControlAction::SoftAnchor { basis_hash, .. },
        ) = &node.content
        {
            let parent_count = self.get_soft_anchor_chain_length(basis_hash).unwrap_or(0);
            Some(1 + parent_count)
        } else {
            Some(0)
        }
    }
}

impl<F: FileSystem> NodeStore for FsStore<F> {
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.heads.clone())
            .unwrap_or_default()
    }

    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get_mut(conversation_id).unwrap();
        ctx.state.heads = heads;
        let state_file = StateFile::new(self.fs.clone(), ctx.path.join("state.bin"));
        state_file.save(&ctx.state)?;
        Ok(())
    }

    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        inner
            .conversations
            .get(conversation_id)
            .map(|c| c.state.admin_heads.clone())
            .unwrap_or_default()
    }

    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get_mut(conversation_id).unwrap();
        ctx.state.admin_heads = heads;
        let state_file = StateFile::new(self.fs.clone(), ctx.path.join("state.bin"));
        state_file.save(&ctx.state)?;
        Ok(())
    }

    fn has_node(&self, hash: &NodeHash) -> bool {
        self.contains_node(hash)
    }

    fn is_verified(&self, hash: &NodeHash) -> bool {
        let inner = self.inner.read();
        let conv_id = match inner.node_to_conv.get(hash) {
            Some(id) => id,
            None => return false,
        };
        let ctx = match inner.conversations.get(conv_id) {
            Some(ctx) => ctx,
            None => return false,
        };

        if let Some(info) = ctx.volatile_nodes.get(hash) {
            return info.verified;
        }

        for pack in &ctx.packs {
            if let Some(record) = pack.index.lookup(hash) {
                return record.status == 0x01;
            }
        }
        false
    }

    fn get_node(&self, hash: &NodeHash) -> Option<MerkleNode> {
        let inner = self.inner.read();
        let conv_id = inner.node_to_conv.get(hash)?;
        let ctx = inner.conversations.get(conv_id)?;

        // Check journal
        if let Some(info) = ctx.volatile_nodes.get(hash) {
            let record = ctx.journal.lock().read_record_at(info.offset).ok()?;
            let decoded: (u8, MerkleNode) = tox_proto::deserialize(&record.payload).ok()?;
            if decoded.1.hash() != *hash {
                return None;
            }
            return Some(decoded.1);
        }

        // Check packs
        for pack in &ctx.packs {
            if let Ok(Some(data)) = pack.get_node_data(hash) {
                let data: Vec<u8> = data;
                let decoded: (u8, MerkleNode) = tox_proto::deserialize(&data).ok()?;
                if decoded.1.hash() != *hash {
                    continue;
                }
                return Some(decoded.1);
            }
        }
        None
    }

    fn get_wire_node(&self, hash: &NodeHash) -> Option<WireNode> {
        let inner = self.inner.read();
        let conv_id = inner.node_to_conv.get(hash)?;
        let ctx = inner.conversations.get(conv_id)?;

        if let Ok(Some(data)) = ctx.opaque.get_node(hash) {
            let data: Vec<u8> = data;
            return tox_proto::deserialize(&data).ok();
        }
        None
    }

    fn put_node(
        &self,
        conversation_id: &ConversationId,
        node: MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();

        let hash = node.hash();
        let status = if verified { 0x01u8 } else { 0x02u8 };
        let payload = tox_proto::serialize(&(status, node.clone()))?;

        let mut admin_distance = 0u16;
        if node.node_type() == NodeType::Content {
            let mut min_dist = u64::MAX;
            let ctx = inner.conversations.get(conversation_id).unwrap();
            for parent in &node.parents {
                let dist = if let Some(info) = ctx.volatile_nodes.get(parent) {
                    Some(info.admin_distance as u64)
                } else {
                    let mut found = None;
                    for pack in &ctx.packs {
                        if let Some(record) = pack.index.lookup(parent) {
                            found = Some(record.admin_distance as u64);
                            break;
                        }
                    }
                    found
                };
                if let Some(d) = dist {
                    min_dist = min_dist.min(d);
                }
            }
            if min_dist != u64::MAX {
                admin_distance = (min_dist + 1).min(u16::MAX as u64) as u16;
            } else {
                admin_distance = u16::MAX;
            }
        }

        {
            let ctx = inner.conversations.get_mut(conversation_id).unwrap();
            ctx.lock_file.try_lock_exclusive().map_err(|_| {
                MerkleToxError::Io(Error::other("Failed to acquire exclusive lock for write"))
            })?;
            let (_, offset) = ctx
                .journal
                .lock()
                .append(JournalRecordType::Node, &payload)?;
            ctx.volatile_nodes.insert(
                hash,
                JournalNodeInfo {
                    node_type: node.node_type(),
                    rank: node.topological_rank,
                    admin_distance,
                    sender_pk: node.sender_pk,
                    sequence_number: node.sequence_number,
                    verified,
                    offset,
                },
            );
            let entry = ctx.last_seq_numbers.entry(node.sender_pk).or_insert(0);
            if node.sequence_number > *entry {
                *entry = node.sequence_number;
            }
            for parent in &node.parents {
                ctx.child_index.entry(*parent).or_default().push(hash);
            }
            ctx.lock_file.try_lock_shared().ok(); // downgrade back
        }
        inner.node_to_conv.insert(hash, *conversation_id);

        let num_volatile = inner
            .conversations
            .get(conversation_id)
            .unwrap()
            .volatile_nodes
            .len();
        if num_volatile >= COMPACT_THRESHOLD {
            self.compact_internal(&mut inner, conversation_id)?;
        }

        Ok(())
    }

    fn put_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        node: WireNode,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let data = tox_proto::serialize(&node)?;
        ctx.opaque.put_node(hash, &data)?;
        inner.node_to_conv.insert(*hash, *conversation_id);
        Ok(())
    }

    fn remove_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        ctx.opaque.remove_node(hash)?;
        inner.node_to_conv.remove(hash);
        Ok(())
    }

    fn get_speculative_nodes(&self, conversation_id: &ConversationId) -> Vec<MerkleNode> {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        let ctx = match inner.conversations.get(conversation_id) {
            Some(ctx) => ctx,
            None => return Vec::new(),
        };

        let hashes: Vec<_> = ctx
            .volatile_nodes
            .iter()
            .filter(|(_, info)| !info.verified)
            .map(|(hash, _)| *hash)
            .collect();
        drop(inner);

        let mut speculative = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(node) = self.get_node(&hash) {
                speculative.push(node);
            }
        }
        speculative
    }

    fn mark_verified(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get_mut(conversation_id).unwrap();

        if let Some(info) = ctx.volatile_nodes.get_mut(hash)
            && !info.verified
        {
            ctx.journal
                .lock()
                .append(JournalRecordType::Promotion, &tox_proto::serialize(hash)?)?;
            info.verified = true;
        }
        Ok(())
    }

    fn get_last_sequence_number(
        &self,
        conversation_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64 {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        let ctx = match inner.conversations.get(conversation_id) {
            Some(ctx) => ctx,
            None => return 0,
        };

        ctx.last_seq_numbers.get(sender_pk).copied().unwrap_or(0)
    }

    fn get_node_counts(&self, conversation_id: &ConversationId) -> (usize, usize) {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        let ctx = match inner.conversations.get(conversation_id) {
            Some(ctx) => ctx,
            None => return (0, 0),
        };

        let mut ver = 0;
        let mut spec = 0;
        for info in ctx.volatile_nodes.values() {
            if info.verified {
                ver += 1;
            } else {
                spec += 1;
            }
        }
        for pack in &ctx.packs {
            for record in &pack.index.records {
                if record.status == 0x01 {
                    ver += 1;
                } else {
                    spec += 1;
                }
            }
        }
        (ver, spec)
    }

    fn get_verified_nodes_by_type(
        &self,
        conversation_id: &ConversationId,
        node_type: NodeType,
    ) -> MerkleToxResult<Vec<MerkleNode>> {
        let _ = self.ensure_conversation(conversation_id);
        let mut hashes = Vec::new();
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();

        for (hash, info) in &ctx.volatile_nodes {
            if info.verified && info.node_type == node_type {
                hashes.push(*hash);
            }
        }
        for pack in &ctx.packs {
            for record in &pack.index.records {
                let r_type = if record.node_type == 0x01 {
                    NodeType::Admin
                } else {
                    NodeType::Content
                };
                if record.status == 0x01 && r_type == node_type {
                    hashes.push(record.hash);
                }
            }
        }
        drop(inner);

        let mut nodes = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(node) = self.get_node(&hash) {
                nodes.push(node);
            }
        }

        // Sort by (topological_rank, T_eff, hash) for spec-compliant presentation ordering.
        let t_effs: HashMap<NodeHash, i64> = nodes
            .iter()
            .map(|n| (n.hash(), merkle_tox_core::dag::effective_timestamp(n, self)))
            .collect();
        nodes.sort_by(|a, b| {
            a.topological_rank
                .cmp(&b.topological_rank)
                .then_with(|| {
                    let t_a = t_effs
                        .get(&a.hash())
                        .copied()
                        .unwrap_or(a.network_timestamp);
                    let t_b = t_effs
                        .get(&b.hash())
                        .copied()
                        .unwrap_or(b.network_timestamp);
                    t_a.cmp(&t_b)
                })
                .then_with(|| a.hash().cmp(&b.hash()))
        });
        Ok(nodes)
    }

    fn get_node_hashes_in_range(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let _ = self.ensure_conversation(conversation_id);
        let mut hashes = Vec::new();
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();

        for (hash, info) in &ctx.volatile_nodes {
            if info.verified && info.rank >= range.min_rank && info.rank <= range.max_rank {
                hashes.push(*hash);
            }
        }
        for pack in &ctx.packs {
            for record in &pack.index.records {
                if record.status == 0x01
                    && record.rank >= range.min_rank
                    && record.rank <= range.max_rank
                {
                    hashes.push(record.hash);
                }
            }
        }
        Ok(hashes)
    }

    fn get_opaque_node_hashes(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let records = ctx.opaque.load_index()?;
        Ok(records.into_iter().map(|r| r.hash).collect())
    }

    fn size_bytes(&self) -> u64 {
        self.calculate_size(&self.root).unwrap_or(0)
    }

    fn put_conversation_key(
        &self,
        conversation_id: &ConversationId,
        epoch: u64,
        k_conv: KConv,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let keys_dir = ctx.path.join("keys");
        self.fs.create_dir_all(&keys_dir)?;

        let key_path = keys_dir.join(format!("{:016x}.key", epoch));
        self.fs.write(&key_path, k_conv.as_bytes())?;
        Ok(())
    }

    fn get_conversation_keys(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<(u64, KConv)>> {
        self.ensure_conversation(conversation_id)?;
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let keys_dir = ctx.path.join("keys");
        if !self.fs.exists(&keys_dir) {
            return Ok(vec![]);
        }

        let mut keys = Vec::new();
        if let Ok(entries) = self.fs.read_dir(&keys_dir) {
            for path in entries {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str())
                    && let Ok(epoch) = u64::from_str_radix(name, 16)
                    && let Ok(data) = self.fs.read(&path)
                    && let Ok(bytes) = <Vec<u8> as TryInto<[u8; 32]>>::try_into(data)
                {
                    keys.push((epoch, KConv::from(bytes)));
                }
            }
        }
        keys.sort_unstable_by_key(|(e, _)| *e);
        Ok(keys)
    }

    fn update_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
        message_count: u32,
        last_rotation_time: i64,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get_mut(conversation_id).unwrap();
        ctx.state.message_count = message_count;
        ctx.state.last_rotation_time = last_rotation_time;
        let state_file = StateFile::new(self.fs.clone(), ctx.path.join("state.bin"));
        state_file.save(&ctx.state)?;
        Ok(())
    }

    fn get_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Option<(u32, i64)>> {
        self.ensure_conversation(conversation_id)?;
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        if ctx.state.last_rotation_time == -1 {
            return Ok(None);
        }
        Ok(Some((
            ctx.state.message_count,
            ctx.state.last_rotation_time,
        )))
    }

    fn put_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
        chain_key: ChainKey,
        epoch_id: u64,
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let mut inner = self.inner.write();
        let ctx = inner.conversations.get_mut(conversation_id).unwrap();
        ctx.journal.lock().append(
            JournalRecordType::RatchetAdvance,
            &tox_proto::serialize(&(node_hash, chain_key.clone(), epoch_id))?,
        )?;
        ctx.hot_ratchets
            .insert(*node_hash, (chain_key.clone(), epoch_id));
        if let Some(info) = ctx.volatile_nodes.get(node_hash) {
            ctx.latest_ratchets.insert(
                info.sender_pk,
                (chain_key, info.sequence_number, *node_hash, epoch_id),
            );
        }
        Ok(())
    }

    fn get_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<Option<(ChainKey, u64)>> {
        let _ = self.ensure_conversation(conversation_id);
        let inner = self.inner.read();
        let ctx = match inner.conversations.get(conversation_id) {
            Some(ctx) => ctx,
            None => return Ok(None),
        };

        if let Some(res) = ctx.hot_ratchets.get(node_hash) {
            return Ok(Some(res.clone()));
        }

        // We don't currently support looking up by NodeHash from the packed ratchet.bin
        // because it only stores the latest per device.
        Ok(None)
    }

    fn remove_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        let mut inner = self.inner.write();
        if let Some(ctx) = inner.conversations.get_mut(conversation_id) {
            ctx.hot_ratchets.remove(node_hash);
        }
        Ok(())
    }
}

impl<F: FileSystem> FsStore<F> {
    pub fn finalize_blob(&self, hash: &NodeHash) -> MerkleToxResult<()> {
        self.blob_store.finalize(hash).map_err(MerkleToxError::Io)
    }

    pub fn prune_vault(&self, max_age: std::time::Duration) -> MerkleToxResult<()> {
        let vault_dir = self.root.join("vault");
        if let Ok(entries) = self.fs.read_dir(&vault_dir) {
            for path in entries {
                if let Ok(metadata) = self.fs.metadata(&path)
                    && let Ok(elapsed) = metadata.modified.elapsed()
                    && elapsed > max_age
                {
                    let _ = self.fs.remove_file(&path);
                }
            }
        }
        Ok(())
    }

    fn calculate_size(&self, dir: &std::path::Path) -> io::Result<u64> {
        let mut total = 0;
        if let Ok(entries) = self.fs.read_dir(dir) {
            for path in entries {
                let meta = self.fs.metadata(&path)?;
                if meta.is_dir {
                    total += self.calculate_size(&path)?;
                } else {
                    total += meta.len;
                }
            }
        }
        Ok(total)
    }
}

impl<F: FileSystem> BlobStoreTrait for FsStore<F> {
    fn has_blob(&self, hash: &NodeHash) -> bool {
        self.blob_store
            .get_info(hash)
            .map(|i| {
                i.map(|i| i.status == BlobStatus::Available)
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    fn get_blob_info(&self, hash: &NodeHash) -> Option<BlobInfo> {
        self.blob_store.get_info(hash).ok().flatten()
    }

    fn put_blob_info(&self, info: BlobInfo) -> MerkleToxResult<()> {
        self.blob_store.put_info(&info)?;
        Ok(())
    }

    fn put_chunk(
        &self,
        _conversation_id: &ConversationId,
        hash: &NodeHash,
        offset: u64,
        data: &[u8],
        _proof: Option<&[u8]>,
    ) -> MerkleToxResult<()> {
        let mut info = self
            .blob_store
            .get_info(hash)?
            .ok_or(MerkleToxError::BlobNotFound(*hash))?;

        self.blob_store.put_chunk(hash, offset, data)?;

        // Update BlobInfo status
        if info.status == BlobStatus::Pending {
            info.status = BlobStatus::Downloading;
        }

        // Basic completion check if received_mask is managed (for compliance tests)
        let chunk_index = offset / merkle_tox_core::cas::CHUNK_SIZE;
        let mut mask = info.received_mask.unwrap_or_default();
        let byte_idx = (chunk_index / 8) as usize;
        let bit_idx = (chunk_index % 8) as u8;
        if byte_idx >= mask.len() {
            mask.resize(byte_idx + 1, 0);
        }
        mask[byte_idx] |= 1 << bit_idx;

        // Check if all chunks are received
        let num_chunks = info.size.div_ceil(merkle_tox_core::cas::CHUNK_SIZE);
        let mut complete = true;
        for i in 0..num_chunks {
            let b = (i / 8) as usize;
            let bit = (i % 8) as u8;
            if b >= mask.len() || (mask[b] & (1 << bit)) == 0 {
                complete = false;
                break;
            }
        }
        if complete
            && let Ok(data) = self.blob_store.get_chunk(hash, 0, info.size as u32)
            && data.len() as u64 == info.size
        {
            return self.finalize_blob(hash);
        }

        info.received_mask = Some(mask);
        self.blob_store.put_info(&info)?;

        Ok(())
    }

    fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> MerkleToxResult<Vec<u8>> {
        match self.blob_store.get_chunk(hash, offset, length) {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                if let Some(info) = self.get_blob_info(hash)
                    && offset + length as u64 <= info.size
                {
                    return Ok(vec![0u8; length as usize]);
                }
                Err(MerkleToxError::Io(e))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(MerkleToxError::BlobNotFound(*hash))
            }
            Err(e) => Err(MerkleToxError::Io(e)),
        }
    }

    fn get_chunk_with_proof(
        &self,
        hash: &NodeHash,
        offset: u64,
        length: u32,
    ) -> MerkleToxResult<(Vec<u8>, Vec<u8>)> {
        self.blob_store
            .get_chunk_with_proof(hash, offset, length)
            .map_err(MerkleToxError::Io)
    }
}

impl<F: FileSystem> GlobalStore for FsStore<F> {
    fn get_global_offset(&self) -> Option<i64> {
        self.inner.read().global_offset
    }

    fn set_global_offset(&self, offset: i64) -> MerkleToxResult<()> {
        let mut inner = self.inner.write();
        inner.global_offset = Some(offset);
        let path = self.root.join("global.bin");
        self.fs.write(&path, &offset.to_le_bytes())?;
        Ok(())
    }
}

impl<F: FileSystem> ReconciliationStore for FsStore<F> {
    fn put_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
        sketch: &[u8],
    ) -> MerkleToxResult<()> {
        self.ensure_conversation(conversation_id)?;
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let sketches_dir = ctx.path.join("sketches");
        self.fs.create_dir_all(&sketches_dir)?;

        let sketch_name = format!("{:016x}_{:016x}.bin", range.min_rank, range.max_rank);
        let sketch_path = sketches_dir.join(sketch_name);
        self.fs.write(&sketch_path, sketch)?;
        Ok(())
    }

    fn get_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Option<Vec<u8>>> {
        self.ensure_conversation(conversation_id)?;
        let inner = self.inner.read();
        let ctx = inner.conversations.get(conversation_id).unwrap();
        let sketch_name = format!("{:016x}_{:016x}.bin", range.min_rank, range.max_rank);
        let sketch_path = ctx.path.join("sketches").join(sketch_name);

        if self.fs.exists(&sketch_path) {
            Ok(Some(self.fs.read(&sketch_path)?))
        } else {
            Ok(None)
        }
    }
}

pub fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}
