pub mod schema;

use merkle_tox_core::cas::{BlobInfo, BlobStatus};
use merkle_tox_core::dag::{
    ChainKey, ConversationId, KConv, MerkleNode, NodeHash, NodeLookup, NodeType, PhysicalDevicePk,
};
use merkle_tox_core::error::{MerkleToxError, MerkleToxResult};
use merkle_tox_core::sync::{BlobStore, GlobalStore, NodeStore, ReconciliationStore, SyncRange};
use merkle_tox_core::vfs::{FileSystem, StdFileSystem};
use rusqlite::{Connection, OptionalExtension, Result, params};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct Storage {
    conn: Mutex<Connection>,
    blob_dir: Option<PathBuf>,
    vfs: Arc<dyn FileSystem>,
}

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(schema::CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
            blob_dir: None,
            vfs: Arc::new(StdFileSystem),
        })
    }

    pub fn with_vfs(mut self, vfs: Arc<dyn FileSystem>) -> Self {
        self.vfs = vfs;
        self
    }

    pub fn with_blob_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        if !self.vfs.exists(&path) {
            let _ = self.vfs.create_dir_all(&path);
        }
        self.blob_dir = Some(path);
        self
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
            blob_dir: None,
            vfs: Arc::new(StdFileSystem),
        })
    }

    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
            blob_dir: None,
            vfs: Arc::new(StdFileSystem),
        }
    }

    pub fn connection(&self) -> &Mutex<Connection> {
        &self.conn
    }

    fn is_anchor(&self, data: &[u8]) -> bool {
        if let Ok(wire) = tox_proto::deserialize::<merkle_tox_core::dag::WireNode>(data) {
            if matches!(
                wire.authentication,
                merkle_tox_core::dag::NodeAuth::Signature(_)
            ) {
                return true;
            }

            if !wire
                .flags
                .contains(merkle_tox_core::dag::WireFlags::ENCRYPTED)
            {
                let mut payload_data = wire.payload_data.clone();
                if merkle_tox_core::dag::remove_padding(&mut payload_data).is_ok() {
                    if wire
                        .flags
                        .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
                        && let Ok(decompressed) = zstd::decode_all(&payload_data[..])
                    {
                        payload_data = decompressed;
                    }

                    if payload_data.len() >= 8 {
                        let mut cursor = std::io::Cursor::new(&payload_data[8..]);
                        if let Ok(content) =
                            <merkle_tox_core::dag::Content as tox_proto::ToxDeserialize>::deserialize(
                                &mut cursor,
                                &tox_proto::ToxContext::empty(),
                            ) && matches!(content, merkle_tox_core::dag::Content::KeyWrap { .. })
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn check_opaque_eviction(&self, conversation_id: &ConversationId) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        let total_size: i64 = conn
            .query_row(
                "SELECT IFNULL(SUM(LENGTH(raw_data)), 0) FROM opaque_nodes WHERE conversation_id = ?1",
                params![conversation_id.as_bytes()],
                |r| r.get(0),
            )
            .unwrap_or(0);

        const OPAQUE_TOTAL_MAX_SIZE: i64 = 100 * 1024 * 1024;

        if total_size > OPAQUE_TOTAL_MAX_SIZE {
            let mut stmt = conn
                .prepare("SELECT hash, raw_data FROM opaque_nodes WHERE conversation_id = ?1")
                .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(params![conversation_id.as_bytes()], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

            let mut to_delete = Vec::new();
            let mut current_size = total_size;

            for row in rows {
                if current_size <= OPAQUE_TOTAL_MAX_SIZE {
                    break;
                }
                let (hash_bytes, raw_data) =
                    row.map_err(|e| MerkleToxError::Storage(e.to_string()))?;

                if !self.is_anchor(&raw_data) {
                    current_size -= raw_data.len() as i64;
                    to_delete.push(hash_bytes);
                }
            }

            for h in to_delete {
                conn.execute("DELETE FROM opaque_nodes WHERE hash = ?1", params![h])
                    .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
            }
        }
        Ok(())
    }
}

impl NodeLookup for Storage {
    fn get_node_type(&self, hash: &NodeHash) -> Option<NodeType> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT node_type FROM nodes WHERE hash = ?1")
            .ok()?;
        let res: Option<i32> = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .ok()?;
        res.map(|t| {
            if t == 0 {
                NodeType::Admin
            } else {
                NodeType::Content
            }
        })
    }

    fn get_rank(&self, hash: &NodeHash) -> Option<u64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT topological_rank FROM nodes WHERE hash = ?1")
            .ok()?;
        let res: i64 = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .ok()??;
        Some((res ^ i64::MIN) as u64)
    }

    fn get_admin_distance(&self, hash: &NodeHash) -> Option<u64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT admin_distance FROM nodes WHERE hash = ?1")
            .ok()?;
        let res: i64 = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .ok()??;
        Some(res as u64)
    }

    fn contains_node(&self, hash: &NodeHash) -> bool {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM nodes WHERE hash = ?1")
            .ok()
            .unwrap();
        stmt.exists(params![hash.as_bytes()]).unwrap_or(false)
    }

    fn has_children(&self, hash: &NodeHash) -> bool {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM edges WHERE parent_hash = ?1")
            .ok()
            .unwrap();
        stmt.exists(params![hash.as_bytes()]).unwrap_or(false)
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

impl NodeStore for Storage {
    fn get_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT heads FROM conversation_meta WHERE conversation_id = ?1")
            .ok()
            .unwrap();
        let res: Option<Vec<u8>> = stmt
            .query_row(params![conversation_id.as_bytes()], |r| r.get(0))
            .optional()
            .ok()
            .flatten();
        res.and_then(|data| tox_proto::deserialize::<Vec<NodeHash>>(&data).ok())
            .unwrap_or_default()
    }

    fn set_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        let heads_data = tox_proto::serialize(&heads).map_err(MerkleToxError::Protocol)?;
        conn.execute(
            "INSERT INTO conversation_meta (conversation_id, heads) VALUES (?1, ?2)
             ON CONFLICT(conversation_id) DO UPDATE SET heads = ?2",
            params![conversation_id.as_bytes(), heads_data],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_admin_heads(&self, conversation_id: &ConversationId) -> Vec<NodeHash> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT admin_heads FROM conversation_meta WHERE conversation_id = ?1")
            .ok()
            .unwrap();
        let res: Option<Vec<u8>> = stmt
            .query_row(params![conversation_id.as_bytes()], |r| r.get(0))
            .optional()
            .ok()
            .flatten();
        res.and_then(|data| tox_proto::deserialize::<Vec<NodeHash>>(&data).ok())
            .unwrap_or_default()
    }

    fn set_admin_heads(
        &self,
        conversation_id: &ConversationId,
        heads: Vec<NodeHash>,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        let heads_data = tox_proto::serialize(&heads).map_err(MerkleToxError::Protocol)?;
        conn.execute(
            "INSERT INTO conversation_meta (conversation_id, admin_heads) VALUES (?1, ?2)
             ON CONFLICT(conversation_id) DO UPDATE SET admin_heads = ?2",
            params![conversation_id.as_bytes(), heads_data],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn has_node(&self, hash: &NodeHash) -> bool {
        self.contains_node(hash)
    }

    fn is_verified(&self, hash: &NodeHash) -> bool {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT verification_status FROM nodes WHERE hash = ?1")
            .ok()
            .unwrap();
        let res: Option<i32> = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .unwrap_or(None);
        res == Some(1)
    }

    fn get_node(&self, hash: &NodeHash) -> Option<MerkleNode> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT raw_data FROM nodes WHERE hash = ?1")
            .ok()?;
        let raw_data: Vec<u8> = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .ok()??;
        let node: MerkleNode = tox_proto::deserialize(&raw_data).ok()?;
        if node.hash() != *hash {
            return None;
        }
        Some(node)
    }

    fn get_wire_node(&self, hash: &NodeHash) -> Option<merkle_tox_core::dag::WireNode> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT raw_data FROM opaque_nodes WHERE hash = ?1")
            .ok()?;
        let raw_data: Vec<u8> = stmt
            .query_row(params![hash.as_bytes()], |r| r.get(0))
            .optional()
            .ok()??;
        tox_proto::deserialize(&raw_data).ok()
    }

    fn put_node(
        &self,
        conversation_id: &ConversationId,
        node: MerkleNode,
        verified: bool,
    ) -> MerkleToxResult<()> {
        let hash = node.hash();
        let node_type = if node.node_type() == NodeType::Admin {
            0
        } else {
            1
        };

        let mut admin_distance = 0;
        if node_type == 1 {
            // Content Node: Calculate distance from parents
            let mut min_dist = u64::MAX;
            for parent_hash in &node.parents {
                if let Some(dist) = self.get_admin_distance(parent_hash) {
                    min_dist = min_dist.min(dist);
                }
            }
            if min_dist != u64::MAX {
                admin_distance = min_dist + 1;
            } else {
                admin_distance = u64::MAX;
            }
        }

        let mut conn = self.conn.lock().unwrap();
        let raw_data = tox_proto::serialize(&node).map_err(MerkleToxError::Protocol)?;
        let parents_data = tox_proto::serialize(&node.parents).map_err(MerkleToxError::Protocol)?;
        let status = if verified { 1 } else { 0 };

        let tx = conn
            .transaction()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO nodes (
                hash, conversation_id, node_type, author_pk, sender_pk, network_timestamp,
                sequence_number, topological_rank, admin_distance, parents, verification_status, raw_data
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                hash.as_bytes(),
                conversation_id.as_bytes(),
                node_type,
                node.author_pk.as_bytes(),
                node.sender_pk.as_bytes(),
                node.network_timestamp,
                (node.sequence_number as i64) ^ i64::MIN,
                (node.topological_rank as i64) ^ i64::MIN,
                admin_distance as i64,
                parents_data,
                status,
                raw_data,
            ],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        for parent_hash in &node.parents {
            tx.execute(
                "INSERT OR IGNORE INTO edges (parent_hash, child_hash) VALUES (?1, ?2)",
                params![parent_hash.as_bytes(), hash.as_bytes()],
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn put_wire_node(
        &self,
        conversation_id: &ConversationId,
        hash: &NodeHash,
        node: merkle_tox_core::dag::WireNode,
    ) -> MerkleToxResult<()> {
        {
            let conn = self.conn.lock().unwrap();
            let raw_data = tox_proto::serialize(&node).map_err(MerkleToxError::Protocol)?;
            conn.execute(
                "INSERT OR REPLACE INTO opaque_nodes (hash, conversation_id, raw_data) VALUES (?1, ?2, ?3)",
                params![hash.as_bytes(), conversation_id.as_bytes(), raw_data],
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        }
        self.check_opaque_eviction(conversation_id)?;
        Ok(())
    }

    fn remove_wire_node(
        &self,
        _conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM opaque_nodes WHERE hash = ?1",
            params![hash.as_bytes()],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_speculative_nodes(&self, conversation_id: &ConversationId) -> Vec<MerkleNode> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT raw_data FROM nodes WHERE conversation_id = ?1 AND verification_status = 0",
            )
            .ok()
            .unwrap();
        let rows = stmt
            .query_map(params![conversation_id.as_bytes()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .ok()
            .unwrap();
        rows.filter_map(|r| r.ok())
            .filter_map(|data| tox_proto::deserialize(&data).ok())
            .collect()
    }

    fn mark_verified(
        &self,
        _conversation_id: &ConversationId,
        hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE nodes SET verification_status = 1 WHERE hash = ?1",
            params![hash.as_bytes()],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_last_sequence_number(
        &self,
        conversation_id: &ConversationId,
        sender_pk: &PhysicalDevicePk,
    ) -> u64 {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT sequence_number FROM nodes 
                 WHERE conversation_id = ?1 AND sender_pk = ?2 
                 ORDER BY sequence_number DESC 
                 LIMIT 1",
            )
            .ok()
            .unwrap();
        let res: Option<i64> = stmt
            .query_row(
                params![conversation_id.as_bytes(), sender_pk.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        res.map(|r| (r ^ i64::MIN) as u64).unwrap_or(0)
    }

    fn get_node_counts(&self, conversation_id: &ConversationId) -> (usize, usize) {
        let conn = self.conn.lock().unwrap();
        let ver: i64 = conn
            .query_row(
                "SELECT count(*) FROM nodes WHERE conversation_id = ?1 AND verification_status = 1",
                params![conversation_id.as_bytes()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let spec: i64 = conn
            .query_row(
                "SELECT count(*) FROM nodes WHERE conversation_id = ?1 AND verification_status = 0",
                params![conversation_id.as_bytes()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (ver as usize, spec as usize)
    }

    fn get_verified_nodes_by_type(
        &self,
        conversation_id: &ConversationId,
        node_type: NodeType,
    ) -> MerkleToxResult<Vec<MerkleNode>> {
        let type_int = if node_type == NodeType::Admin { 0 } else { 1 };
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT raw_data FROM nodes 
                 WHERE conversation_id = ?1 AND node_type = ?2 AND verification_status = 1
                 ORDER BY topological_rank ASC, hash ASC",
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![conversation_id.as_bytes(), type_int], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let mut nodes = Vec::new();
        for row in rows {
            let data = row.map_err(|e| MerkleToxError::Storage(e.to_string()))?;
            let node: MerkleNode = tox_proto::deserialize(&data)?;
            nodes.push(node);
        }
        Ok(nodes)
    }

    fn get_node_hashes_in_range(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT hash FROM nodes 
                 WHERE conversation_id = ?1 
                 AND topological_rank BETWEEN ?2 AND ?3 
                 AND verification_status = 1",
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(
                params![
                    conversation_id.as_bytes(),
                    (range.min_rank as i64) ^ i64::MIN,
                    (range.max_rank as i64) ^ i64::MIN
                ],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let mut hashes = Vec::new();
        for row in rows {
            let data = row.map_err(|e| MerkleToxError::Storage(e.to_string()))?;
            let bytes: [u8; 32] = data
                .try_into()
                .map_err(|_| MerkleToxError::Storage("Invalid hash size".to_string()))?;
            hashes.push(NodeHash::from(bytes));
        }
        Ok(hashes)
    }

    fn get_opaque_node_hashes(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<NodeHash>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT hash FROM opaque_nodes WHERE conversation_id = ?1")
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![conversation_id.as_bytes()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let mut hashes = Vec::new();
        for row in rows {
            let data = row.map_err(|e| MerkleToxError::Storage(e.to_string()))?;
            let bytes: [u8; 32] = data
                .try_into()
                .map_err(|_| MerkleToxError::Storage("Invalid hash size".to_string()))?;
            hashes.push(NodeHash::from(bytes));
        }
        Ok(hashes)
    }

    fn size_bytes(&self) -> u64 {
        let conn = self.conn.lock().unwrap();
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap_or(0);
        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap_or(0);
        (page_count * page_size) as u64
    }

    fn put_conversation_key(
        &self,
        conversation_id: &ConversationId,
        epoch: u64,
        k_conv: KConv,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conversation_keys (conversation_id, epoch, k_conv) VALUES (?1, ?2, ?3)
             ON CONFLICT(conversation_id, epoch) DO UPDATE SET k_conv = ?3",
            params![
                conversation_id.as_bytes(),
                (epoch as i64) ^ i64::MIN,
                k_conv.as_bytes()
            ],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_conversation_keys(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Vec<(u64, KConv)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT epoch, k_conv FROM conversation_keys WHERE conversation_id = ?1",
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![conversation_id.as_bytes()], |r| {
                let epoch: i64 = r.get(0)?;
                let k_conv: Vec<u8> = r.get(1)?;
                let bytes: [u8; 32] = k_conv.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "k_conv".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(((epoch ^ i64::MIN) as u64, KConv::from(bytes)))
            })
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| MerkleToxError::Storage(e.to_string()))?);
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conversation_meta (conversation_id, message_count, last_rotation_time) VALUES (?1, ?2, ?3)
             ON CONFLICT(conversation_id) DO UPDATE SET message_count = ?2, last_rotation_time = ?3",
            params![conversation_id.as_bytes(), message_count as i64, last_rotation_time],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_epoch_metadata(
        &self,
        conversation_id: &ConversationId,
    ) -> MerkleToxResult<Option<(u32, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT message_count, last_rotation_time FROM conversation_meta WHERE conversation_id = ?1")
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        stmt.query_row(params![conversation_id.as_bytes()], |r| {
            let count: i64 = r.get(0)?;
            let time: i64 = r.get(1)?;
            Ok((count as u32, time))
        })
        .optional()
        .map_err(|e| MerkleToxError::Storage(e.to_string()))
    }

    fn put_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
        chain_key: ChainKey,
        epoch_id: u64,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO ratchet_keys (conversation_id, node_hash, chain_key, epoch_id) VALUES (?1, ?2, ?3, ?4)",
            params![
                conversation_id.as_bytes(),
                node_hash.as_bytes(),
                chain_key.as_bytes().to_vec(),
                (epoch_id as i64) ^ i64::MIN
            ],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<Option<(ChainKey, u64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT chain_key, epoch_id FROM ratchet_keys WHERE conversation_id = ?1 AND node_hash = ?2",
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let res: Option<(Vec<u8>, i64)> = stmt
            .query_row(
                params![conversation_id.as_bytes(), node_hash.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        match res {
            Some((bytes, epoch)) => {
                let key_bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| MerkleToxError::Storage("Invalid key size".to_string()))?;
                Ok(Some((ChainKey::from(key_bytes), (epoch ^ i64::MIN) as u64)))
            }
            None => Ok(None),
        }
    }

    fn remove_ratchet_key(
        &self,
        conversation_id: &ConversationId,
        node_hash: &NodeHash,
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ratchet_keys WHERE conversation_id = ?1 AND node_hash = ?2",
            params![conversation_id.as_bytes(), node_hash.as_bytes()],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }
}

impl BlobStore for Storage {
    fn has_blob(&self, hash: &NodeHash) -> bool {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM cas_blobs WHERE hash = ?1 AND status = 'Available' AND (data IS NOT NULL OR file_path IS NOT NULL)")
            .ok()
            .unwrap();
        stmt.exists(params![hash.as_bytes()]).unwrap_or(false)
    }

    fn get_blob_info(&self, hash: &NodeHash) -> Option<BlobInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT hash, total_size, status, received_chunks FROM cas_blobs WHERE hash = ?1",
            )
            .ok()?;
        stmt.query_row(params![hash.as_bytes()], |r| {
            let hash_bytes: Vec<u8> = r.get(0)?;
            let size: i64 = r.get(1)?;
            let status_str: String = r.get(2)?;
            let received_mask: Option<Vec<u8>> = r.get(3)?;

            let bytes: [u8; 32] = hash_bytes.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(0, "hash".into(), rusqlite::types::Type::Blob)
            })?;
            let status = match status_str.as_str() {
                "Pending" => BlobStatus::Pending,
                "Downloading" => BlobStatus::Downloading,
                "Available" => BlobStatus::Available,
                _ => BlobStatus::Error,
            };

            Ok(BlobInfo {
                hash: NodeHash::from(bytes),
                size: size as u64,
                status,
                received_mask,
                decryption_key: None,
            })
        })
        .optional()
        .ok()
        .flatten()
    }

    fn put_blob_info(&self, info: BlobInfo) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        let status_str = match info.status {
            BlobStatus::Pending => "Pending",
            BlobStatus::Downloading => "Downloading",
            BlobStatus::Available => "Available",
            BlobStatus::Error => "Error",
        };
        conn.execute(
            "INSERT INTO cas_blobs (hash, total_size, status, received_chunks) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(hash) DO UPDATE SET status = ?3, received_chunks = ?4",
            params![
                info.hash.as_bytes(),
                info.size as i64,
                status_str,
                info.received_mask,
            ],
        ).map_err(|e| MerkleToxError::Storage(e.to_string()))?;
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
        if self.has_blob(hash) {
            return Ok(());
        }

        let info = self
            .get_blob_info(hash)
            .ok_or(MerkleToxError::BlobNotFound(*hash))?;

        // Use filesystem if blob_dir is set AND (blob is > 1MB OR it already has a file_path).
        let mut use_fs = self.blob_dir.is_some() && info.size > 1024 * 1024;

        if !use_fs && self.blob_dir.is_some() {
            // Check if it already has a file_path in DB
            let conn = self.conn.lock().unwrap();
            let res: Option<String> = conn
                .query_row(
                    "SELECT file_path FROM cas_blobs WHERE hash = ?1",
                    params![hash.as_bytes()],
                    |r| r.get(0),
                )
                .optional()
                .unwrap_or(None);
            if res.is_some() {
                use_fs = true;
            }
        }

        if use_fs && let Some(blob_dir) = &self.blob_dir {
            let hex = hex::encode(hash.as_bytes());
            let path = blob_dir.join(&hex[0..2]).join(&hex);
            if let Some(parent) = path.parent() {
                let _ = self.vfs.create_dir_all(parent);
            }

            let mut file = self
                .vfs
                .open(&path, true, true, false)
                .map_err(MerkleToxError::Io)?;

            if file.metadata().map(|m| m.len).unwrap_or(0) < info.size {
                file.set_len(info.size).map_err(MerkleToxError::Io)?;
            }

            file.seek(SeekFrom::Start(offset))
                .map_err(MerkleToxError::Io)?;
            file.write_all(data).map_err(MerkleToxError::Io)?;

            // Update mask and status in DB
            let mut conn = self.conn.lock().unwrap();
            let tx = conn
                .transaction()
                .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

            let (mut mask, total_size): (Vec<u8>, i64) = tx.query_row(
                    "SELECT IFNULL(received_chunks, zeroblob((total_size + 524287) / 524288)), total_size FROM cas_blobs WHERE hash = ?1",
                    params![hash.as_bytes()],
                    |r| Ok((r.get(0)?, r.get(1)?))
                ).map_err(|e| MerkleToxError::Storage(e.to_string()))?;

            let chunk_idx = offset / (64 * 1024);
            let byte_idx = (chunk_idx / 8) as usize;
            let bit_idx = (chunk_idx % 8) as u8;
            if byte_idx < mask.len() {
                mask[byte_idx] |= 1 << bit_idx;
            }

            let num_chunks = (total_size + 65535) / 65536;
            let mut complete = true;
            for i in 0..num_chunks {
                let b_idx = (i / 8) as usize;
                let bit_i = (i % 8) as u8;
                if (mask[b_idx] & (1 << bit_i)) == 0 {
                    complete = false;
                    break;
                }
            }

            let status = if complete { "Available" } else { "Downloading" };

            tx.execute(
                    "UPDATE cas_blobs SET received_chunks = ?1, status = ?2, file_path = ?3 WHERE hash = ?4",
                    params![
                        mask,
                        status,
                        path.to_string_lossy(),
                        hash.as_bytes()
                    ],
                )
                .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

            tx.commit()
                .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        // 1. Get current data and mask
        let (mut blob_data, mut mask, total_size): (Vec<u8>, Vec<u8>, i64) = tx.query_row(
            "SELECT IFNULL(data, zeroblob(total_size)), IFNULL(received_chunks, zeroblob((total_size + 524287) / 524288)), total_size FROM cas_blobs WHERE hash = ?1",
            params![hash.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        ).map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        // 2. Update data
        let end = (offset as usize + data.len()).min(blob_data.len());
        blob_data[offset as usize..end].copy_from_slice(&data[0..(end - offset as usize)]);

        // 3. Update mask
        let chunk_idx = offset / (64 * 1024);
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_idx = (chunk_idx % 8) as u8;
        if byte_idx < mask.len() {
            mask[byte_idx] |= 1 << bit_idx;
        }

        // 4. Check if complete
        let num_chunks = (total_size + 65535) / 65536;
        let mut complete = true;
        for i in 0..num_chunks {
            let b_idx = (i / 8) as usize;
            let bit_i = (i % 8) as u8;
            if (mask[b_idx] & (1 << bit_i)) == 0 {
                complete = false;
                break;
            }
        }

        let status = if complete { "Available" } else { "Downloading" };

        tx.execute(
            "UPDATE cas_blobs SET data = ?1, received_chunks = ?2, status = ?3 WHERE hash = ?4",
            params![blob_data, mask, status, hash.as_bytes()],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        tx.commit()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> MerkleToxResult<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();
        let res: Option<(Option<Vec<u8>>, Option<String>, i64)> = conn
            .query_row(
                "SELECT data, file_path, total_size FROM cas_blobs WHERE hash = ?1",
                params![hash.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        let (data_opt, file_path_opt, total_size) =
            res.ok_or(MerkleToxError::BlobNotFound(*hash))?;

        if let Some(path_str) = file_path_opt {
            let mut file = self
                .vfs
                .open(Path::new(&path_str), false, false, false)
                .map_err(MerkleToxError::Io)?;
            if offset >= total_size as u64 || offset + length as u64 > total_size as u64 {
                return Err(MerkleToxError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                )));
            }
            file.seek(SeekFrom::Start(offset))
                .map_err(MerkleToxError::Io)?;
            let mut buf = vec![0u8; length as usize];
            file.read_exact(&mut buf).map_err(MerkleToxError::Io)?;
            return Ok(buf);
        }

        let data = data_opt.ok_or(MerkleToxError::BlobNotFound(*hash))?;

        if offset >= total_size as u64
            || offset + length as u64 > total_size as u64
            || data.len() < (offset + length as u64) as usize
        {
            return Err(MerkleToxError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )));
        }

        Ok(data[offset as usize..(offset as usize + length as usize)].to_vec())
    }
}

impl GlobalStore for Storage {
    fn get_global_offset(&self) -> Option<i64> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT value FROM global_state WHERE key = 'network_offset'")
            .ok()?;
        let res: Vec<u8> = stmt.query_row([], |r| r.get(0)).optional().ok()??;
        tox_proto::deserialize(&res).ok()
    }

    fn set_global_offset(&self, offset: i64) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        let data = tox_proto::serialize(&offset).map_err(MerkleToxError::Protocol)?;
        conn.execute(
            "INSERT INTO global_state (key, value) VALUES ('network_offset', ?1)
             ON CONFLICT(key) DO UPDATE SET value = ?1",
            params![data],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }
}

impl ReconciliationStore for Storage {
    fn put_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
        sketch: &[u8],
    ) -> MerkleToxResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO reconciliation_sketches (conversation_id, min_rank, max_rank, sketch)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(conversation_id, min_rank, max_rank) DO UPDATE SET sketch = ?4",
            params![
                conversation_id.as_bytes(),
                (range.min_rank as i64) ^ i64::MIN,
                (range.max_rank as i64) ^ i64::MIN,
                sketch
            ],
        )
        .map_err(|e| MerkleToxError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_sketch(
        &self,
        conversation_id: &ConversationId,
        range: &SyncRange,
    ) -> MerkleToxResult<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT sketch FROM reconciliation_sketches
                 WHERE conversation_id = ?1 AND min_rank = ?2 AND max_rank = ?3",
            )
            .map_err(|e| MerkleToxError::Storage(e.to_string()))?;

        stmt.query_row(
            params![
                conversation_id.as_bytes(),
                (range.min_rank as i64) ^ i64::MIN,
                (range.max_rank as i64) ^ i64::MIN
            ],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| MerkleToxError::Storage(e.to_string()))
    }
}
