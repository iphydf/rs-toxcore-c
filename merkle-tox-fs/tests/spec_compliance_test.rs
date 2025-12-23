use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use tempfile::TempDir;

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn test_journal_footer_compliance() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([1u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        // Add some nodes to ensure journal activity
        for i in 1..=5 {
            let node = MerkleNode {
                parents: vec![],
                author_pk: LogicalIdentityPk::from([1u8; 32]),
                sender_pk: PhysicalDevicePk::from([1u8; 32]),
                sequence_number: i,
                topological_rank: i - 1,
                network_timestamp: 100,
                content: Content::Text(format!("Node {}", i)),
                metadata: vec![],
                authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
            };
            store.put_node(&conv_id, node, true).unwrap();
        }
        // Graceful shutdown should ideally write the footer
        drop(store);
    }

    let journal_path = root
        .join("conversations")
        .join(conv_hex)
        .join("journal.bin");
    let data = fs::read(&journal_path).unwrap();

    // SPEC: Section 4.1 - Tail-Commit Footer: [u32 magic_end] [u32 record_count] [u8[32] journal_checksum] [IndexTable]
    // magic_end = 0x454E4421 ("END!")

    let footer_magic = 0x454E4421u32;
    let mut found_magic = false;
    if data.len() > 40 {
        for i in (0..data.len() - 4).rev() {
            let val = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            if val == footer_magic {
                found_magic = true;
                break;
            }
        }
    }

    assert!(
        found_magic,
        "Spec Section 4.1 mandates an optional Tail-Commit Footer (0x454E4421) for fast startup after clean shutdown."
    );
}

#[test]
fn test_permissions_cache_compliance() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([2u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        // Trigger conversation initialization
        store.get_heads(&conv_id);
    }

    let perm_path = root
        .join("conversations")
        .join(conv_hex)
        .join("permissions.bin");
    assert!(
        fs::metadata(&perm_path).is_ok(),
        "Spec Section 6.3 mandates a persisted Effective Permissions cache (permissions.bin)."
    );
}

#[test]
fn test_global_blacklist_presence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);

    let _store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();

    let blacklist_path = root.join("blacklist.bin");
    assert!(
        fs::metadata(&blacklist_path).is_ok(),
        "Spec Section 6.5 mandates a Global Blacklist (blacklist.bin) in the storage root."
    );
}

#[test]
fn test_generation_id_mismatch_truncation() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([3u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        let node = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: 1,
            topological_rank: 0,
            network_timestamp: 100,
            content: Content::Text("test".to_string()),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        let hash = node.hash();
        store.put_node(&conv_id, node, true).unwrap();
        store.set_heads(&conv_id, vec![hash]).unwrap(); // This forces state.bin to be written
    }

    // Manually corrupt the active_journal_id in state.bin to cause a mismatch
    let state_path = root.join("conversations").join(&conv_hex).join("state.bin");

    assert!(
        state_path.exists(),
        "state.bin should exist after set_heads"
    );

    let mut state_data = fs::read(&state_path).unwrap();
    // active_journal_id is the last field in ConvState (u64).
    // ConvState is MessagePack encoded. In this simple case, the u64 is likely at the end.
    let len = state_data.len();
    if len > 8 {
        // Change the last byte to ensure a mismatch
        state_data[len - 1] = state_data[len - 1].wrapping_add(1);
    }
    fs::write(&state_path, state_data).unwrap();

    let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
    let (verified, _) = store.get_node_counts(&conv_id);

    // SPEC: Section 4.1 "Startup (The Fast Path)": 2. If IDs mismatch, truncate the journal immediately.
    assert_eq!(
        verified, 0,
        "Spec Section 4.1 mandates that if generation IDs mismatch, the journal MUST be truncated immediately."
    );
}

#[test]
fn test_ratchet_slot_alignment() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([4u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        // Add a node to advance sequence number, then compact to move it to ratchet.bin
        let node = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: 10,
            topological_rank: 0,
            network_timestamp: 100,
            content: Content::Text("Trigger".to_string()),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        store.put_node(&conv_id, node, true).unwrap();
        store.compact(&conv_id).unwrap();
    }

    let ratchet_path = root
        .join("conversations")
        .join(conv_hex)
        .join("ratchet.bin");
    let data = fs::read(&ratchet_path).unwrap();

    // SPEC: Section 6.2 - RatchetSlot: 32 (PK) + 32 (CK) + 8 (Seq) = 72 bytes.
    // Header is 16 bytes.
    assert!(
        data.len() >= 16 + 72,
        "Ratchet file should contain at least one slot of 72 bytes."
    );

    // Check magic
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    assert_eq!(magic, 0x52415443, "Ratchet magic mismatch (0x52415443).");
}

#[test]
fn test_vouch_record_injection() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([5u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    // 1. Initialize store and perform an operation to trigger ensure_conversation
    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        store.get_heads(&conv_id); // Trigger lazy init
    }

    // 2. Manually append a Vouch record to the journal
    let journal_path = root
        .join("conversations")
        .join(conv_hex)
        .join("journal.bin");

    assert!(
        journal_path.exists(),
        "Journal should exist after lazy init"
    );

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .unwrap();

    // SPEC: Section 4.1 - FramedRecord: [u32 length] [u8[32] hash] [u8 type] [Payload]
    // Type 0x02 (Vouch)
    let payload = vec![
        0x91, 0xC4, 0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
    ]; // MsgPack([PhysicalDevicePk])
    let hash = blake3::hash(&payload);
    let length = payload.len() as u32;

    file.write_all(&length.to_le_bytes()).unwrap();
    file.write_all(hash.as_bytes()).unwrap();
    file.write_all(&[0x02u8]).unwrap(); // Type: Vouch
    file.write_all(&payload).unwrap();
    drop(file);

    // 3. Re-open the store. It should successfully parse the Vouch record during replay_journal.
    let _store = FsStore::new(root.clone(), fs_handle.clone())
        .expect("Store should successfully replay journal with Vouch records.");
}

#[test]
fn test_storage_tier_transparency() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs_handle = Arc::new(StdFileSystem);
    let conv_id = ConversationId::from([6u8; 32]);
    let conv_hex = encode_hex_32(conv_id.as_bytes());

    {
        let store = FsStore::new(root.clone(), fs_handle.clone()).unwrap();
        store.get_heads(&conv_id); // Trigger lazy init
    }

    // SPEC: Section 1 - Transparency: The storage structure should be human-readable/navigable via standard CLI tools (ls, cd).
    assert!(root.join("conversations").join(&conv_hex).exists());
    assert!(
        root.join("conversations")
            .join(&conv_hex)
            .join("journal.bin")
            .exists()
    );
}
