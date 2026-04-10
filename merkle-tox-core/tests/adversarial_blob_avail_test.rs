//! Adversarial coverage for `ProtocolMessage::BlobAvail`.
//!
//! `BlobAvail` is a peer-supplied "I have this blob" advertisement.
//! Sibling `BlobFetch` is gated at `handlers/mod.rs:962-978` against
//! `blob_conversations + sessions` — only peers in the blob's
//! conversation are served. `BlobAvail` had **no equivalent gate**:
//! any friend-connected peer could ship a `BlobAvail` for any 32-byte
//! hash and force the local node to either:
//!
//!   1. Allocate a fresh `SwarmSync` keyed by the hash (no cap, no
//!      eviction) AND emit `Effect::WriteBlobInfo(local_info)` — a
//!      **synchronous disk write** per fake hash through
//!      `merkle-tox-fs/src/blob.rs::write_blob_info`. A single friend
//!      sending random hashes at line rate forces unbounded local
//!      memory + disk amplification.
//!
//!   2. For hashes we *are* already syncing, register the sender as a
//!      seeder via `sync.add_seeder(sender_pk)` — letting any friend
//!      pollute the seeder set of any in-progress download, including
//!      blobs the friend is not authorised to participate in.
//!
//! The fix mirrors the `BlobFetch` gate at the top of the BlobAvail
//! arm: drop the message unless `blob_conversations.get(&hash)`
//! resolves to a conversation `c` AND `sessions.contains_key(&(sender,
//! c))`. This closes both branches with a single check.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE, SwarmSync};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::testing::{InMemoryStore, TestIdentity};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

struct Fixture {
    engine: MerkleToxEngine,
    store: InMemoryStore,
    blob_hash: NodeHash,
    blob_conv_id: ConversationId,
    member_pk: PhysicalDevicePk,
    outsider_pk: PhysicalDevicePk,
}

fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt::try_init();
    let receiver = TestIdentity::new();
    let member = TestIdentity::new();
    let outsider = TestIdentity::new();
    let blob_conv_id = ConversationId::from([0xC1u8; 32]);
    let other_conv_id = ConversationId::from([0xC2u8; 32]);
    let blob_hash = NodeHash::from([0xBBu8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        receiver.device_pk,
        receiver.master_pk,
        StdRng::seed_from_u64(0xBA1A),
        tp,
    );
    let store = InMemoryStore::new();

    // Tie the blob to `blob_conv_id` in the engine's auth map. In
    // production this is populated when a HistoryExport / authoring
    // node lands and the blob hash becomes known to the conversation.
    engine.blob_conversations.insert(blob_hash, blob_conv_id);

    // Seed the legitimate member in the blob's conversation, the
    // outsider in a different conversation. Both have a friend
    // connection at the transport layer — the gate must distinguish
    // by which conversation we share with each.
    seed_active_session(&mut engine, member.device_pk, blob_conv_id, &store);
    seed_active_session(&mut engine, outsider.device_pk, other_conv_id, &store);

    Fixture {
        engine,
        store,
        blob_hash,
        blob_conv_id,
        member_pk: member.device_pk,
        outsider_pk: outsider.device_pk,
    }
}

fn seed_active_session(
    engine: &mut MerkleToxEngine,
    peer_pk: PhysicalDevicePk,
    conv_id: ConversationId,
    store: &InMemoryStore,
) {
    use merkle_tox_core::engine::Conversation;
    use merkle_tox_core::engine::conversation::{ConversationData, Established};
    use merkle_tox_core::engine::session::{PeerSession, SyncSession, handshake::Handshake};

    let k_conv = KConv::from([0x11u8; 32]);
    let established = ConversationData::<Established>::new(conv_id, k_conv, 1000);
    engine
        .conversations
        .entry(conv_id)
        .or_insert_with(|| Conversation::Established(established));

    let session = SyncSession::<Handshake>::new(conv_id, store, false, Instant::now());
    engine
        .sessions
        .insert((peer_pk, conv_id), PeerSession::Handshake(session));
}

fn peer_blob_info(hash: NodeHash) -> BlobInfo {
    BlobInfo {
        hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    }
}

/// §BA-1 — A `BlobAvail` from a peer who is NOT a session-member of
/// the blob's conversation must be dropped before any state mutates.
/// No `SwarmSync` must be allocated and no `WriteBlobInfo` effect
/// emitted. Without this gate, an authenticated friend can spam
/// random hashes and drive unbounded `engine.blob_syncs` growth plus
/// matching disk writes via the fs `write_blob_info` path.
#[test]
fn test_blob_avail_from_non_member_is_dropped_no_alloc_no_disk_write() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.outsider_pk,
            ProtocolMessage::BlobAvail(peer_blob_info(f.blob_hash)),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert!(
        !f.engine.blob_syncs.contains_key(&f.blob_hash),
        "BlobAvail from non-member must not allocate a SwarmSync — \
         that's the in-memory amplification leg of the attack",
    );
    let write_blob_info_emitted = effects
        .iter()
        .any(|e| matches!(e, Effect::WriteBlobInfo(_)));
    assert!(
        !write_blob_info_emitted,
        "BlobAvail from non-member must not emit WriteBlobInfo — \
         that effect lands as a synchronous disk write per emission \
         and is the disk amplification leg of the attack",
    );
}

/// §BA-2 — A `BlobAvail` from a non-member for a blob we are *already*
/// syncing must not register the sender as a seeder. The existing-
/// sync branch is the second exposure: even when the new-allocation
/// path is closed, an unauthorised peer must not pollute the seeder
/// set of an in-progress download.
#[test]
fn test_blob_avail_from_non_member_does_not_add_seeder() {
    let mut f = fixture();

    // Pre-register a SwarmSync so the existing-sync branch is the
    // one under test.
    let our_info = BlobInfo {
        hash: f.blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    f.engine
        .blob_syncs
        .insert(f.blob_hash, SwarmSync::new(our_info));

    f.engine
        .handle_message(
            f.outsider_pk,
            ProtocolMessage::BlobAvail(peer_blob_info(f.blob_hash)),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    let sync = f
        .engine
        .blob_syncs
        .get(&f.blob_hash)
        .expect("pre-registered sync should still exist");
    assert!(
        !sync.has_seeder(&f.outsider_pk),
        "BlobAvail from non-member must not register the sender as a \
         seeder — without this gate any friend can pollute seeder \
         sets of in-progress downloads",
    );
}

/// §BA-3 — Hash unknown to `blob_conversations` is rejected even from
/// an otherwise-authenticated friend. The attacker's primary vector
/// is "spam random hashes that don't belong to any conversation we
/// know about" — `blob_conversations.get(&random_hash) == None`. The
/// gate must reject on that branch, not just the wrong-conversation
/// branch.
#[test]
fn test_blob_avail_for_unknown_hash_is_dropped() {
    let mut f = fixture();
    let random_hash = NodeHash::from([0xDEu8; 32]);

    let effects = f
        .engine
        .handle_message(
            f.member_pk, // same friend, but for a hash they shouldn't know
            ProtocolMessage::BlobAvail(peer_blob_info(random_hash)),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert!(
        !f.engine.blob_syncs.contains_key(&random_hash),
        "BlobAvail for a hash not in `blob_conversations` must not \
         allocate a SwarmSync — this is the primary attack vector \
         (spam random hashes that don't map to any conversation)",
    );
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::WriteBlobInfo(_))),
        "BlobAvail for unknown hash must not emit WriteBlobInfo",
    );
}

/// §BA-4 — Honest baseline: a `BlobAvail` from a peer who IS a
/// session-member of the blob's conversation must still allocate a
/// `SwarmSync` (or update an existing one) and emit `WriteBlobInfo`.
/// Without this regression guard the fix could degenerate to "drop
/// everything" and pass §BA-1/2/3 trivially.
#[test]
fn test_blob_avail_from_conversation_member_is_accepted() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.member_pk,
            ProtocolMessage::BlobAvail(peer_blob_info(f.blob_hash)),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert!(
        f.engine.blob_syncs.contains_key(&f.blob_hash),
        "BlobAvail from an active conversation member must allocate \
         a SwarmSync — the fix must not regress to blanket rejection",
    );
    assert!(
        effects.iter().any(|e| matches!(e, Effect::WriteBlobInfo(_))),
        "BlobAvail from an active member must emit WriteBlobInfo so \
         the new sync's BlobInfo is persisted",
    );
    let _ = f.blob_conv_id;
}
