//! Adversarial demonstration: `BlobAvail` accepts unclamped peer-
//! supplied `info.size`, which then drives unbounded receiver-side
//! `partial_chunks` allocation in the `BlobData` handler.
//!
//! ## Attack chain
//!
//! 1. Friend in our conversation ships
//!    `BlobAvail(BlobInfo { hash, size: <huge>, ... })`. The
//!    `blob_conversations + sessions` gate at handlers/mod.rs:759
//!    (commit f5eee7a) admits the message — the attacker is a
//!    legitimate conversation member.
//! 2. The handler at handlers/mod.rs:784-790 clones the peer's
//!    `BlobInfo` into `SwarmSync::new_with_offset(local_info, ...)`
//!    **without** clamping `size`. `BlobInfo.size: u64` is a raw
//!    field at cas.rs:23 (no `Untrusted<T>` wrapper). The
//!    `HistoryExport` ingestion path clamps via
//!    `blob_size.checked_le(MAX_BLOB_SIZE)` at
//!    processor/verification.rs:629; `BlobAvail` is the asymmetry.
//! 3. Subsequent `BlobData` packets clamp incoming `data.offset`
//!    against `sync.info.size` (handlers/mod.rs:857) — but
//!    `sync.info.size` is now the attacker's value, so any offset
//!    up to that cap is admitted.
//! 4. Each fresh `chunk_idx` (= `offset / CHUNK_SIZE`) triggers
//!    `partial_chunks.entry(chunk_idx).or_insert_with(|| vec![0u8;
//!    full_chunk_size])` at handlers/mod.rs:888-890. With one piece
//!    sent per chunk (offset = `chunk_idx * CHUNK_SIZE`,
//!    `data.len()` = MAX_PIECE_DATA), `chunk_now_complete` never
//!    fires (a chunk needs all ~50 pieces to complete), so the
//!    65 536-byte buffer persists.
//! 5. `remove_seeder` (cas.rs:750-753) clears `seeders` and
//!    `active_fetches` but **not** `partial_chunks` — even
//!    proof-verify failure later doesn't free the receiver state.
//!
//! ## Amplification measured by this test
//!
//! Pre-fix: 1 BlobAvail (~150 wire bytes) + 256 BlobData pieces
//! (~1.3 KB each, ~333 KB total wire) → 256 × 65 536 = 16 MiB of
//! resident `partial_chunks`. Roughly **48× amplification** of the
//! attacker's wire footprint, sustained until process restart.
//!
//! At realistic friend-link rate (10 k pkt/s) the attacker reaches
//! GB-scale receiver RAM in seconds. The fix clamps `info.size`
//! against `MAX_BLOB_SIZE` (100 GiB) at the `BlobAvail` handler
//! entry, mirroring the HistoryExport precedent.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobData, BlobInfo, BlobStatus, CHUNK_SIZE, MAX_PIECE_DATA};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::Conversation;
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::engine::conversation::{ConversationData, Established};
use merkle_tox_core::engine::session::{PeerSession, SyncSession, handshake::Handshake};
use merkle_tox_core::testing::{InMemoryStore, TestIdentity};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;

struct Fixture {
    engine: MerkleToxEngine,
    store: InMemoryStore,
    conv_id: ConversationId,
    blob_hash: NodeHash,
    attacker_pk: PhysicalDevicePk,
}

fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt::try_init();
    let receiver = TestIdentity::new();
    let attacker = TestIdentity::new();
    let conv_id = ConversationId::from([0xC1u8; 32]);
    let blob_hash = NodeHash::from([0xBBu8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        receiver.device_pk,
        receiver.master_pk,
        StdRng::seed_from_u64(0xB1A4),
        tp,
    );
    let store = InMemoryStore::new();

    // The attacker is a legitimate conversation member. Pre-recent-
    // commits this would have been the only gate; now it's necessary
    // but not sufficient — `info.size` clamping is the missing piece.
    let established =
        ConversationData::<Established>::new(conv_id, KConv::from([0x11u8; 32]), 1000);
    engine
        .conversations
        .insert(conv_id, Conversation::Established(established));
    engine.blob_conversations.insert(blob_hash, conv_id);
    let session = SyncSession::<Handshake>::new(conv_id, &store, false, Instant::now());
    engine.sessions.insert(
        (attacker.device_pk, conv_id),
        PeerSession::Handshake(session),
    );

    Fixture {
        engine,
        store,
        conv_id,
        blob_hash,
        attacker_pk: attacker.device_pk,
    }
}

/// §BAOOM-1 — Wire-to-receiver-RAM amplification: `info.size` set
/// well above `MAX_BLOB_SIZE` (100 GiB) must not seed a `SwarmSync`
/// whose attacker-controlled ceiling lets subsequent `BlobData`
/// pieces drive unbounded `partial_chunks` allocation.
///
/// Pre-fix this test panics with a measurement of the actual amp
/// factor — the assertion message is the demonstration. Post-fix the
/// `BlobAvail` is dropped at the `MAX_BLOB_SIZE` clamp, no sync
/// exists, and the BlobData stream allocates nothing.
#[test]
fn test_blob_avail_oversize_info_size_does_not_seed_unbounded_partial_chunks() {
    let mut f = fixture();

    // 1 TiB — well above MAX_BLOB_SIZE = 100 GiB. The legitimate
    // protocol cap (tox_proto::constants::MAX_BLOB_SIZE) is the
    // gate the HistoryExport path already enforces; this packet
    // should be dropped at the same boundary.
    let attacker_info = BlobInfo {
        hash: f.blob_hash,
        size: 1u64 << 40,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };

    // Step 1 of the attack chain: the BlobAvail seeds blob_syncs
    // with the attacker's size. Pre-fix this succeeds.
    f.engine
        .handle_message(
            f.attacker_pk,
            ProtocolMessage::BlobAvail(attacker_info),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    // Step 2: stream 256 BlobData pieces with distinct chunk_idx,
    // one piece per chunk. Each unique chunk_idx triggers
    // `vec![0u8; 65 536]` in partial_chunks. With chunk_now_complete
    // requiring all pieces of a chunk, 1-piece-per-chunk leaves all
    // buffers permanently live.
    const NUM_DISTINCT_CHUNKS: u64 = 256;
    let piece_data = vec![0xAAu8; MAX_PIECE_DATA];
    for chunk_idx in 0..NUM_DISTINCT_CHUNKS {
        let offset = chunk_idx * CHUNK_SIZE;
        f.engine
            .handle_message(
                f.attacker_pk,
                ProtocolMessage::BlobData(BlobData {
                    hash: f.blob_hash,
                    offset: tox_proto::Untrusted::new(offset),
                    data: tox_proto::BoundedBytes::try_from_vec(piece_data.clone())
                        .expect("piece under cap"),
                    proof: tox_proto::BoundedBytes::new(),
                }),
                &f.store,
                Some(&f.store),
            )
            .unwrap();
    }

    // Measure receiver-side allocation. Post-fix, blob_syncs is
    // empty (BlobAvail was rejected at the cap), so this is 0.
    // Pre-fix, `sync.partial_chunks.len()` = NUM_DISTINCT_CHUNKS and
    // each entry is `CHUNK_SIZE` bytes — the assertion message
    // surfaces the wire→RAM amplification.
    let (partial_chunks_count, partial_bytes) = f
        .engine
        .blob_syncs
        .get(&f.blob_hash)
        .map(|sync| {
            let bytes: usize = sync.partial_chunks.values().map(|v| v.len()).sum();
            (sync.partial_chunks.len(), bytes)
        })
        .unwrap_or((0, 0));

    assert_eq!(
        partial_chunks_count,
        0,
        "BlobAvail with info.size = {} (above MAX_BLOB_SIZE = {}) must \
         be dropped at the cap. Observed {} buffered chunks ({} bytes \
         resident in `partial_chunks`) from {} small adversarial packets — \
         a ~{}× wire-to-receiver-RAM amplification. At line rate this \
         scales to multi-GB OOM in seconds, sustained until process \
         restart (remove_seeder does not clear partial_chunks).",
        1u64 << 40,
        tox_proto::constants::MAX_BLOB_SIZE,
        partial_chunks_count,
        partial_bytes,
        NUM_DISTINCT_CHUNKS + 1,
        partial_bytes / (NUM_DISTINCT_CHUNKS as usize + 1).max(1),
    );

    let _ = f.conv_id;
}

/// §BAOOM-2 — Honest baseline: a `BlobAvail` whose `info.size` is
/// within `MAX_BLOB_SIZE` must still seed a sync and let the
/// receiver buffer pieces normally. Without this regression guard
/// the fix could degenerate to "drop every BlobAvail" and pass
/// §BAOOM-1 trivially.
#[test]
fn test_blob_avail_within_cap_still_seeds_sync_and_buffers_pieces() {
    let mut f = fixture();

    let honest_info = BlobInfo {
        hash: f.blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };

    f.engine
        .handle_message(
            f.attacker_pk,
            ProtocolMessage::BlobAvail(honest_info),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    let piece = vec![0xCDu8; MAX_PIECE_DATA];
    f.engine
        .handle_message(
            f.attacker_pk,
            ProtocolMessage::BlobData(BlobData {
                hash: f.blob_hash,
                offset: tox_proto::Untrusted::new(0),
                data: tox_proto::BoundedBytes::try_from_vec(piece).expect("under cap"),
                proof: tox_proto::BoundedBytes::new(),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    let sync = f
        .engine
        .blob_syncs
        .get(&f.blob_hash)
        .expect("honest BlobAvail must seed a sync — fix must not regress");
    assert!(
        !sync.partial_chunks.is_empty(),
        "honest BlobData piece must reach `partial_chunks` — fix must \
         not regress to dropping all pieces",
    );
}
