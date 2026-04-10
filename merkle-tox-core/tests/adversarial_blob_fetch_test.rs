//! Adversarial coverage for `ProtocolMessage::BlobFetch`.
//!
//! The seeder-side handler creates a `PushStream` whenever
//! `blob_store.has_blob(hash) && status == Available`. No check ties
//! the requester to the conversation the blob was exported from, so
//! any peer with a friend connection (including a since-revoked
//! former member) can drain gigabytes of chunks by sending a single
//! `BlobFetch(hash)`.
//!
//! The chunk bytes themselves are encrypted under `K_export` — so
//! confidentiality is preserved — but the seeder pays the full
//! bandwidth cost. The fix gates `BlobFetch` on "we share a
//! conversation with the requester, and that conversation is the one
//! the blob was exported from".

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobFetch, BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ConversationId, KConv, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::{InMemoryStore, TestIdentity};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;
use tox_proto::Untrusted;

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
    let seeder = TestIdentity::new();
    let member = TestIdentity::new();
    let outsider = TestIdentity::new();
    let blob_conv_id = ConversationId::from([0xC1u8; 32]);
    let other_conv_id = ConversationId::from([0xC2u8; 32]);
    let blob_hash = NodeHash::from([0xBBu8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        seeder.device_pk,
        seeder.master_pk,
        StdRng::seed_from_u64(0xBFBF),
        tp,
    );
    let store = InMemoryStore::new();

    // Stage a small blob in the seeder's store. 4 chunks gives the
    // clamp-range tests room to distinguish "skipped" chunks from
    // "still to send" chunks.
    let info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE * 4,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(info).unwrap();
    let chunk = vec![0xCDu8; CHUNK_SIZE as usize];
    for i in 0..4 {
        store
            .put_chunk(&blob_conv_id, &blob_hash, i * CHUNK_SIZE, &chunk, None)
            .unwrap();
    }

    // Tie the blob to `blob_conv_id` in the engine's auth map. In
    // production this is populated when a HistoryExport is received
    // or locally authored.
    engine
        .blob_conversations
        .insert(blob_hash, blob_conv_id);

    // Seed a session for the legitimate member in the blob's
    // conversation, and a session for the outsider in a different
    // conversation. Both peers have *some* friend connection to the
    // seeder; the gate must distinguish them by which conversation
    // the blob belongs to.
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
    use merkle_tox_core::engine::conversation::{ConversationData, Established};
    use merkle_tox_core::engine::session::{PeerSession, SyncSession, handshake::Handshake};
    use merkle_tox_core::engine::Conversation;

    // Minimal Established conversation so other side-effects don't
    // trip. The exact k_conv is irrelevant for the BlobFetch gate.
    let k_conv = KConv::from([0x11u8; 32]);
    let established = ConversationData::<Established>::new(conv_id, k_conv, 1000);
    engine
        .conversations
        .entry(conv_id)
        .or_insert_with(|| Conversation::Established(established));

    // A Handshake-state session is enough to signal "peer is an
    // authorised participant of this conversation"; the BlobFetch
    // gate checks session membership, not state.
    let session = SyncSession::<Handshake>::new(conv_id, store, false, Instant::now());
    engine
        .sessions
        .insert((peer_pk, conv_id), PeerSession::Handshake(session));
}

/// §BF-1 — A `BlobFetch` from a peer who is NOT an active member of
/// the blob's conversation must be dropped. No `PushStream` must be
/// registered; otherwise the seeder serves out gigabytes of chunks to
/// a since-revoked or unrelated peer.
#[test]
fn test_blob_fetch_from_non_member_is_rejected() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.outsider_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: f.blob_hash,
                completed_ranges: None,
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert!(
        !f.engine.push_streams.contains_key(&(f.blob_hash, f.outsider_pk)),
        "BlobFetch from a non-member of the blob's conversation must \
         not register a push stream — lets any peer drain the seeder's \
         upload bandwidth on a blob they aren't authorised to receive",
    );
}

/// §BF-2 — Regression guard: a `BlobFetch` from a peer who IS an
/// active member of the blob's conversation must still create a push
/// stream. Otherwise the fix regresses to "nobody can fetch".
#[test]
fn test_blob_fetch_from_conversation_member_still_accepted() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.member_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: f.blob_hash,
                completed_ranges: None,
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert!(
        f.engine.push_streams.contains_key(&(f.blob_hash, f.member_pk)),
        "BlobFetch from an active member of the blob's conversation \
         must create a push stream — the fix must not regress to \
         blanket rejection",
    );
    let _ = f.blob_conv_id;
}

/// §BF-3 — `completed_ranges: Some(...)` honest path. When a requester
/// tells the seeder "I already have chunks 0..=1", the push stream
/// must skip those chunks — `next_piece()` returns an offset inside
/// chunk 2 or later, never inside chunks 0 or 1. Without this test
/// the clamp logic in the handler is dead code: every existing
/// fixture uses `None` and never exercises the `Some` branch.
#[test]
fn test_blob_fetch_with_prior_completed_ranges_skips_those_chunks() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.member_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: f.blob_hash,
                completed_ranges: Some(tox_proto::bounded_vec![(
                    Untrusted::new(0),
                    Untrusted::new(1)
                )]),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    let stream = f
        .engine
        .push_streams
        .get_mut(&(f.blob_hash, f.member_pk))
        .expect("push stream should exist for authorised member");
    let first_offset = stream
        .next_piece()
        .expect("seeder must have something to push for a 4-chunk blob \
                 when the requester only has chunks 0..=1");
    assert!(
        first_offset >= 2 * CHUNK_SIZE,
        "seeder pushed offset {} (chunk {}), but requester already has \
         chunks 0..=1 — the honest completed_ranges was ignored",
        first_offset,
        first_offset / CHUNK_SIZE,
    );
}

/// §BF-4 — An adversarial `completed_ranges` that names out-of-range
/// chunk indices must be clamped at the handler before it reaches
/// `PushStream`, so the internal `receiver_completed` state never
/// holds a bound past `num_chunks`. Inspect the state directly:
/// observable send-path behaviour alone is not discriminating because
/// `receiver_has_chunk` uses containment only, not arithmetic on
/// peer-supplied values.
#[test]
fn test_blob_fetch_with_out_of_range_completed_ranges_is_clamped() {
    let mut f = fixture();

    f.engine
        .handle_message(
            f.member_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: f.blob_hash,
                // Mix one valid range with two out-of-range ranges so
                // we can tell "clamp silently kept the valid one" from
                // "the whole list was dropped".
                completed_ranges: Some(tox_proto::bounded_vec![
                    (Untrusted::new(0), Untrusted::new(1)),
                    (Untrusted::new(u64::MAX - 1), Untrusted::new(u64::MAX)),
                    (Untrusted::new(100), Untrusted::new(u64::MAX)),
                ]),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    let stream = f
        .engine
        .push_streams
        .get(&(f.blob_hash, f.member_pk))
        .expect("push stream should exist for authorised member");
    let ranges = stream.receiver_ranges();
    // Post-clamp: only (0, 1) survives. The first out-of-range pair
    // is filtered entirely by `checked_in(0, num_chunks)` on its
    // start. The second has a valid start (100 is outside the
    // 4-chunk blob so also filtered by checked_in).
    assert_eq!(
        ranges,
        &[(0u64, 1u64)],
        "post-clamp receiver_ranges must retain only the valid (0, 1) \
         entry — any raw peer-supplied chunk_idx past num_chunks \
         would otherwise sit in internal state, ready to drive \
         arithmetic in any future consumer that trusts these bounds",
    );
}
