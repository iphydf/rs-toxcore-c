//! Adversarial coverage for `ProtocolMessage::BlobReq` (legacy
//! pull-based fetch fallback). Companion to
//! `adversarial_blob_fetch_test.rs`, which covers the push path.
//!
//! `BlobReq` carries peer-supplied `offset: u64` and `length: u32`
//! that drive a `BlobStore::get_chunk` call directly. The storage
//! layer has defensive bounds checks today, but the handler trusts
//! them — a future store implementation that lost the check would
//! re-open OOM / overread vectors. The fix wraps both fields as
//! `Untrusted<_>` and clamps at the handler entry: `length` must be
//! at most `CHUNK_SIZE` (legitimate senders only ever request one
//! 64 KiB chunk at a time — see `cas.rs::next_requests`), and the
//! request is dropped silently if the cap is exceeded.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{BlobInfo, BlobReq, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
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
    requester_pk: PhysicalDevicePk,
}

fn fixture() -> Fixture {
    let _ = tracing_subscriber::fmt::try_init();
    let seeder = TestIdentity::new();
    let requester = TestIdentity::new();
    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let conv_id = merkle_tox_core::dag::ConversationId::from([0xC1u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let mut engine = MerkleToxEngine::new(
        seeder.device_pk,
        seeder.master_pk,
        StdRng::seed_from_u64(0xBE51),
        tp,
    );
    let store = InMemoryStore::new();

    // Seed the requester as an authorised member of the blob's
    // conversation. The BlobReq handler now mirrors `BlobFetch`'s
    // gate (drop unless `blob_conversations.get(&hash)` resolves to
    // a conv where `sessions.contains_key((sender, conv))`); without
    // this seeding the existing offset/length-clamp tests below
    // would all hit the auth gate and silently drop the request.
    {
        use merkle_tox_core::dag::KConv;
        use merkle_tox_core::engine::Conversation;
        use merkle_tox_core::engine::conversation::{ConversationData, Established};
        use merkle_tox_core::engine::session::{
            PeerSession, SyncSession, handshake::Handshake,
        };
        engine.blob_conversations.insert(blob_hash, conv_id);
        let established = ConversationData::<Established>::new(
            conv_id,
            KConv::from([0x11u8; 32]),
            1000,
        );
        engine
            .conversations
            .insert(conv_id, Conversation::Established(established));
        let session = SyncSession::<Handshake>::new(conv_id, &store, false, Instant::now());
        engine
            .sessions
            .insert((requester.device_pk, conv_id), PeerSession::Handshake(session));
    }

    // Stage a 4-chunk blob (256 KiB) so an honest 64 KiB BlobReq
    // succeeds and an oversized one is the discriminating signal.
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
            .put_chunk(&conv_id, &blob_hash, i * CHUNK_SIZE, &chunk, None)
            .unwrap();
    }

    Fixture {
        engine,
        store,
        blob_hash,
        requester_pk: requester.device_pk,
    }
}

fn count_blob_data(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(_, ProtocolMessage::BlobData(_))))
        .count()
}

/// §BR-1 — Honest baseline: a `BlobReq` for one piece
/// (`length = MAX_PIECE_DATA`) at a valid `offset` must produce a
/// `BlobData` effect carrying the piece bytes. Without this the fix
/// could regress to "reject everything" and pass §BR-2/3 trivially.
///
/// Note: previously the legacy pull-fallback served up to one
/// CHUNK_SIZE-sized response per `BlobReq`. The migration of
/// `BlobData.data` to `BoundedBytes<MAX_PIECE_DATA>` (the modern
/// per-piece envelope) makes the handler structurally limited to
/// one piece — the chunk-size variant was always over-MTU and is
/// not actually achievable in a single Tox datagram.
#[test]
fn test_blob_req_honest_one_chunk_succeeds() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.requester_pk,
            ProtocolMessage::BlobReq(BlobReq {
                hash: f.blob_hash,
                offset: Untrusted::new(0),
                length: Untrusted::new(merkle_tox_core::cas::MAX_PIECE_DATA as u32),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert_eq!(
        count_blob_data(&effects),
        1,
        "a one-piece BlobReq at a valid offset must serve the piece \
         — honest pull-fallback path",
    );
}

/// §BR-2 — `length > MAX_PIECE_DATA` (formerly CHUNK_SIZE) is the
/// type-level invariant: the handler caps at one piece per
/// `BlobReq` so a malicious peer cannot ask the seeder to read
/// megabytes into a single response packet (which `tox-sequenced`
/// would then have to fragment). Drop silently at the handler.
#[test]
fn test_blob_req_oversized_length_is_rejected() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.requester_pk,
            ProtocolMessage::BlobReq(BlobReq {
                hash: f.blob_hash,
                offset: Untrusted::new(0),
                // 8 × CHUNK_SIZE = 512 KiB request — twice the blob
                // size, well above the per-request ceiling.
                length: Untrusted::new((CHUNK_SIZE * 8) as u32),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert_eq!(
        count_blob_data(&effects),
        0,
        "BlobReq with length > CHUNK_SIZE must not produce a \
         BlobData effect — without the handler-level cap, a peer can \
         force the seeder into multi-megabyte single-packet reads \
         that fragment unpredictably",
    );
}

/// §BR-3 — `u32::MAX` length is the most extreme variant of §BR-2:
/// without the type-level wrap, a careless future change could let
/// this through to `get_chunk(..)`, where an arithmetic check on
/// `offset + length` could (under a future store implementation that
/// lost SQLite's defensive guard) overread the file. Pin the
/// handler-level rejection.
#[test]
fn test_blob_req_u32_max_length_is_rejected() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.requester_pk,
            ProtocolMessage::BlobReq(BlobReq {
                hash: f.blob_hash,
                offset: Untrusted::new(0),
                length: Untrusted::new(u32::MAX),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert_eq!(
        count_blob_data(&effects),
        0,
        "BlobReq with length = u32::MAX must be dropped at the \
         handler before any storage call — the type wrap exists \
         exactly so this guard is unforgettable",
    );
}

/// §BR-4 — `offset` past `blob_size` must also be rejected at the
/// handler. The engine knows `blob_size` from `BlobInfo`; with the
/// type wrap, the handler must explicitly clamp before passing
/// `offset` into the store.
#[test]
fn test_blob_req_oversized_offset_is_rejected() {
    let mut f = fixture();

    let effects = f
        .engine
        .handle_message(
            f.requester_pk,
            ProtocolMessage::BlobReq(BlobReq {
                hash: f.blob_hash,
                // Past the 4-chunk blob's end.
                offset: Untrusted::new(CHUNK_SIZE * 100),
                length: Untrusted::new(CHUNK_SIZE as u32),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert_eq!(
        count_blob_data(&effects),
        0,
        "BlobReq with offset past blob_size must be dropped at the \
         handler — the storage layer's defensive bounds check is \
         defense-in-depth, not the primary gate",
    );
}

/// §BR-5 — A `BlobReq` from a peer who is NOT a session-member of
/// the blob's conversation must be dropped, mirroring the existing
/// `BlobFetch` gate (`handlers/mod.rs:1023-1031`). Without this
/// gate, any friend who learns a blob hash (former member, leaked
/// log, public hash) can drain the seeder's upload bandwidth at
/// line rate by piping `BlobReq`s — same authorization story as
/// `BlobFetch`, just on the legacy pull-fallback channel.
#[test]
fn test_blob_req_from_non_member_is_rejected() {
    let mut f = fixture();
    // Outsider: a friend at the transport layer (the underlying Tox
    // friend gate has admitted them) but with no session in the
    // blob's conversation. This is the discriminating signal — the
    // request must be rejected purely on conversation membership.
    let outsider = PhysicalDevicePk::from([0xDEu8; 32]);

    let effects = f
        .engine
        .handle_message(
            outsider,
            ProtocolMessage::BlobReq(BlobReq {
                hash: f.blob_hash,
                offset: Untrusted::new(0),
                length: Untrusted::new(merkle_tox_core::cas::MAX_PIECE_DATA as u32),
            }),
            &f.store,
            Some(&f.store),
        )
        .unwrap();

    assert_eq!(
        count_blob_data(&effects),
        0,
        "BlobReq from a non-member of the blob's conversation must \
         not produce a BlobData reply — without the gate, any friend \
         who knows a blob hash can drain upload bandwidth at line \
         rate, same shape as the BlobFetch attack closed earlier",
    );
}
