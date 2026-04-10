//! Engine-level TDD tests for chunk-boundary verification.
//!
//! These tests pin down the security contract of the BlobData receive
//! path. They define the "what" — what the engine must do on valid vs
//! invalid pieces — independently of the "how" (which lives in
//! `src/engine/handlers/mod.rs` and `src/cas.rs`).
//!
//! Security properties pinned:
//!
//! 1. A well-formed chunk with a valid proof is accepted and written to
//!    disk (exactly one WriteChunk effect per completed chunk).
//! 2. A chunk whose bytes have been tampered with in flight is
//!    rejected. No WriteChunk, no completion mark, and the seeder is
//!    removed from the SwarmSync seeder set so subsequent requests
//!    won't go to them.
//! 3. A chunk whose proof is structurally valid but has been corrupted
//!    (wrong path hash) is rejected and the seeder is removed.
//! 4. A chunk whose proof authenticates against a different root is
//!    rejected and the seeder is removed.
//! 5. A chunk that completes without ever having received a proof is
//!    rejected (not silently accepted). Prevents the "forgot to send a
//!    proof" or "stripped proof in flight" attack.
//! 6. The authentic root comes from the trusted `sync.info.hash` —
//!    NOT from any field in the BlobData message itself. The receiver
//!    ignores anything a seeder sends about the root.
//!
//! The tests use a locally-constructed trust chain (ChunkMerkleTree over
//! synthetic chunks), skipping the DAG sig + BlobAvail plumbing so the
//! verification logic itself is what's under test.

use merkle_tox_core::ProtocolMessage;
use merkle_tox_core::cas::{
    BlobData, BlobInfo, BlobStatus, CHUNK_SIZE, ChunkMerkleTree, MAX_PIECE_DATA, SwarmSync,
};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{LogicalIdentityPk, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::testing::InMemoryStore;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

/// A test blob split into 64KB chunks, with the Merkle tree and root
/// ready to use.
struct TestBlob {
    root: NodeHash,
    size: u64,
    chunks: Vec<Vec<u8>>,
    tree: ChunkMerkleTree,
}

impl TestBlob {
    /// Build a test blob of `num_chunks` full 64KB chunks with the
    /// given `seed` mixed into every byte, so two `TestBlob`s with
    /// different seeds produce distinct chunks and distinct roots.
    fn new(num_chunks: u64, seed: u8) -> Self {
        let chunks: Vec<Vec<u8>> = (0..num_chunks)
            .map(|i| vec![i.wrapping_add(seed as u64) as u8; CHUNK_SIZE as usize])
            .collect();
        let tree = ChunkMerkleTree::from_chunks(chunks.iter().map(Vec::as_slice));
        Self {
            root: NodeHash::from(tree.root()),
            size: num_chunks * CHUNK_SIZE,
            chunks,
            tree,
        }
    }

    fn num_chunks(&self) -> u64 {
        self.chunks.len() as u64
    }
}

/// Set up a receiver engine with a pre-registered SwarmSync whose
/// `info.hash` is the trusted Merkle root. Mimics the state after Bob
/// has received a signed `Content::Blob` MerkleNode committing to
/// `blob.root`.
fn setup_receiver(blob: &TestBlob) -> (MerkleToxEngine, InMemoryStore, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let receiver_pk = PhysicalDevicePk::from([0x11u8; 32]);
    let sender_pk = PhysicalDevicePk::from([0x22u8; 32]);
    let mut engine = MerkleToxEngine::new(
        receiver_pk,
        LogicalIdentityPk::from([0x11u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();

    let info = BlobInfo {
        hash: blob.root,
        size: blob.size,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync = SwarmSync::new_with_offset(info, &receiver_pk);
    sync.add_seeder(sender_pk);
    engine.blob_syncs.insert(blob.root, sync);

    (engine, store, sender_pk)
}

/// Break a 64KB chunk into piece-sized BlobData messages for sender
/// `sender_pk`'s blob `blob.root`. The last piece of each chunk carries
/// the Merkle proof.
///
/// `tamper_byte_at`: if Some((chunk_idx, piece_idx)), flip one bit in
/// the data of the piece at that position before emitting it. Used to
/// simulate an attacker altering bytes in flight.
fn pieces_for_chunk(
    blob: &TestBlob,
    chunk_idx: u64,
    tamper_byte_at_piece: Option<usize>,
) -> Vec<BlobData> {
    let chunk = &blob.chunks[chunk_idx as usize];
    let chunk_start = chunk_idx * CHUNK_SIZE;
    let num_pieces = chunk.len().div_ceil(MAX_PIECE_DATA);
    let proof = blob.tree.proof_for(chunk_idx as usize);

    (0..num_pieces)
        .map(|piece_idx| {
            let piece_start = piece_idx * MAX_PIECE_DATA;
            let piece_end = (piece_start + MAX_PIECE_DATA).min(chunk.len());
            let mut data = chunk[piece_start..piece_end].to_vec();
            if Some(piece_idx) == tamper_byte_at_piece {
                data[0] ^= 0xFF;
            }
            let piece_proof = if piece_idx == num_pieces - 1 {
                proof.clone()
            } else {
                Vec::new()
            };
            BlobData {
                hash: blob.root,
                offset: tox_proto::Untrusted::new(chunk_start + piece_start as u64),
                data: tox_proto::BoundedBytes::try_from_vec(data).expect("under cap"),
                proof: tox_proto::BoundedBytes::try_from_vec(piece_proof).expect("under cap"),
            }
        })
        .collect()
}

/// Feed pieces through the engine, returning the flattened list of
/// effects emitted across all handle_message calls.
fn feed(
    engine: &mut MerkleToxEngine,
    store: &InMemoryStore,
    sender_pk: PhysicalDevicePk,
    pieces: Vec<BlobData>,
) -> Vec<Effect> {
    let mut all_effects = Vec::new();
    for p in pieces {
        let effects = engine
            .handle_message(
                sender_pk,
                ProtocolMessage::BlobData(p),
                store,
                Some(store),
            )
            .unwrap();
        all_effects.extend(effects);
    }
    all_effects
}

fn count_write_chunks(effects: &[Effect], blob_hash: NodeHash) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::WriteChunk(_, h, _, _, _) if *h == blob_hash))
        .count()
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn receiver_accepts_chunk_with_valid_proof() {
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    // Feed all pieces of chunk 0 with a valid proof.
    let pieces = pieces_for_chunk(&blob, 0, None);
    let effects = feed(&mut engine, &store, sender_pk, pieces);

    // Exactly one WriteChunk effect emitted on chunk completion.
    assert_eq!(
        count_write_chunks(&effects, blob.root),
        1,
        "valid chunk should produce exactly one WriteChunk"
    );

    // Seeder is still trusted — no verification failure.
    let sync = engine
        .blob_syncs
        .get(&blob.root)
        .expect("sync still exists");
    assert!(
        sync.seeders.contains_key(&sender_pk),
        "valid transfer should not remove the seeder"
    );
}

#[test]
fn receiver_accepts_every_chunk_across_multi_chunk_blob() {
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    for chunk_idx in 0..blob.num_chunks() {
        let pieces = pieces_for_chunk(&blob, chunk_idx, None);
        let _ = feed(&mut engine, &store, sender_pk, pieces);
    }

    // Seeder still trusted; blob sync removed on completion (see
    // BlobData handler: the sync is dropped once tracker.is_complete).
    assert!(
        !engine.blob_syncs.contains_key(&blob.root),
        "completed blob sync should be dropped after final chunk"
    );
}

// ---------------------------------------------------------------------------
// Failure paths — the real security properties
// ---------------------------------------------------------------------------

#[test]
fn receiver_rejects_tampered_chunk_data() {
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    // Tamper with byte 0 of piece 2 in chunk 1 (a middle piece, so the
    // tamper doesn't collide with the proof piece itself).
    let pieces = pieces_for_chunk(&blob, 1, Some(2));
    let effects = feed(&mut engine, &store, sender_pk, pieces);

    // No WriteChunk effect — the chunk must not land on disk.
    assert_eq!(
        count_write_chunks(&effects, blob.root),
        0,
        "tampered chunk must not produce a WriteChunk effect"
    );

    // Seeder removed from the SwarmSync seeder set.
    let sync = engine
        .blob_syncs
        .get(&blob.root)
        .expect("sync still exists after failure");
    assert!(
        !sync.seeders.contains_key(&sender_pk),
        "seeder that sent tampered data must be removed from the seeder set"
    );
}

#[test]
fn receiver_rejects_proof_with_flipped_sibling_hash() {
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    // Flip a bit in the proof attached to the last piece. The data
    // bytes are valid; only the proof is corrupt.
    let mut pieces = pieces_for_chunk(&blob, 2, None);
    let last = pieces.last_mut().expect("non-empty");
    assert!(!last.proof.is_empty(), "last piece must carry the proof");
    last.proof[0] ^= 0xFF;

    let effects = feed(&mut engine, &store, sender_pk, pieces);

    assert_eq!(count_write_chunks(&effects, blob.root), 0);
    let sync = engine.blob_syncs.get(&blob.root).unwrap();
    assert!(!sync.seeders.contains_key(&sender_pk));
}

#[test]
fn receiver_rejects_proof_from_different_blob() {
    let blob = TestBlob::new(4, 0);
    let other_blob = TestBlob::new(4, 99); // different chunk contents / root
    let (mut engine, store, sender_pk) = setup_receiver(&blob);
    assert_ne!(
        blob.root, other_blob.root,
        "two distinct blobs must have distinct roots"
    );

    // Feed chunk 0 of the CORRECT blob but with chunk 0's proof taken
    // from a DIFFERENT blob's tree. Data is valid, proof is for the
    // wrong root.
    let mut pieces = pieces_for_chunk(&blob, 0, None);
    let foreign_proof = other_blob.tree.proof_for(0);
    pieces.last_mut().unwrap().proof =
        tox_proto::BoundedBytes::try_from_vec(foreign_proof).expect("under cap");

    let effects = feed(&mut engine, &store, sender_pk, pieces);

    assert_eq!(count_write_chunks(&effects, blob.root), 0);
    let sync = engine.blob_syncs.get(&blob.root).unwrap();
    assert!(!sync.seeders.contains_key(&sender_pk));
}

#[test]
fn receiver_rejects_chunk_with_no_proof() {
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    // Feed all pieces with the proof stripped. An attacker that wanted
    // to avoid detection would simply omit the proof; the receiver
    // must not treat "no proof" as "verified".
    let mut pieces = pieces_for_chunk(&blob, 0, None);
    for p in pieces.iter_mut() {
        p.proof.clear();
    }

    let effects = feed(&mut engine, &store, sender_pk, pieces);

    assert_eq!(
        count_write_chunks(&effects, blob.root),
        0,
        "chunk without any proof must not be accepted"
    );
    let sync = engine.blob_syncs.get(&blob.root).unwrap();
    assert!(
        !sync.seeders.contains_key(&sender_pk),
        "seeder that omitted the proof must be removed"
    );
}

/// Regression guard for the scenario-5 retransmit amplification cascade
/// (task #22). A duplicate piece arriving AFTER a chunk was successfully
/// verified must not spuriously re-verify against a freshly-created
/// zero-filled buffer.
///
/// The cascade was:
/// 1. All pieces of chunk X arrive, verify succeeds, partial_chunks[X]
///    + pending_proofs[X] consumed, chunk in completed_ranges.
/// 2. A late retransmit piece for chunk X arrives.
/// 3. Handler did `partial_chunks.entry(X).or_insert_with(...)` → new
///    zero-filled buffer populated with only this one piece.
/// 4. `mark_piece_received` early-returned (chunk already complete).
/// 5. `chunk_now_complete` was still true (still in completed_ranges).
/// 6. Verification ran against the zero buffer with proof=None → FAIL.
/// 7. Seeder removed, chunk unmarked, cascade of retransmits followed.
///
/// The fix: drop duplicate pieces for already-completed chunks on the
/// floor, before touching partial_chunks or pending_proofs.
#[test]
fn receiver_drops_duplicate_piece_for_completed_chunk_without_reverifying() {
    let blob = TestBlob::new(1, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    // Phase 1: send all pieces of chunk 0 normally. Chunk completes,
    // WriteChunk effect emitted.
    let pieces = pieces_for_chunk(&blob, 0, None);
    let pieces_clone = pieces.clone();
    let effects = feed(&mut engine, &store, sender_pk, pieces);
    assert_eq!(
        count_write_chunks(&effects, blob.root),
        1,
        "phase 1 must produce exactly one WriteChunk"
    );
    // Seeder still trusted (no verification failure).
    assert!(
        engine
            .blob_syncs
            .get(&blob.root)
            .is_none_or(|sync| sync.seeders.contains_key(&sender_pk)),
        "seeder must not be removed after successful transfer"
    );

    // Phase 2: feed the SAME pieces again (simulating a late
    // retransmission). The receiver must NOT emit another WriteChunk,
    // and MUST NOT remove the seeder.
    let dup_effects = feed(&mut engine, &store, sender_pk, pieces_clone);
    let dup_write_chunks = count_write_chunks(&dup_effects, blob.root);
    assert_eq!(
        dup_write_chunks, 0,
        "duplicate pieces for a completed chunk must not produce \
         another WriteChunk — that indicates the receiver is \
         re-verifying against a fresh buffer populated with only the \
         duplicate piece, which either (a) spuriously succeeds and \
         writes corrupted data, or (b) spuriously fails and removes \
         the seeder. Either outcome is a regression of the cascade \
         that caused 5-16x retransmission amplification in scenario 5."
    );

    // If the blob was complete and the sync removed, that's also fine;
    // but if the sync still exists, the seeder must remain trusted.
    if let Some(sync) = engine.blob_syncs.get(&blob.root) {
        assert!(
            sync.seeders.contains_key(&sender_pk),
            "duplicate arrivals must not cause seeder removal"
        );
    }
}

#[test]
fn receiver_accepts_out_of_order_pieces() {
    // Pieces can arrive in any order over the wire; the receiver must
    // buffer and verify correctly regardless. Exercises the case where
    // the proof-carrying piece arrives BEFORE the earlier pieces
    // whose bytes it ultimately authenticates.
    let blob = TestBlob::new(4, 0);
    let (mut engine, store, sender_pk) = setup_receiver(&blob);

    let mut pieces = pieces_for_chunk(&blob, 0, None);
    // Reverse: last piece (with proof) first.
    pieces.reverse();

    let effects = feed(&mut engine, &store, sender_pk, pieces);

    assert_eq!(
        count_write_chunks(&effects, blob.root),
        1,
        "out-of-order pieces for a valid chunk must still verify"
    );
}
