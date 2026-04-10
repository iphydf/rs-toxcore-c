//! Tests for push-based blob streaming.
//!
//! Verifies that:
//! 1. Seeder begins pushing BlobData after receiving BlobFetch
//! 2. Seeder respects BlobProgress to skip already-received chunks
//! 3. Seeder stops pushing on BlobCancel

use merkle_tox_core::cas::{BlobFetch, BlobInfo, BlobProgress, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{LogicalIdentityPk, NodeHash, PhysicalDevicePk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::InMemoryStore;
use merkle_tox_core::ProtocolMessage;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

fn setup_seeder_with_blob(
    blob_hash: NodeHash,
    num_chunks: u64,
) -> (MerkleToxEngine, InMemoryStore, PhysicalDevicePk) {
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let seeder_pk = PhysicalDevicePk::from([1u8; 32]);
    let mut engine = MerkleToxEngine::new(
        seeder_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();

    // Store full blob with all chunks
    let size = num_chunks * CHUNK_SIZE;
    let info = BlobInfo {
        hash: blob_hash,
        size,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(info).unwrap();
    let conv_id = merkle_tox_core::dag::ConversationId::from([0u8; 32]);
    let chunk_data = vec![0x42u8; CHUNK_SIZE as usize];
    for i in 0..num_chunks {
        store
            .put_chunk(&conv_id, &blob_hash, i * CHUNK_SIZE, &chunk_data, None)
            .unwrap();
    }

    // This test bypasses the DAG (no Content::Blob node), so we must
    // populate the blob → conversation map and seed a session so
    // the BlobFetch authorisation gate lets the receiver through.
    // The shared receiver pk `[2u8; 32]` matches what each test uses.
    let receiver_pk = PhysicalDevicePk::from([2u8; 32]);
    engine.blob_conversations.insert(blob_hash, conv_id);
    seed_session(&mut engine, receiver_pk, conv_id, &store);

    (engine, store, seeder_pk)
}

/// Minimal Handshake-state session so the BlobFetch authorisation
/// gate sees `receiver_pk` as an active participant of `conv_id`.
fn seed_session(
    engine: &mut MerkleToxEngine,
    peer_pk: PhysicalDevicePk,
    conv_id: merkle_tox_core::dag::ConversationId,
    store: &InMemoryStore,
) {
    use merkle_tox_core::engine::conversation::{ConversationData, Established};
    use merkle_tox_core::engine::session::{PeerSession, SyncSession, handshake::Handshake};
    use merkle_tox_core::engine::Conversation;

    let k_conv = merkle_tox_core::dag::KConv::from([0x11u8; 32]);
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

/// After receiving BlobFetch, the engine should create a push stream
/// for the requested blob. The actual BlobData sending is driven by
/// node.poll() which has access to session queue capacity.
#[test]
fn seeder_creates_push_stream_after_fetch_request() {
    let blob_hash = NodeHash::from([0xAAu8; 32]);
    let num_chunks = 8;
    let (mut engine, store, _seeder_pk) = setup_seeder_with_blob(blob_hash, num_chunks);
    let receiver_pk = PhysicalDevicePk::from([2u8; 32]);

    // Receiver sends BlobFetch (no chunks yet)
    engine
        .handle_message(
            receiver_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: blob_hash,
                completed_ranges: None,
            }),
            &store,
            Some(&store),
        )
        .unwrap();

    // The handler should register a push stream for this (blob, peer) pair.
    assert!(
        engine.push_streams.contains_key(&(blob_hash, receiver_pk)),
        "Engine should create a push stream after receiving BlobFetch. \
         The push stream drives BlobData sending via node.poll()."
    );

    let stream = &engine.push_streams[&(blob_hash, receiver_pk)];
    assert_eq!(stream.num_chunks, num_chunks);
}

/// When the receiver sends BlobProgress with an updated mask showing it
/// already has some chunks, the seeder should skip those chunks.
#[test]
fn seeder_skips_chunks_from_progress_update() {
    let blob_hash = NodeHash::from([0xBBu8; 32]);
    let num_chunks = 8;
    let (mut engine, store, _seeder_pk) = setup_seeder_with_blob(blob_hash, num_chunks);
    let receiver_pk = PhysicalDevicePk::from([2u8; 32]);

    // Start push stream
    engine
        .handle_message(
            receiver_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: blob_hash,
                completed_ranges: None,
            }),
            &store,
            Some(&store),
        )
        .unwrap();

    // Receiver reports it already has chunks 0-5 (from swarming)
    engine
        .handle_message(
            receiver_pk,
            ProtocolMessage::BlobProgress(BlobProgress {
                hash: blob_hash,
                completed_ranges: tox_proto::bounded_vec![(
                    tox_proto::Untrusted::new(0),
                    tox_proto::Untrusted::new(5),
                )],
                incomplete_chunks: tox_proto::BoundedVec::new(),
            }),
            &store,
            Some(&store),
        )
        .unwrap();

    // Poll should only push chunks 6 and 7
    let now = Instant::now();
    let effects = engine.poll(now, &store, Some(&store)).unwrap();

    let pushed_offsets: Vec<u64> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::SendPacket(pk, ProtocolMessage::BlobData(data)) = e
                && *pk == receiver_pk
            {
                return Some(*data.offset.expose_unchecked());
            }
            None
        })
        .collect();

    for offset in &pushed_offsets {
        let chunk_idx = offset / CHUNK_SIZE;
        assert!(
            chunk_idx >= 6,
            "Seeder pushed chunk {} but receiver already has it (per BlobProgress). \
             Seeder must skip chunks the receiver reported in BlobProgress.",
            chunk_idx
        );
    }
}

/// BlobCancel stops the push stream — no more BlobData after cancel.
#[test]
fn seeder_stops_pushing_on_cancel() {
    let blob_hash = NodeHash::from([0xCCu8; 32]);
    let num_chunks = 8;
    let (mut engine, store, _seeder_pk) = setup_seeder_with_blob(blob_hash, num_chunks);
    let receiver_pk = PhysicalDevicePk::from([2u8; 32]);

    // Start push stream
    engine
        .handle_message(
            receiver_pk,
            ProtocolMessage::BlobFetch(BlobFetch {
                hash: blob_hash,
                completed_ranges: None,
            }),
            &store,
            Some(&store),
        )
        .unwrap();

    // Cancel
    engine
        .handle_message(
            receiver_pk,
            ProtocolMessage::BlobCancel(blob_hash),
            &store,
            Some(&store),
        )
        .unwrap();

    // Poll should generate no BlobData
    let now = Instant::now();
    let effects = engine.poll(now, &store, Some(&store)).unwrap();

    let blob_data_count = effects
        .iter()
        .filter(|e| matches!(e, Effect::SendPacket(pk, ProtocolMessage::BlobData(_)) if *pk == receiver_pk))
        .count();

    assert_eq!(
        blob_data_count, 0,
        "Seeder should not push BlobData after BlobCancel"
    );
}

/// Regression guard for the per-piece bao-proof bug (commit 0a1c9bd):
/// the streaming-piece BlobData wire format MUST fit in a single
/// `Packet::Data` payload (≤ MAX_TOX_PACKET_SIZE). If a future change
/// adds a field to BlobData (or grows an existing one) and pushes the
/// serialized message past MTU, `send_auto` falls back to FRAGMENT,
/// where any single dropped tail fragment causes a 5-second
/// reassembly-timeout that wedges the entire transfer under load.
///
/// We exercised exactly that pathology earlier: with `data` AND
/// `proof` both populated, every piece became 3-4 fragments, ~99% of
/// fragments timed out, and 1MB transfers couldn't complete in 60s.
/// This test fails loudly the moment that boundary is recrossed.
#[test]
fn streaming_piece_blob_data_fits_in_single_data_packet() {
    use merkle_tox_core::cas::{BlobData, MAX_PIECE_DATA};
    // Mirror of `tox_sequenced::protocol::MAX_TOX_PACKET_SIZE` (1373).
    // Hardcoded here because the test crate intentionally does not
    // depend on tox_sequenced. Update both if MTU changes.
    const MAX_TOX_PACKET_SIZE: usize = 1373;

    // Construct a streaming piece exactly as `node.rs::poll` does:
    // data populated to MAX_PIECE_DATA, proof intentionally empty (the
    // per-piece bao proof was the original culprit — now replaced by
    // chunk-boundary Merkle proofs handled in a separate test).
    let piece = BlobData {
        hash: NodeHash::from([0xAAu8; 32]),
        offset: tox_proto::Untrusted::new(12345),
        data: tox_proto::BoundedBytes::try_from_vec(vec![0xCDu8; MAX_PIECE_DATA]).expect("test fixture under cap"),
        proof: tox_proto::BoundedBytes::new(),
    };
    let msg = ProtocolMessage::BlobData(piece);
    let serialized = tox_proto::serialize(&msg)
        .expect("BlobData should always serialize");
    assert!(
        serialized.len() <= MAX_TOX_PACKET_SIZE,
        "Streaming BlobData wire size {} exceeds MAX_TOX_PACKET_SIZE {} — \
         a future field added to BlobData has pushed it past MTU. This \
         will cause send_auto to fragment every piece, and any dropped \
         tail fragment will silently wedge blob transfers via the 5s \
         reassembly timeout. Either shrink MAX_PIECE_DATA or rethink \
         the wire format.",
        serialized.len(),
        MAX_TOX_PACKET_SIZE,
    );
}

/// Regression guard for the chunk-buffering optimization (commit 02e33e4):
/// the receiver MUST emit exactly ONE `WriteChunk` effect per completed
/// 64KB chunk, NOT one per piece. The previous per-piece behavior caused
/// ~7 file syscalls per piece (read .info, open/seek/write/close blob,
/// tmp+rename .info), dominating the receiver's iterate() time at ~36ms
/// and capping real-Tox throughput at ~7.5 Mbps regardless of cwnd or
/// pacing. The fix buffers pieces in `SwarmSync::partial_chunks` and
/// emits one WriteChunk for the whole 64KB only when all pieces of the
/// chunk have arrived.
///
/// A regression here would still let the blob arrive correctly (the
/// data is the same), so behavioral / e2e tests would NOT catch it —
/// only throughput would silently drop ~2x.
#[test]
fn receiver_emits_one_write_chunk_per_completed_chunk_not_per_piece() {
    use merkle_tox_core::cas::{
        BlobData, BlobInfo, BlobStatus, ChunkMerkleTree, MAX_PIECE_DATA, SwarmSync,
    };

    let chunk_size = CHUNK_SIZE as usize;
    let pieces_per_chunk = chunk_size.div_ceil(MAX_PIECE_DATA);

    // Build a single-chunk blob whose bytes and Merkle root are real,
    // so the receiver's chunk-boundary verification (added in the
    // ChunkMerkleTree commit) can authenticate the chunk against
    // `sync.info.hash`.
    let chunk_bytes: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
    let tree = ChunkMerkleTree::from_chunks([chunk_bytes.as_slice()]);
    let blob_hash = NodeHash::from(tree.root());
    let proof = tree.proof_for(0); // empty for single-chunk tree

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));
    let receiver_pk = PhysicalDevicePk::from([1u8; 32]);
    let sender_pk = PhysicalDevicePk::from([2u8; 32]);
    let mut engine = MerkleToxEngine::new(
        receiver_pk,
        LogicalIdentityPk::from([1u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();

    // Pre-register a SwarmSync for the blob so the BlobData handler
    // has a sync state to look up. We bypass the BlobAvail negotiation
    // because that's not what's under test here.
    let info = BlobInfo {
        hash: blob_hash,
        size: CHUNK_SIZE,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    let mut sync_state = SwarmSync::new_with_offset(info, &receiver_pk);
    // Register the sender as a seeder. The BlobData handler now
    // gates on `sync.has_seeder(sender_pk)` (mirrors the BlobAvail/
    // BlobReq/BlobFetch arms — only registered seeders may push
    // pieces).
    sync_state.add_seeder(sender_pk);
    engine.blob_syncs.insert(blob_hash, sync_state);

    // Feed one piece at a time. Each piece must NOT trigger a
    // WriteChunk on its own — only the LAST piece (the one that
    // completes the chunk) should produce exactly one WriteChunk for
    // the whole 64KB, and only because the chunk verifies against the
    // committed Merkle root.
    let mut total_write_chunks = 0usize;
    let mut last_chunk_bytes: Option<usize> = None;
    for piece_idx in 0..pieces_per_chunk {
        let offset = (piece_idx * MAX_PIECE_DATA) as u64;
        let len = MAX_PIECE_DATA.min(chunk_size - piece_idx * MAX_PIECE_DATA);
        let start = piece_idx * MAX_PIECE_DATA;
        let piece_data = chunk_bytes[start..start + len].to_vec();
        // Attach the (empty) proof to the last piece of the chunk.
        // For a single-chunk blob the proof is empty — the chunk's
        // leaf hash IS the root.
        let piece_proof: Vec<u8> = if piece_idx == pieces_per_chunk - 1 {
            proof.clone()
        } else {
            Vec::new()
        };
        let piece = BlobData {
            hash: blob_hash,
            offset: tox_proto::Untrusted::new(offset),
            data: tox_proto::BoundedBytes::try_from_vec(piece_data).expect("under cap"),
            proof: tox_proto::BoundedBytes::try_from_vec(piece_proof).expect("under cap"),
        };
        let effects = engine
            .handle_message(
                sender_pk,
                ProtocolMessage::BlobData(piece),
                &store,
                Some(&store),
            )
            .unwrap();
        for e in &effects {
            if let Effect::WriteChunk(_, h, _, bytes, _) = e
                && *h == blob_hash
            {
                total_write_chunks += 1;
                last_chunk_bytes = Some(bytes.len());
            }
        }
    }

    assert_eq!(
        total_write_chunks, 1,
        "Expected exactly 1 WriteChunk after all {} pieces of a single \
         chunk arrive, got {}. The receiver must buffer pieces in memory \
         and only flush to disk on chunk completion — emitting WriteChunk \
         per piece causes a file-syscall storm in FsStore::put_chunk that \
         halves real-Tox throughput.",
        pieces_per_chunk,
        total_write_chunks,
    );
    assert_eq!(
        last_chunk_bytes,
        Some(chunk_size),
        "The single WriteChunk must carry the full 64KB chunk, not a piece."
    );
}

/// Regression guard for retransmission amplification (commit addressing
/// task #22). Under loss, scenario 5 showed 5-16x amplification: a 10MB
/// blob was re-sent up to 924 MB because the forward-scanner in
/// `PushStream::next_piece` re-sent ALL 55 pieces of in-progress chunks
/// on every `reset_pass` cycle, even pieces the receiver already had.
///
/// The fix: piece-level skip in the forward scan. When the sender's
/// latest `BlobProgress.incomplete_chunks` shows a piece as received
/// (bit set in the bitmask), `next_piece` advances past it without
/// sending.
///
/// A regression here would silently raise retransmission overhead
/// under loss — goodput still works, but efficiency tanks. Scenario 5
/// scores would bifurcate into 55/83 bimodal as before.
#[test]
fn push_stream_skips_within_chunk_pieces_receiver_already_has() {
    use merkle_tox_core::cas::{BlobProgress, MAX_PIECE_DATA, PushStream};

    // 5-chunk blob. All chunks start un-received.
    let blob_hash = NodeHash::from([0x11u8; 32]);
    let blob_size = 5 * CHUNK_SIZE;
    let mut stream = PushStream::new(blob_hash, blob_size, None, None);

    // Give enough credit to drain the whole blob without pausing —
    // simulating the state after multiple progress cycles have
    // replenished credits. This test focuses on the scanner logic,
    // not credit flow.
    let pieces_per_chunk = (CHUNK_SIZE as usize).div_ceil(MAX_PIECE_DATA);
    stream.credits = 5 * pieces_per_chunk * 10;

    // First pass: drain all pieces via next_piece (simulating a full
    // forward scan). Count them.
    let mut first_pass_pieces = 0usize;
    while let Some(_offset) = stream.next_piece() {
        first_pass_pieces += 1;
    }
    assert!(stream.pass_complete());
    let expected_first_pass = 5 * pieces_per_chunk;
    assert_eq!(
        first_pass_pieces, expected_first_pass,
        "first pass must emit every piece"
    );

    // Simulate a BlobProgress where chunks 0-3 are fully received and
    // chunk 4 has pieces 0..=pieces_per_chunk-3 received (i.e. only
    // the LAST two pieces are still missing). Under the old "whole-
    // chunk rescan" behavior, reset_pass + next_piece would re-send
    // all pieces_per_chunk pieces of chunk 4. With piece-level skip,
    // it must emit only 2 pieces.
    let missing = 2usize;
    let received_in_chunk4 = pieces_per_chunk - missing;
    let mask_len_bytes = pieces_per_chunk.div_ceil(8);
    let mut mask = vec![0u8; mask_len_bytes];
    for i in 0..received_in_chunk4 {
        mask[i / 8] |= 1 << (i % 8);
    }

    let progress = BlobProgress {
        hash: blob_hash,
        completed_ranges: tox_proto::bounded_vec![(
            tox_proto::Untrusted::new(0),
            tox_proto::Untrusted::new(3),
        )],
        incomplete_chunks: tox_proto::bounded_vec![(tox_proto::Untrusted::new(4), mask)],
    };
    stream.on_progress(&progress);

    // Start the next pass. Restore credits so the scanner can emit.
    stream.reset_pass();
    stream.credits = 5 * pieces_per_chunk * 10;

    // Count how many pieces next_piece emits now. Should be exactly
    // `missing` (2) — the two still-needed pieces in chunk 4.
    let mut second_pass_pieces = 0usize;
    while let Some(_offset) = stream.next_piece() {
        second_pass_pieces += 1;
    }

    assert_eq!(
        second_pass_pieces, missing,
        "piece-level skip is broken: forward-scan emitted {} pieces when \
         only {} pieces were actually missing in chunk 4. This causes \
         5-16x retransmission amplification under loss (scenario 5 \
         bimodality). Check PushStream::next_piece skips pieces whose \
         bit is set in prev_incomplete[chunk_idx] during forward scan.",
        second_pass_pieces, missing,
    );
}
