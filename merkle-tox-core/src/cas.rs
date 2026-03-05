use crate::dag::{NodeHash, PhysicalDevicePk};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum BlobStatus {
    Pending,
    Downloading,
    Available,
    Error,
}

/// Metadata for large binary object.
///
/// `hash` is the blob's content-addressed identity: the root of the
/// chunk-Merkle tree over its 64KB chunks (see doc/merkle-tox-cas.md §3).
/// Chunk-boundary integrity is authenticated against this root at receive
/// time via proofs attached to `BlobData` messages.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobInfo {
    pub hash: NodeHash,
    pub size: u64,
    pub status: BlobStatus,
    /// Optional bitmask of received chunks (legacy, kept for storage compat).
    pub received_mask: Option<Vec<u8>>,
    /// Decryption key for blob (K_export from HistoryExport).
    pub decryption_key: Option<[u8; 32]>,
}

/// Request for specific blob chunk (legacy pull-based fallback).
///
/// `offset` and `length` are peer-supplied; the seeder must clamp
/// `length` against `CHUNK_SIZE` (legitimate senders only ever ask
/// for one chunk at a time — see `next_requests`) and `offset`
/// against the blob's known size before passing them to
/// `BlobStore::get_chunk`. The storage layer has its own defensive
/// bounds check, but the handler-level clamp is the primary gate;
/// the type wrap exists so a future refactor cannot drop it.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobReq {
    pub hash: NodeHash,
    pub offset: tox_proto::Untrusted<u64>,
    pub length: tox_proto::Untrusted<u32>,
}

/// Request to start a push-based blob stream.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobFetch {
    pub hash: NodeHash,
    /// Chunk ranges the requester already has. `None` means "no
    /// chunks yet"; an empty list means "fully received" (rare but
    /// valid). Each bound is peer-supplied and must be clamped
    /// against the seeder's own `num_chunks` before it drives any
    /// scheduling decision. The list is structurally bounded at
    /// `MAX_BLOB_PROGRESS_RANGES` at the type level: the deserialiser
    /// rejects oversize wire payloads before any per-range work.
    pub completed_ranges: Option<
        tox_proto::BoundedVec<
            (tox_proto::Untrusted<u64>, tox_proto::Untrusted<u64>),
            MAX_BLOB_PROGRESS_RANGES,
        >,
    >,
}

/// Periodic progress update from receiver during push stream.
///
/// Chunk indices in `completed_ranges` and `incomplete_chunks` are
/// peer-supplied; the seeder must clamp every index against its own
/// `num_chunks` before arithmetic (see `PushStream::on_progress`).
/// Both fields are tagged `Untrusted<u64>` at the type level so that
/// bound cannot be forgotten, and both are length-capped at
/// `MAX_BLOB_PROGRESS_RANGES` so a peer cannot drive O(N × num_chunks)
/// work on the seeder via a single oversize packet. Wire format is
/// unchanged.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobProgress {
    pub hash: NodeHash,
    /// Completed (Bao-verified) chunk ranges: (start_chunk, end_chunk) inclusive.
    pub completed_ranges: tox_proto::BoundedVec<
        (tox_proto::Untrusted<u64>, tox_proto::Untrusted<u64>),
        MAX_BLOB_PROGRESS_RANGES,
    >,
    /// Partially received chunks with piece-level bitmasks.
    pub incomplete_chunks:
        tox_proto::BoundedVec<(tox_proto::Untrusted<u64>, Vec<u8>), MAX_BLOB_PROGRESS_RANGES>,
}

/// Data payload for a single piece (~1300B), sent as a sequenced DATA packet.
///
/// `proof` is attached only to the LAST piece of each 64KB chunk (see §3
/// of `doc/merkle-tox-cas.md`): it's the Merkle path from the chunk's
/// leaf hash to the blob's `chunk_merkle_root`, authenticating the whole
/// 64KB chunk that the receiver has buffered from prior pieces. Most
/// pieces carry an empty proof.
///
/// Both `data` and `proof` are length-capped at the type level so a
/// peer cannot ship per-packet payloads that exceed the legitimate
/// per-piece envelope.  The pre-fix `Vec<u8>` floor (1 MiB) admitted
/// roughly a 1000× amplification over the legitimate sizes.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobData {
    pub hash: NodeHash,
    /// Peer-supplied; must be clamped against `sync.info.size` at the
    /// handler before any arithmetic touches it. Without the clamp
    /// `chunk_idx * CHUNK_SIZE` and `chunk_start + CHUNK_SIZE` both
    /// wrap on huge offsets, and `chunk_end - chunk_start` underflows
    /// when `offset >= info.size` — the wrapped `usize` then drives
    /// `vec![0u8; …]` into an OOM/abort. Single-packet kill from any
    /// peer reachable through the unauthenticated `BlobAvail` join.
    pub offset: tox_proto::Untrusted<u64>,
    pub data: tox_proto::BoundedBytes<MAX_PIECE_DATA>,
    /// Merkle path for the chunk ending at this offset (empty on
    /// non-chunk-boundary pieces). See `ChunkMerkleTree::verify` for the
    /// wire layout.
    pub proof: tox_proto::BoundedBytes<MAX_PROOF_SIZE>,
}

/// Maximum entries in a single `BlobFetch.completed_ranges` /
/// `BlobProgress.completed_ranges` / `BlobProgress.incomplete_chunks`
/// list. Each entry forces a per-element clamp + an inner-loop scan
/// of `[start, end]` against the receiver's `num_chunks`, so an
/// unbounded count is an O(N × num_chunks) DoS amplifier on the
/// seeder. 1024 is well above any legitimate use (a 100 GB blob with
/// pathological chunk fragmentation would still produce <1024 ranges
/// after coalescing) while keeping the worst-case attack at
/// 1024 × num_chunks operations — orders of magnitude below the
/// pre-fix unbounded-Vec ceiling.
pub const MAX_BLOB_PROGRESS_RANGES: usize = 1024;

/// Maximum bytes in a `BlobData.proof` (chunk-Merkle authentication
/// path). At chunk-tree depth 16 (4 GB blobs, the largest blob the
/// per-packet derivation supports) the proof is `16 × 32 = 512` B
/// of siblings + small msgpack framing overhead. 1024 leaves
/// generous headroom for future scheme tweaks while bounding the
/// per-packet allocation at ~1× the legitimate maximum, vs the
/// 1 MiB `MAX_MESSAGE_SIZE` floor a `Vec<u8>` deserialiser admits —
/// roughly a 1000× amplifier per packet that an authenticated peer
/// can drive on every received `BlobData`.
pub const MAX_PROOF_SIZE: usize = 1024;

/// 64KB chunk size — unit of verification and tracking.
pub const CHUNK_SIZE: u64 = 64 * 1024;
/// Maximum piece payload in a single DATA packet on non-chunk-boundary
/// pieces. Budget for the serialized Packet::Data wrapping a BlobData:
///
/// - Packet::Data header (variant tag + seq + msg_type + length): ~10B
/// - ProtocolMessage::BlobData enum tag: ~1B
/// - BlobData fields: 32 (hash) + 8 (offset) + 4 (data len) + 4 (proof len) ≈ 48B
/// - Safety margin: ~40B
///
/// Total fixed overhead ≈ 100B, so any value ≤ ~1250 fits. We use 1200.
///
/// Chunk-boundary pieces (the last piece of each chunk) additionally
/// carry a Merkle proof. Because `CHUNK_SIZE % MAX_PIECE_DATA == 736`,
/// the natural last piece is 736 B of data — leaving ~540 B for the
/// proof and its msgpack length prefix. At 32 B/sibling that budget
/// supports trees up to depth 16 = 2^16 chunks = **4 GiB blobs** in
/// a single datagram.
///
/// Above 4 GiB the chunk-boundary piece overflows into a second
/// transport fragment; correctness is preserved (tox-sequenced
/// transparently reassembles) but the one-chunk-boundary-piece-per-
/// datagram property is lost. `node.rs::poll` holds a
/// `debug_assert!` on this budget so any regression below 4 GiB
/// fires loudly in tests.
pub const MAX_PIECE_DATA: usize = 1200;

/// Empirical budget for `data + proof` combined inside one
/// `ProtocolMessage::BlobData`, before `Packet::Data` and transport
/// framing. Derived from `USABLE_PACKET_MTU` minus fixed per-packet
/// overhead (see `MAX_PIECE_DATA` docs). Enforced via `debug_assert!`
/// in the sender hot path so any code change that pushes a real
/// packet over this budget is caught by the test suite.
pub const MAX_BLOBDATA_PAYLOAD: usize = 1282;
/// Approximate pieces per chunk.
pub const PIECES_PER_CHUNK: usize = (CHUNK_SIZE as usize).div_ceil(MAX_PIECE_DATA);
/// Initial credit window (pieces). 256 pieces × 1200B = ~300KB.
pub const INITIAL_CREDITS: usize = 256;
/// Maximum credit window (pieces). 4096 pieces × 1200B = ~4.8MB.
pub const MAX_CREDITS: usize = 4096;
/// Interval between BLOB_PROGRESS messages.
/// Spec says "at least once per second", but we send more frequently
/// during active transfers to keep the credit window flowing.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// State for an active push stream (seeder side).
///
/// Tracks piece-level credit window and sends pieces chunk-sequentially.
/// Each piece is a single ~1300B DATA packet.
pub struct PushStream {
    pub blob_hash: NodeHash,
    pub blob_size: u64,
    pub num_chunks: u64,
    /// Piece-level credit window.
    pub credits: usize,
    pub max_credits: usize,
    /// Next piece offset to push (byte offset into blob).
    pub next_piece_offset: u64,
    /// Chunk ranges the receiver has completed (from BlobProgress).
    receiver_completed: Vec<(u64, u64)>,
    /// Previous incomplete_chunks state for retransmission detection.
    prev_incomplete: HashMap<u64, Vec<u8>>,
    /// Pieces that need retransmission, popped by `next_piece`. Kept
    /// in a FIFO-draining Vec and mirrored in `retransmit_pending` for
    /// O(1) dedup — so a piece that stays missing across many
    /// BlobProgress cycles cannot pile up duplicate entries (the
    /// pre-fix behaviour produced 10x+ amplification under 5% loss).
    retransmit_queue: Vec<u64>,
    /// Offsets currently present in `retransmit_queue`. Dedup only:
    /// pushing an offset already in this set is a no-op, and popping
    /// from the queue removes from the set.
    retransmit_pending: HashSet<u64>,
    /// Whether we've completed one full pass through the blob.
    pass_complete: bool,
    /// Chunk-boundary Merkle tree for this blob. Lazily computed the
    /// first time a proof is requested (see `proof_for_chunk`). Built
    /// once per stream and cached for the stream's lifetime.
    pub tree: Option<ChunkMerkleTree>,
}

impl PushStream {
    pub fn new(
        blob_hash: NodeHash,
        blob_size: u64,
        receiver_completed: Option<Vec<(u64, u64)>>,
        tree: Option<ChunkMerkleTree>,
    ) -> Self {
        let num_chunks = blob_size.div_ceil(CHUNK_SIZE);
        Self {
            blob_hash,
            blob_size,
            num_chunks,
            credits: INITIAL_CREDITS,
            max_credits: INITIAL_CREDITS,
            next_piece_offset: 0,
            receiver_completed: receiver_completed.unwrap_or_default(),
            prev_incomplete: HashMap::new(),
            retransmit_queue: Vec::new(),
            retransmit_pending: HashSet::new(),
            pass_complete: false,
            tree,
        }
    }

    /// Check if the receiver has completed a given chunk.
    fn receiver_has_chunk(&self, chunk_idx: u64) -> bool {
        self.receiver_completed
            .iter()
            .any(|&(start, end)| chunk_idx >= start && chunk_idx <= end)
    }

    /// Get the next piece offset to push, or None if credits exhausted or pass complete.
    pub fn next_piece(&mut self) -> Option<u64> {
        // 1. Check retransmit queue first (retransmissions don't consume credits)
        if let Some(offset) = self.retransmit_queue.pop() {
            self.retransmit_pending.remove(&offset);
            return Some(offset);
        }

        // 2. Check credits
        if self.credits == 0 {
            return None;
        }

        // 3. Find next unsent piece, skipping:
        //    - whole chunks the receiver has fully completed
        //      (`receiver_completed` ranges)
        //    - individual pieces within in-progress chunks that the
        //      receiver reported as received in the most recent
        //      BlobProgress (`prev_incomplete` piece bitmasks)
        //
        // The piece-level skip is essential under loss. Without it,
        // reset_pass + forward-scan re-sends ALL ~55 pieces of any
        // chunk that's missing even a single piece — producing 5-16x
        // retransmission amplification at 5% loss (scenario 5
        // bimodality, task #22).
        //
        // Pieces are aligned to chunk boundaries: a piece never spans
        // two chunks.
        loop {
            if self.next_piece_offset >= self.blob_size {
                self.pass_complete = true;
                return None;
            }

            let chunk_idx = self.next_piece_offset / CHUNK_SIZE;
            if self.receiver_has_chunk(chunk_idx) {
                // Skip entire chunk
                self.next_piece_offset = (chunk_idx + 1) * CHUNK_SIZE;
                continue;
            }

            let offset = self.next_piece_offset;
            // Clamp piece to not cross chunk boundary
            let chunk_end = ((chunk_idx + 1) * CHUNK_SIZE).min(self.blob_size);
            let remaining_in_chunk = (chunk_end - offset) as usize;
            let piece_size = MAX_PIECE_DATA.min(remaining_in_chunk);

            // Piece-level skip: if the receiver's latest BlobProgress
            // reported this piece as received (bit set in the chunk's
            // piece bitmask), advance past it without sending. The
            // mask may be slightly stale (up to one progress interval,
            // ~100ms), but sending a piece the receiver already has is
            // the waste we're trying to avoid — stale info here only
            // means we occasionally fail to skip a piece we could
            // have, never that we skip one we shouldn't.
            let chunk_start = chunk_idx * CHUNK_SIZE;
            let piece_idx_in_chunk = ((offset - chunk_start) / MAX_PIECE_DATA as u64) as usize;
            let skip = self.prev_incomplete.get(&chunk_idx).is_some_and(|mask| {
                let byte_idx = piece_idx_in_chunk / 8;
                let bit_idx = piece_idx_in_chunk % 8;
                byte_idx < mask.len() && (mask[byte_idx] & (1 << bit_idx)) != 0
            });
            self.next_piece_offset = offset + piece_size as u64;
            if skip {
                continue;
            }
            self.credits -= 1;
            return Some(offset);
        }
    }

    /// Process incoming BlobProgress: replenish credits and detect retransmissions.
    pub fn on_progress(&mut self, progress: &BlobProgress) {
        // Peer-supplied chunk indices are tagged `Untrusted<u64>` on
        // the wire. Anything outside `[0, num_chunks)` is meaningless
        // for this blob — and if trusted, explodes: `(0, u64::MAX)`
        // in a `completed_ranges` pair runs the inner loop 2^64
        // times, and a `chunk_idx` past `num_chunks` in
        // `incomplete_chunks` underflows `chunk_end -
        // chunk_start_offset`. Build a pre-clamped local view of
        // both lists and use the clamped values throughout.
        let clamped_ranges: Vec<(u64, u64)> = progress
            .completed_ranges
            .iter()
            .filter_map(|&(start, end)| {
                let start = start.checked_in(0, self.num_chunks)?;
                let end = end.clamp_max(self.num_chunks.saturating_sub(1));
                if end >= start {
                    Some((start, end))
                } else {
                    None
                }
            })
            .collect();
        let clamped_incomplete: Vec<(u64, &Vec<u8>)> = progress
            .incomplete_chunks
            .iter()
            .filter_map(|(chunk_idx, mask)| {
                chunk_idx.checked_in(0, self.num_chunks).map(|c| (c, mask))
            })
            .collect();

        // Count newly confirmed pieces from completed_ranges
        let mut newly_confirmed = 0u64;
        for &(start_chunk, end_chunk) in &clamped_ranges {
            for chunk_idx in start_chunk..=end_chunk {
                if !self.receiver_has_chunk(chunk_idx) {
                    // This chunk is newly completed
                    let pieces_in_chunk = if chunk_idx == self.num_chunks - 1 {
                        let remaining = self.blob_size - chunk_idx * CHUNK_SIZE;
                        remaining.div_ceil(MAX_PIECE_DATA as u64)
                    } else {
                        PIECES_PER_CHUNK as u64
                    };
                    newly_confirmed += pieces_in_chunk;
                }
            }
        }

        // Count newly confirmed pieces from incomplete_chunks
        for &(chunk_idx, piece_mask) in &clamped_incomplete {
            if let Some(prev_mask) = self.prev_incomplete.get(&chunk_idx) {
                // Count bits that changed from 0 to 1
                for (&new_byte, &old_byte) in piece_mask.iter().zip(prev_mask.iter()) {
                    let new_bits = new_byte & !old_byte;
                    newly_confirmed += new_bits.count_ones() as u64;
                }
                // Handle case where new mask is longer
                if piece_mask.len() > prev_mask.len() {
                    for byte in &piece_mask[prev_mask.len()..] {
                        newly_confirmed += byte.count_ones() as u64;
                    }
                }
            } else {
                // First time seeing this chunk — all set bits are new
                for byte in piece_mask.iter() {
                    newly_confirmed += byte.count_ones() as u64;
                }
            }

            // Check for pieces missing across 2 consecutive progress messages
            if let Some(prev_mask) = self.prev_incomplete.get(&chunk_idx) {
                let chunk_start_offset = chunk_idx * CHUNK_SIZE;
                let chunk_end = (chunk_start_offset + CHUNK_SIZE).min(self.blob_size);
                let total_pieces_in_chunk =
                    (chunk_end - chunk_start_offset).div_ceil(MAX_PIECE_DATA as u64);

                for piece_idx in 0..total_pieces_in_chunk as usize {
                    let byte_idx = piece_idx / 8;
                    let bit_idx = piece_idx % 8;
                    let prev_has =
                        byte_idx < prev_mask.len() && (prev_mask[byte_idx] & (1 << bit_idx)) != 0;
                    let curr_has =
                        byte_idx < piece_mask.len() && (piece_mask[byte_idx] & (1 << bit_idx)) != 0;
                    if !prev_has && !curr_has {
                        // Missing across 2 consecutive — retransmit,
                        // but only if the piece isn't already queued
                        // from a previous progress cycle. Without
                        // this dedup, a piece missing across N
                        // cycles would be queued N-1 times.
                        let offset = chunk_start_offset + piece_idx as u64 * MAX_PIECE_DATA as u64;
                        if offset < self.blob_size && self.retransmit_pending.insert(offset) {
                            self.retransmit_queue.push(offset);
                        }
                    }
                }
            }
        }

        // Update state from the pre-clamped views so no peer-supplied
        // `chunk_idx` ever reaches the internal, trusted fields.
        self.receiver_completed = clamped_ranges;
        self.prev_incomplete.clear();
        for &(chunk_idx, mask) in &clamped_incomplete {
            self.prev_incomplete.insert(chunk_idx, mask.clone());
        }

        // Replenish credits
        let confirmed = newly_confirmed as usize;
        self.credits = (self.credits + confirmed).min(self.max_credits);

        // Multiplicative increase of max_credits (doubles per round until MAX)
        self.max_credits = (self.max_credits + self.max_credits / 2 + confirmed).min(MAX_CREDITS);
    }

    /// Current depth of the retransmit queue. Observability only — used
    /// by tests and diagnostics to detect retransmit pile-ups when
    /// pieces remain missing across many BlobProgress cycles.
    pub fn retransmit_queue_len(&self) -> usize {
        self.retransmit_queue.len()
    }

    /// Read-only view of chunk ranges the receiver has reported as
    /// already-owned. Observability only — used by tests to assert
    /// that peer-supplied `completed_ranges` were clamped against
    /// the blob's `num_chunks` at the handler boundary.
    pub fn receiver_ranges(&self) -> &[(u64, u64)] {
        &self.receiver_completed
    }

    /// Check if the push stream has completed one full pass.
    pub fn pass_complete(&self) -> bool {
        self.pass_complete
    }

    /// Reset for another pass.
    pub fn reset_pass(&mut self) {
        self.next_piece_offset = 0;
        self.pass_complete = false;
    }

    /// Check if all chunks are either completed or past the last piece.
    pub fn all_done(&self) -> bool {
        for i in 0..self.num_chunks {
            if !self.receiver_has_chunk(i) {
                return false;
            }
        }
        true
    }
}

pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_REQUESTS_PER_SEEDER: usize = 16;
pub const MAX_REQUESTS_PER_POLL: usize = 32;

/// Tracks received blob pieces, organized by chunks.
pub struct ChunkTracker {
    pub hash: NodeHash,
    pub total_size: u64,
    pub num_chunks: u64,
    /// Completed (Bao-verified) chunks stored as ranges.
    pub completed_ranges: Vec<(u64, u64)>,
    /// Per-chunk piece bitmasks for chunks currently being received.
    /// BTreeMap so BlobProgress.incomplete_chunks (wire-visible) is sent
    /// in deterministic order.
    pub incomplete_chunks: BTreeMap<u64, Vec<u8>>,
}

impl ChunkTracker {
    pub fn new(hash: NodeHash, total_size: u64) -> Self {
        let num_chunks = total_size.div_ceil(CHUNK_SIZE);
        Self {
            hash,
            total_size,
            num_chunks,
            completed_ranges: Vec::new(),
            incomplete_chunks: BTreeMap::new(),
        }
    }

    /// Record receipt of a piece at the given byte offset.
    pub fn mark_piece_received(&mut self, offset: u64, data_len: usize) {
        let chunk_idx = offset / CHUNK_SIZE;
        let chunk_start = chunk_idx * CHUNK_SIZE;
        let chunk_end = (chunk_start + CHUNK_SIZE).min(self.total_size);
        let chunk_size = (chunk_end - chunk_start) as usize;

        // If this covers the whole chunk (legacy 64KB BlobReq path), mark complete
        if offset == chunk_start && data_len >= chunk_size {
            self.incomplete_chunks.remove(&chunk_idx);
            self.add_completed_chunk(chunk_idx);
            return;
        }

        let piece_idx = ((offset - chunk_start) / MAX_PIECE_DATA as u64) as usize;

        // Skip if chunk already completed
        if self.is_chunk_complete(chunk_idx) {
            return;
        }

        let chunk_start = chunk_idx * CHUNK_SIZE;
        let chunk_end = (chunk_start + CHUNK_SIZE).min(self.total_size);
        let pieces = (chunk_end - chunk_start).div_ceil(MAX_PIECE_DATA as u64) as usize;
        let mask = self
            .incomplete_chunks
            .entry(chunk_idx)
            .or_insert_with(|| vec![0u8; pieces.div_ceil(8)]);

        let byte_idx = piece_idx / 8;
        let bit_idx = piece_idx % 8;
        if byte_idx < mask.len() {
            mask[byte_idx] |= 1 << bit_idx;
        }

        // Check if chunk is now complete
        if self.is_chunk_pieces_complete(chunk_idx) {
            self.incomplete_chunks.remove(&chunk_idx);
            self.add_completed_chunk(chunk_idx);
        }
    }

    /// Number of pieces in a given chunk.
    pub fn pieces_in_chunk(&self, chunk_idx: u64) -> usize {
        let chunk_start = chunk_idx * CHUNK_SIZE;
        let chunk_end = (chunk_start + CHUNK_SIZE).min(self.total_size);
        (chunk_end - chunk_start).div_ceil(MAX_PIECE_DATA as u64) as usize
    }

    /// Check if all pieces in a chunk have been received.
    fn is_chunk_pieces_complete(&self, chunk_idx: u64) -> bool {
        let total_pieces = self.pieces_in_chunk(chunk_idx);
        let Some(mask) = self.incomplete_chunks.get(&chunk_idx) else {
            return false;
        };
        for i in 0..total_pieces {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if byte_idx >= mask.len() || (mask[byte_idx] & (1 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }

    fn is_chunk_complete(&self, chunk_idx: u64) -> bool {
        self.completed_ranges
            .iter()
            .any(|&(start, end)| chunk_idx >= start && chunk_idx <= end)
    }

    /// Add a completed chunk and merge adjacent ranges.
    fn add_completed_chunk(&mut self, chunk_idx: u64) {
        self.completed_ranges.push((chunk_idx, chunk_idx));
        self.merge_ranges();
    }

    fn merge_ranges(&mut self) {
        if self.completed_ranges.len() <= 1 {
            return;
        }
        self.completed_ranges.sort_unstable();
        let mut merged = vec![self.completed_ranges[0]];
        for &(start, end) in &self.completed_ranges[1..] {
            let last = merged.last_mut().unwrap();
            if start <= last.1 + 1 {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.completed_ranges = merged;
    }

    /// Check if all chunks are complete.
    pub fn is_complete(&self) -> bool {
        if self.num_chunks == 0 {
            return true;
        }
        self.completed_ranges.len() == 1
            && self.completed_ranges[0].0 == 0
            && self.completed_ranges[0].1 >= self.num_chunks - 1
    }

    /// Legacy compatibility: mark a whole chunk as received (for old BlobData handler).
    pub fn mark_received(&mut self, chunk_idx: u64) {
        if !self.is_chunk_complete(chunk_idx) {
            self.add_completed_chunk(chunk_idx);
        }
    }

    /// Legacy compatibility: check if chunk is received.
    pub fn is_received(&self, chunk_idx: u64) -> bool {
        self.is_chunk_complete(chunk_idx)
    }

    /// Find the next missing (incomplete) chunk starting from hint.
    pub fn next_missing(&self, hint: u64) -> Option<u64> {
        (hint..self.num_chunks)
            .find(|&i| !self.is_chunk_complete(i))
            .or_else(|| (0..hint).find(|&i| !self.is_chunk_complete(i)))
    }
}

/// Manages synchronization of blob from multiple peers.
pub struct SwarmSync {
    pub info: BlobInfo,
    pub tracker: ChunkTracker,
    /// Peers and their chunk availability. `None` = full seeder (has all chunks).
    /// BTreeMap for deterministic iteration order (BlobFetch / BlobProgress
    /// dispatch order is observable on the wire).
    pub seeders: BTreeMap<PhysicalDevicePk, Option<Vec<(u64, u64)>>>,
    /// Chunks currently being fetched: chunk_index to (peer_pk, start_time)
    pub active_fetches: HashMap<u64, (PhysicalDevicePk, Instant)>,
    /// Last time we sent a re-advertisement (for 1/sec throttling).
    pub last_readvertise: Option<Instant>,
    /// Random offset for chunk request ordering.
    pub chunk_offset: u64,
    /// Seeders to which we've sent BlobFetch, and the wallclock at which
    /// the most recent BlobFetch was sent. BTreeMap for deterministic
    /// iteration order. Used to retry BlobFetch when no pieces have
    /// arrived from a peer: if our latest fetch was dropped in flight
    /// (a 1% loss scenario hits this on a typical ab_compare run), a
    /// single-shot send leaves the receiver waiting forever. Poll logic
    /// resends periodically until `tracker` starts showing progress.
    pub fetch_sent: BTreeMap<PhysicalDevicePk, Instant>,
    /// Last time we sent BlobProgress to active seeders.
    pub last_progress: Option<Instant>,
    /// In-progress chunk buffers for the piece-level streaming path. Each
    /// entry holds the assembled bytes of one 64KB chunk while its pieces
    /// are still arriving. When all pieces of a chunk have been received,
    /// the buffer is moved out as a single `WriteChunk` effect — avoiding
    /// the per-piece file I/O syscall storm that otherwise dominated the
    /// receiver's iterate() time. BTreeMap for deterministic iteration.
    pub partial_chunks: BTreeMap<u64, Vec<u8>>,
    /// Merkle proofs received for chunks, keyed by chunk index. The
    /// sender attaches a proof to the last piece of each chunk; pieces
    /// can arrive in any order, so we buffer proofs as they come in and
    /// apply them at chunk-completion time. A chunk that completes
    /// without ever receiving a proof is rejected — the receiver must
    /// not silently treat "no proof" as "verified". BTreeMap for
    /// deterministic iteration.
    pub pending_proofs: BTreeMap<u64, Vec<u8>>,
}

/// Minimum interval between proactive re-advertisements to the same peer set.
pub const READVERTISE_INTERVAL: Duration = Duration::from_secs(1);

impl SwarmSync {
    pub fn new_with_offset(info: BlobInfo, self_pk: &PhysicalDevicePk) -> Self {
        let num_chunks = info.size.div_ceil(CHUNK_SIZE);
        let chunk_offset = if num_chunks > 1 {
            let h = info.hash.as_bytes();
            let p = self_pk.as_bytes();
            let mixed = u64::from_le_bytes([
                h[0] ^ p[0],
                h[1] ^ p[1],
                h[2] ^ p[2],
                h[3] ^ p[3],
                h[4] ^ p[4],
                h[5] ^ p[5],
                h[6] ^ p[6],
                h[7] ^ p[7],
            ]);
            mixed % num_chunks
        } else {
            0
        };
        let tracker = ChunkTracker::new(info.hash, info.size);
        Self {
            info,
            tracker,
            seeders: BTreeMap::new(),
            active_fetches: HashMap::new(),
            last_readvertise: None,
            chunk_offset,
            fetch_sent: BTreeMap::new(),
            last_progress: None,
            partial_chunks: BTreeMap::new(),
            pending_proofs: BTreeMap::new(),
        }
    }

    pub fn new(info: BlobInfo) -> Self {
        let tracker = ChunkTracker::new(info.hash, info.size);
        Self {
            info,
            tracker,
            seeders: BTreeMap::new(),
            active_fetches: HashMap::new(),
            last_readvertise: None,
            chunk_offset: 0,
            fetch_sent: BTreeMap::new(),
            last_progress: None,
            partial_chunks: BTreeMap::new(),
            pending_proofs: BTreeMap::new(),
        }
    }

    /// Add a full seeder (has all chunks).
    pub fn add_seeder(&mut self, peer: PhysicalDevicePk) {
        self.seeders.insert(peer, None);
    }

    /// Add a partial seeder with completed chunk ranges.
    pub fn add_partial_seeder(&mut self, peer: PhysicalDevicePk, ranges: Vec<(u64, u64)>) {
        self.seeders.insert(peer, Some(ranges));
    }

    /// Check if a peer is registered as a seeder.
    pub fn has_seeder(&self, peer: &PhysicalDevicePk) -> bool {
        self.seeders.contains_key(peer)
    }

    /// Check if a seeder has a specific chunk.
    pub fn seeder_has_chunk(&self, peer: &PhysicalDevicePk, chunk_idx: u64) -> bool {
        match self.seeders.get(peer) {
            Some(None) => true,
            Some(Some(ranges)) => ranges
                .iter()
                .any(|&(start, end)| chunk_idx >= start && chunk_idx <= end),
            None => false,
        }
    }

    pub fn remove_seeder(&mut self, peer: &PhysicalDevicePk) {
        self.seeders.remove(peer);
        self.active_fetches.retain(|_, (p, _)| p != peer);
        // Also drop any in-flight per-chunk receive buffers if this
        // was our last seeder. Without this, a misbehaving peer
        // (proof-verify failure → `remove_seeder`) leaves any
        // partially-buffered chunks resident until the sync
        // finishes — which it never will if there's no other
        // seeder. Defense-in-depth complement to the
        // `MAX_BLOB_SIZE` clamp at the `BlobAvail` handler:
        // upstream gates the *ceiling*, this gates the *retention*.
        if self.seeders.is_empty() {
            self.partial_chunks.clear();
            self.pending_proofs.clear();
        }
    }

    pub fn clear_stalled_fetches(&mut self, now: Instant) {
        let timeout = if self.seeders.len() > 1 {
            Duration::from_secs(3)
        } else {
            FETCH_TIMEOUT
        };
        self.active_fetches
            .retain(|_, (_, start)| now.saturating_duration_since(*start) < timeout);
    }

    /// Selects next chunk requests for available seeders (legacy pull-based fallback).
    pub fn next_requests(
        &mut self,
        max_total_requests: usize,
        now: Instant,
    ) -> Vec<(PhysicalDevicePk, BlobReq)> {
        let mut reqs = Vec::new();
        let mut hint = self.chunk_offset;
        let mut in_flight_per_peer: HashMap<PhysicalDevicePk, usize> = HashMap::new();
        for (peer, _) in self.active_fetches.values() {
            *in_flight_per_peer.entry(*peer).or_default() += 1;
        }

        let num_chunks = self.info.size.div_ceil(CHUNK_SIZE);

        for _ in 0..num_chunks {
            if reqs.len() >= max_total_requests {
                break;
            }
            let chunk_idx = if hint < num_chunks {
                hint
            } else {
                break;
            };

            if !self.tracker.is_received(chunk_idx) && !self.active_fetches.contains_key(&chunk_idx)
            {
                let seeder = self
                    .seeders
                    .iter()
                    .filter(|(p, _)| {
                        in_flight_per_peer.get(*p).copied().unwrap_or(0) < MAX_REQUESTS_PER_SEEDER
                    })
                    // Suppress legacy BlobReq for any seeder we've already sent a
                    // BlobFetch handshake to: those peers will stream via PushStream
                    // (~1300B pieces). Mixing in 64KB BlobReq responses re-introduces
                    // fragmentation and 5s reassembly timeouts that wedge transfers.
                    .filter(|(p, _)| !self.fetch_sent.contains_key(*p))
                    .filter(|(p, _)| self.seeder_has_chunk(p, chunk_idx))
                    .min_by_key(|(p, _)| (in_flight_per_peer.get(*p).copied().unwrap_or(0), *p))
                    .map(|(p, _)| *p);

                if let Some(seeder) = seeder {
                    reqs.push((
                        seeder,
                        BlobReq {
                            hash: self.info.hash,
                            offset: tox_proto::Untrusted::new(chunk_idx * CHUNK_SIZE),
                            length: tox_proto::Untrusted::new(CHUNK_SIZE as u32),
                        },
                    ));
                    self.active_fetches.insert(chunk_idx, (seeder, now));
                    *in_flight_per_peer.entry(seeder).or_default() += 1;
                }
            }
            hint += 1;
        }
        reqs
    }

    /// Mark a chunk as received, by chunk index. Advances the completion
    /// tracker and clears any in-flight fetch for this chunk. Verification
    /// is handled by the engine handler at chunk-completion time against
    /// the BlobInfo chunk-Merkle root; see `ChunkMerkleTree` and Task #15.
    ///
    /// Takes a `u64` chunk index rather than a `BlobData` so peer-supplied
    /// `data.offset` cannot reach this function un-clamped — the caller
    /// must compute `chunk_idx = clamped_offset / CHUNK_SIZE` itself, where
    /// they have the surrounding `info.size` for the clamp.
    pub fn mark_chunk_received(&mut self, chunk_idx: u64) {
        self.active_fetches.remove(&chunk_idx);
        self.tracker.mark_received(chunk_idx);
    }

    /// Returns next scheduled wakeup time for swarm sync.
    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut next = now + Duration::from_secs(3600);
        for (_, start) in self.active_fetches.values() {
            next = next.min(*start + FETCH_TIMEOUT);
        }
        let has_available_seeder = self
            .seeders
            .keys()
            .any(|p| in_flight_per_peer_count(&self.active_fetches, p) < MAX_REQUESTS_PER_SEEDER);
        if has_available_seeder {
            for chunk_idx in 0..self.tracker.num_chunks {
                if !self.tracker.is_received(chunk_idx)
                    && !self.active_fetches.contains_key(&chunk_idx)
                {
                    return now;
                }
            }
        }
        next
    }
}

fn in_flight_per_peer_count(
    active_fetches: &HashMap<u64, (PhysicalDevicePk, Instant)>,
    peer: &PhysicalDevicePk,
) -> usize {
    active_fetches.values().filter(|(p, _)| p == peer).count()
}

// =============================================================================
// Chunk Merkle Tree
// =============================================================================
//
// Spec: doc/merkle-tox-cas.md §3. A flat binary Merkle tree over 64KB chunk
// hashes, used to authenticate individual chunks against a blob-level root
// commitment that's written into the blob's content node (trusted via the
// DAG, not via the untrusted seeder).
//
// Design choices:
//
// - **Domain-separated blake3 hashing** (0x00 prefix for leaves, 0x01 for
//   internal nodes) to prevent second-preimage attacks that try to pass
//   off an internal node hash as a leaf or vice versa.
//
// - **Duplicate unpaired nodes** at each level rather than pad-to-power-of-2.
//   Matches Bitcoin's Merkle tree convention; simple and deterministic.
//   Safe against CVE-2012-2459 style attacks because the root is committed
//   to in the DAG with a fixed leaf count, so attackers cannot manipulate
//   the tree shape.
//
// - **Proof format**: concatenated sibling hashes from leaf level up to
//   root, `depth * 32` bytes. The receiver uses the leaf index to
//   reconstruct left/right orientation at each level, so no orientation
//   bitmap is transmitted. For a 10MB blob (160 chunks), depth = 8 and
//   proof = 256 bytes; for a 10GB blob (~160K chunks), depth = 18 and
//   proof = 576 bytes. Fits in the ~1350B MTU with room for payload.

/// Domain separation prefix for leaf hashes. All leaves in the chunk
/// Merkle tree are `blake3(CHUNK_LEAF_DOMAIN || chunk_bytes)`.
const CHUNK_LEAF_DOMAIN: u8 = 0x00;

/// Domain separation prefix for internal nodes. All internal nodes are
/// `blake3(CHUNK_INTERNAL_DOMAIN || left_hash || right_hash)`.
const CHUNK_INTERNAL_DOMAIN: u8 = 0x01;

/// Binary Merkle tree over 64KB chunk hashes. Built once at blob
/// finalization time; the sender uses it to produce proofs for the last
/// piece of each chunk, and the receiver verifies each assembled chunk
/// against a proof before accepting it.
#[derive(Debug, Clone)]
pub struct ChunkMerkleTree {
    /// Bottom-up levels. `levels[0]` is the leaves, `levels[last]` is a
    /// single-element `[root]`. Intermediate levels may have odd length;
    /// the unpaired last node is duplicated when computing the next
    /// level up.
    levels: Vec<Vec<[u8; 32]>>,
}

impl ChunkMerkleTree {
    /// Compute the leaf hash for a 64KB chunk (domain-separated blake3).
    pub fn leaf_hash(chunk_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[CHUNK_LEAF_DOMAIN]);
        hasher.update(chunk_bytes);
        *hasher.finalize().as_bytes()
    }

    /// Compute the internal node hash combining two child hashes.
    /// Public so integration tests can assert that leaf and internal
    /// hashes are domain-separated (cannot collide).
    pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[CHUNK_INTERNAL_DOMAIN]);
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    /// Build a tree from pre-computed leaf hashes. The empty-input case
    /// produces a tree whose root is a fixed sentinel leaf hash over the
    /// empty chunk, so callers never have to special-case zero-chunk
    /// blobs.
    pub fn from_leaf_hashes(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            // Sentinel: hash of the empty chunk, for zero-length blobs.
            let root = Self::leaf_hash(&[]);
            return Self {
                levels: vec![vec![root]],
            };
        }

        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next: Vec<[u8; 32]> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    // Unpaired tail: duplicate.
                    &current[i]
                };
                next.push(Self::internal_hash(left, right));
                i += 2;
            }
            levels.push(next);
        }
        Self { levels }
    }

    /// Convenience: build from raw 64KB chunk bytes.
    pub fn from_chunks<'a, I>(chunks: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let leaves: Vec<[u8; 32]> = chunks.into_iter().map(Self::leaf_hash).collect();
        Self::from_leaf_hashes(&leaves)
    }

    /// Build from a `BlobStore` by reading each 64KB chunk once. Returns
    /// `None` if any chunk read fails. Callers should use this at stream
    /// creation time so the flush hot path never issues synchronous disk
    /// I/O to resolve a proof.
    pub fn from_store(
        store: &dyn crate::sync::BlobStore,
        blob_hash: NodeHash,
        blob_size: u64,
    ) -> Option<Self> {
        let num_chunks = blob_size.div_ceil(CHUNK_SIZE);
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_chunks as usize);
        for i in 0..num_chunks {
            let c_start = i * CHUNK_SIZE;
            let c_end = (c_start + CHUNK_SIZE).min(blob_size);
            let c_len = (c_end - c_start) as u32;
            match store.get_chunk(&blob_hash, c_start, c_len) {
                Ok(bytes) => leaves.push(Self::leaf_hash(&bytes)),
                Err(_) => return None,
            }
        }
        Some(Self::from_leaf_hashes(&leaves))
    }

    /// The root hash at the top of the tree. Committed to in the blob's
    /// content node so the receiver has a trusted value to verify against.
    pub fn root(&self) -> [u8; 32] {
        *self.levels.last().unwrap().first().unwrap()
    }

    /// Produce a proof for the leaf at `leaf_idx`. Format: concatenated
    /// 32-byte sibling hashes from leaf level to (but not including) root,
    /// `depth * 32` bytes total. Returns an empty vector for a
    /// single-leaf tree (no sibling needed).
    pub fn proof_for(&self, leaf_idx: usize) -> Vec<u8> {
        let num_leaves = self.levels[0].len();
        if num_leaves == 0 || num_leaves == 1 {
            return Vec::new();
        }
        assert!(
            leaf_idx < num_leaves,
            "leaf_idx {} out of range for {} leaves",
            leaf_idx,
            num_leaves
        );

        let mut proof = Vec::new();
        let mut idx = leaf_idx;
        for level in &self.levels[..self.levels.len() - 1] {
            // Sibling at this level: left ^ 1 flips to right and vice
            // versa. If that position is out of range (unpaired tail),
            // the sibling is ourselves (duplicated during tree build).
            let sibling_idx = idx ^ 1;
            let sibling = if sibling_idx < level.len() {
                &level[sibling_idx]
            } else {
                &level[idx]
            };
            proof.extend_from_slice(sibling);
            idx /= 2;
        }
        proof
    }

    /// Verify a chunk's leaf hash + proof against an expected root.
    /// `leaf_idx` must match the chunk index the proof was produced for;
    /// `proof` must be `depth * 32` bytes. Any mismatch — wrong leaf,
    /// wrong index, tampered proof — yields `false`.
    pub fn verify(
        leaf_hash: [u8; 32],
        leaf_idx: usize,
        num_leaves: usize,
        proof: &[u8],
        expected_root: &[u8; 32],
    ) -> bool {
        // Single-leaf tree: proof must be empty and leaf_hash is the root.
        if num_leaves <= 1 {
            return proof.is_empty() && leaf_hash == *expected_root;
        }
        if leaf_idx >= num_leaves {
            return false;
        }
        // Depth must match: ceil(log2(num_leaves)).
        let expected_depth = (num_leaves - 1)
            .checked_ilog2()
            .map(|l| (l + 1) as usize)
            .unwrap_or(0);
        if proof.len() != expected_depth * 32 {
            return false;
        }

        let mut current = leaf_hash;
        let mut idx = leaf_idx;
        let mut level_size = num_leaves;
        for level_step in 0..expected_depth {
            let sibling_bytes = &proof[level_step * 32..(level_step + 1) * 32];
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(sibling_bytes);

            // At this level, if idx is even we're the left child; if
            // odd we're the right. Exception: if idx is the unpaired
            // last node (idx == level_size - 1 AND level_size is odd),
            // the sibling was duplicated so it equals current, and we
            // act as the left child of the duplicated pair.
            let unpaired_tail = idx == level_size - 1 && !level_size.is_multiple_of(2);
            let is_left = idx.is_multiple_of(2) || unpaired_tail;
            if unpaired_tail && sibling != current {
                // Attacker tried to inject a different sibling into the
                // duplicated slot.
                return false;
            }
            current = if is_left {
                Self::internal_hash(&current, &sibling)
            } else {
                Self::internal_hash(&sibling, &current)
            };
            idx /= 2;
            level_size = level_size.div_ceil(2);
        }
        current == *expected_root
    }

    /// Convenience: compute the leaf hash from chunk bytes and verify
    /// in one call.
    pub fn verify_chunk(
        chunk_bytes: &[u8],
        leaf_idx: usize,
        num_leaves: usize,
        proof: &[u8],
        expected_root: &[u8; 32],
    ) -> bool {
        let leaf = Self::leaf_hash(chunk_bytes);
        Self::verify(leaf, leaf_idx, num_leaves, proof, expected_root)
    }

    /// Number of leaves (64KB chunks) in this tree.
    pub fn num_leaves(&self) -> usize {
        self.levels[0].len()
    }
}
