use crate::dag::{NodeHash, PhysicalDevicePk};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::time::{Duration, Instant};
use tox_proto::ToxProto;

#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub enum BlobStatus {
    Pending,
    Downloading,
    Available,
    Error,
}

/// Metadata for a large binary object.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobInfo {
    pub hash: NodeHash,
    pub size: u64,
    /// The Blake3-Merkle root for incremental verification (Bao).
    pub bao_root: Option<[u8; 32]>,
    pub status: BlobStatus,
    /// Optional bitmask of received chunks.
    pub received_mask: Option<Vec<u8>>,
}

/// A request for a specific chunk of a blob.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobReq {
    pub hash: NodeHash,
    pub offset: u64,
    pub length: u32,
}

/// Data payload for a blob chunk, including Bao proof for verification.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct BlobData {
    pub hash: NodeHash,
    pub offset: u64,
    pub data: Vec<u8>,
    /// Intermediate hashes needed to verify this chunk against the bao_root.
    pub proof: Vec<u8>,
}

impl BlobData {
    /// Verifies the chunk data and proof against the provided Bao root.
    pub fn verify(&self, bao_root: &[u8; 32]) -> bool {
        let mut decoder = bao::decode::SliceDecoder::new(
            &*self.proof,
            &blake3::Hash::from(*bao_root),
            self.offset,
            self.data.len() as u64,
        );
        let mut decoded_data = Vec::with_capacity(self.data.len());
        if decoder.read_to_end(&mut decoded_data).is_err() {
            return false;
        }
        decoded_data == self.data
    }
}

pub const CHUNK_SIZE: u64 = 64 * 1024; // 64KB
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Tracks which chunks of a blob have been received.
pub struct ChunkTracker {
    pub hash: NodeHash,
    pub total_size: u64,
    pub received_mask: Vec<u8>, // Bitmask
}

impl ChunkTracker {
    pub fn new(hash: NodeHash, total_size: u64) -> Self {
        let num_chunks = total_size.div_ceil(CHUNK_SIZE);
        let mask_size = (num_chunks as usize).div_ceil(8);
        Self {
            hash,
            total_size,
            received_mask: vec![0u8; mask_size],
        }
    }

    pub fn mark_received(&mut self, chunk_index: u64) {
        let byte_idx = (chunk_index / 8) as usize;
        let bit_idx = (chunk_index % 8) as u8;
        if byte_idx < self.received_mask.len() {
            self.received_mask[byte_idx] |= 1 << bit_idx;
        }
    }

    pub fn is_received(&self, chunk_index: u64) -> bool {
        let byte_idx = (chunk_index / 8) as usize;
        let bit_idx = (chunk_index % 8) as u8;
        if byte_idx < self.received_mask.len() {
            (self.received_mask[byte_idx] & (1 << bit_idx)) != 0
        } else {
            false
        }
    }

    pub fn is_complete(&self) -> bool {
        let num_chunks = self.total_size.div_ceil(CHUNK_SIZE);
        for i in 0..num_chunks {
            if !self.is_received(i) {
                return false;
            }
        }
        true
    }

    pub fn next_missing(&self, hint: u64) -> Option<u64> {
        let num_chunks = self.total_size.div_ceil(CHUNK_SIZE);
        for i in hint..num_chunks {
            if !self.is_received(i) {
                return Some(i);
            }
        }
        for i in 0..hint {
            if !self.is_received(i) {
                return Some(i);
            }
        }
        if num_chunks > 0 {
            tracing::debug!("No missing chunks found among {} chunks", num_chunks);
        }
        None
    }
}

/// Manages the synchronization of a blob from multiple peers.
pub struct SwarmSync {
    pub info: BlobInfo,
    pub tracker: ChunkTracker,
    /// Peers who have confirmed possession of this blob.
    pub seeders: HashSet<PhysicalDevicePk>,
    /// Chunks currently being fetched: chunk_index -> (peer_pk, start_time)
    pub active_fetches: HashMap<u64, (PhysicalDevicePk, Instant)>,
}

impl SwarmSync {
    pub fn new(info: BlobInfo) -> Self {
        let tracker = ChunkTracker::new(info.hash, info.size);
        Self {
            info,
            tracker,
            seeders: HashSet::new(),
            active_fetches: HashMap::new(),
        }
    }

    pub fn add_seeder(&mut self, peer: PhysicalDevicePk) {
        self.seeders.insert(peer);
    }

    /// Removes a seeder and clears any active fetches assigned to them.
    pub fn remove_seeder(&mut self, peer: &PhysicalDevicePk) {
        self.seeders.remove(peer);
        self.active_fetches.retain(|_, (p, _)| p != peer);
    }

    /// Clears any fetches that have exceeded FETCH_TIMEOUT.
    pub fn clear_stalled_fetches(&mut self, now: Instant) {
        self.active_fetches
            .retain(|_, (_, start)| now.saturating_duration_since(*start) < FETCH_TIMEOUT);
    }

    /// Selects the next set of chunk requests to send to available seeders.
    pub fn next_requests(
        &mut self,
        max_total_requests: usize,
        now: Instant,
    ) -> Vec<(PhysicalDevicePk, BlobReq)> {
        let mut reqs = Vec::new();
        let mut hint = 0;

        // Count in-flight requests per peer
        let mut in_flight_per_peer: HashMap<PhysicalDevicePk, usize> = HashMap::new();
        for (peer, _) in self.active_fetches.values() {
            *in_flight_per_peer.entry(*peer).or_default() += 1;
        }

        let num_chunks = self.info.size.div_ceil(CHUNK_SIZE);

        for _ in 0..num_chunks {
            if reqs.len() >= max_total_requests {
                break;
            }

            if let Some(chunk_idx) = self.tracker.next_missing(hint) {
                if !self.active_fetches.contains_key(&chunk_idx) {
                    // Pick seeder with least in-flight that is below limit
                    let seeder = self
                        .seeders
                        .iter()
                        .filter(|p| in_flight_per_peer.get(*p).copied().unwrap_or(0) < 4)
                        .min_by_key(|p| (in_flight_per_peer.get(*p).copied().unwrap_or(0), *p));

                    if let Some(seeder) = seeder {
                        let seeder = *seeder;
                        tracing::debug!("Requesting chunk {} from {:?}", chunk_idx, seeder);
                        reqs.push((
                            seeder,
                            BlobReq {
                                hash: self.info.hash,
                                offset: chunk_idx * CHUNK_SIZE,
                                length: CHUNK_SIZE as u32,
                            },
                        ));
                        self.active_fetches.insert(chunk_idx, (seeder, now));
                        *in_flight_per_peer.entry(seeder).or_default() += 1;
                    }
                }
                hint = chunk_idx + 1;
            } else {
                break;
            }
        }
        reqs
    }

    pub fn on_chunk_received(&mut self, data: &BlobData) -> bool {
        let chunk_idx = data.offset / CHUNK_SIZE;
        self.active_fetches.remove(&chunk_idx);

        if let Some(bao_root) = &self.info.bao_root
            && !data.verify(bao_root)
        {
            return false;
        }

        self.tracker.mark_received(chunk_idx);
        true
    }

    /// Returns the next scheduled wakeup time for this swarm sync.
    pub fn next_wakeup(&self, now: Instant) -> Instant {
        let mut next = now + Duration::from_secs(3600);

        // 1. Fetch timeouts
        for (_, start) in self.active_fetches.values() {
            next = next.min(*start + FETCH_TIMEOUT);
        }

        // 2. If we have missing chunks and available seeders, we want to poll ASAP
        let busy_peers: HashSet<PhysicalDevicePk> =
            self.active_fetches.values().map(|(p, _)| *p).collect();
        let has_available_seeder = self.seeders.iter().any(|p| !busy_peers.contains(p));

        if has_available_seeder && self.tracker.next_missing(0).is_some() {
            return now;
        }

        next
    }
}

// end of file
