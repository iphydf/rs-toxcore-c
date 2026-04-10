use blake3;
use thiserror::Error;
use tox_proto::{ConversationId, NodeHash, ToxProto};

#[derive(Debug, Error)]
pub enum ReconciliationError {
    #[error("Decoding failed: sketch is not peelable (too many differences)")]
    DecodingFailed(DecodingStats),
    #[error("Invalid sketch: cell count mismatch")]
    InvalidSketch,
}

pub type ReconciliationResult<T> = Result<T, ReconciliationError>;

#[derive(Debug, Clone, Default)]
pub struct DecodingStats {
    pub cells_peeled: usize,
    pub iterations: usize,
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq, Default)]
pub struct IbltCell {
    /// ID 0: Signed count
    pub count: i32,
    /// ID 1: XOR sum of 32-byte Blake3 hashes
    pub id_sum: [u8; 32],
    /// ID 2: XOR sum of truncated 64-bit check-hashes
    pub hash_sum: u64,
}

/// Cap on the number of cells in a `SyncSketch.cells` array.  Equal
/// to `Tier::Large.cell_count()` — the largest legitimate IBLT size
/// in the protocol's tier ladder.  Any sketch with more cells than
/// this is unambiguously over-spec and is rejected at the wire-
/// deserialise boundary by `BoundedVec`.
pub const MAX_SKETCH_CELLS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Tiny,   // 16 cells
    Small,  // 64 cells
    Medium, // 256 cells
    Large,  // 1024 cells
}

impl Tier {
    pub fn cell_count(&self) -> usize {
        match self {
            Tier::Tiny => 16,
            Tier::Small => 64,
            Tier::Medium => 256,
            Tier::Large => 1024,
        }
    }

    pub fn from_cell_count(count: usize) -> Self {
        match count {
            0..=16 => Tier::Tiny,
            17..=64 => Tier::Small,
            65..=256 => Tier::Medium,
            _ => Tier::Large,
        }
    }

    /// Maximum number of symmetric differences decodable for this tier.
    pub fn d_max(&self) -> usize {
        match self {
            Tier::Tiny => 10,
            Tier::Small => 40,
            Tier::Medium => 170,
            Tier::Large => 680,
        }
    }
}

#[derive(Debug, Clone, ToxProto, PartialEq, Eq, Hash)]
pub struct SyncRange {
    pub min_rank: u64,
    pub max_rank: u64,
}

/// Wire payload of a single IBLT-based reconciliation step.
///
/// `cells` is length-capped at `MAX_SKETCH_CELLS = 1024` (= the
/// largest legitimate tier, `Tier::Large`) at the type level: any
/// peer-supplied wire payload claiming more cells is rejected by
/// `BoundedVec`'s deserialiser before allocating a single
/// `IbltCell`. Without this cap the handler's PoW gate at
/// `merkle-tox-core/src/engine/handlers/mod.rs:193` only fires
/// *after* full deserialisation, leaving an authenticated-peer DoS
/// where a 100 000-cell sketch costs ~5 MB allocation +
/// `O(cells.len())` parse work per packet.
#[derive(Debug, Clone, ToxProto, PartialEq, Eq)]
pub struct SyncSketch {
    pub conversation_id: ConversationId,
    pub cells: tox_proto::BoundedVec<IbltCell, MAX_SKETCH_CELLS>,
    pub range: SyncRange,
}

pub struct IbltSketch {
    pub cells: Vec<IbltCell>,
    k: usize,
    /// Optional keyed hash for IBLT indices/checksums.
    /// When set, the IBLT uses a conversation-specific key derived from K_conv
    /// so external parties cannot forge valid sketches.
    k_iblt: Option<[u8; 32]>,
}

const K: usize = 4;
const HASH_CONTEXT_CHECKSUM: &str = "merkle-tox v1 iblt checksum";
const HASH_CONTEXT_INDICES: &str = "merkle-tox v1 iblt indices";

impl IbltSketch {
    pub fn new(cell_count: usize) -> Self {
        Self {
            cells: vec![IbltCell::default(); cell_count],
            k: K,
            k_iblt: None,
        }
    }

    /// Creates a keyed IBLT sketch. When `k_iblt` is `Some`, indices and
    /// checksums are derived from this key instead of the static context,
    /// preventing external parties from crafting valid sketches.
    pub fn new_keyed(cell_count: usize, k_iblt: Option<[u8; 32]>) -> Self {
        Self {
            cells: vec![IbltCell::default(); cell_count],
            k: K,
            k_iblt,
        }
    }

    pub fn from_cells(cells: Vec<IbltCell>) -> Self {
        Self {
            cells,
            k: K,
            k_iblt: None,
        }
    }

    pub fn from_cells_keyed(cells: Vec<IbltCell>, k_iblt: Option<[u8; 32]>) -> Self {
        Self {
            cells,
            k: K,
            k_iblt,
        }
    }

    pub fn into_cells(self) -> Vec<IbltCell> {
        self.cells
    }

    pub fn insert(&mut self, id: &[u8; 32]) {
        self.update(id, 1);
    }

    pub fn remove(&mut self, id: &[u8; 32]) {
        self.update(id, -1);
    }

    fn update(&mut self, id: &[u8; 32], delta: i32) {
        let indices = self.get_indices(id);
        let checksum = self.get_checksum(id);

        for idx in indices {
            let cell = &mut self.cells[idx];
            cell.count += delta;
            for (s, &id_byte) in cell.id_sum.iter_mut().zip(id) {
                *s ^= id_byte;
            }
            cell.hash_sum ^= checksum;
        }
    }

    fn get_indices(&self, id: &[u8; 32]) -> Vec<usize> {
        let mut indices = Vec::with_capacity(self.k);
        let num_cells = self.cells.len();

        let key = match &self.k_iblt {
            Some(k) => blake3::derive_key("merkle-tox v1 iblt indices", k),
            None => blake3_key(HASH_CONTEXT_INDICES),
        };
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(id);
        let mut xof = hasher.finalize_xof();

        while indices.len() < self.k && indices.len() < num_cells {
            let mut buf = [0u8; 4];
            xof.fill(&mut buf);
            let idx = (u32::from_le_bytes(buf) as usize) % num_cells;
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }

        indices.sort_unstable();
        indices
    }

    fn get_checksum(&self, id: &[u8; 32]) -> u64 {
        let key = match &self.k_iblt {
            Some(k) => blake3::derive_key("merkle-tox v1 iblt checksum", k),
            None => blake3_key(HASH_CONTEXT_CHECKSUM),
        };
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(id);
        let hash = hasher.finalize();
        u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap())
    }

    pub fn subtract(&mut self, other: &IbltSketch) -> ReconciliationResult<()> {
        if self.cells.len() != other.cells.len() {
            return Err(ReconciliationError::InvalidSketch);
        }
        for (c_self, c_other) in self.cells.iter_mut().zip(&other.cells) {
            c_self.count -= c_other.count;
            for (s, &o) in c_self.id_sum.iter_mut().zip(&c_other.id_sum) {
                *s ^= o;
            }
            c_self.hash_sum ^= c_other.hash_sum;
        }
        Ok(())
    }

    /// Decodes the difference between two sets.
    /// Returns (elements_in_self_not_other, elements_in_other_not_self, stats)
    pub fn decode(
        &mut self,
    ) -> ReconciliationResult<(Vec<NodeHash>, Vec<NodeHash>, DecodingStats)> {
        let mut in_self = Vec::new();
        let mut in_other = Vec::new();
        let mut pure_cells = Vec::new();
        let mut stats = DecodingStats::default();

        for i in 0..self.cells.len() {
            stats.iterations += 1;
            if self.is_pure(i) {
                pure_cells.push(i);
            }
        }

        while let Some(idx) = pure_cells.pop() {
            stats.iterations += 1;
            if !self.is_pure(idx) {
                continue;
            }

            let cell = self.cells[idx].clone();
            let id = cell.id_sum;
            let count = cell.count;

            if count == 1 {
                in_self.push(NodeHash::from(id));
            } else {
                in_other.push(NodeHash::from(id));
            }
            stats.cells_peeled += 1;

            // D_max cap: abort if total differences exceed tier limit.
            let d_max = Tier::from_cell_count(self.cells.len()).d_max();
            if in_self.len() + in_other.len() > d_max {
                return Err(ReconciliationError::DecodingFailed(stats));
            }

            // Remove the element from all cells it maps to
            let indices = self.get_indices(&id);
            for i in indices {
                let c = &mut self.cells[i];
                c.count -= count;
                for (s, &id_byte) in c.id_sum.iter_mut().zip(&id) {
                    *s ^= id_byte;
                }
                c.hash_sum ^= cell.hash_sum;
                if self.is_pure(i) {
                    pure_cells.push(i);
                }
            }
        }

        // Check if the sketch is empty
        for (i, cell) in self.cells.iter().enumerate() {
            stats.iterations += 1;
            if cell.count != 0 || cell.hash_sum != 0 || cell.id_sum != [0u8; 32] {
                tracing::debug!(
                    "Cell {} not empty: count={}, hash_sum={}, id_sum={:?}",
                    i,
                    cell.count,
                    cell.hash_sum,
                    cell.id_sum
                );
                return Err(ReconciliationError::DecodingFailed(stats));
            }
        }

        Ok((in_self, in_other, stats))
    }

    fn is_pure(&self, idx: usize) -> bool {
        let cell = &self.cells[idx];
        if cell.count.abs() != 1 {
            return false;
        }
        self.get_checksum(&cell.id_sum) == cell.hash_sum
    }
}

fn blake3_key(context: &str) -> [u8; 32] {
    blake3::derive_key(context, &[])
}
