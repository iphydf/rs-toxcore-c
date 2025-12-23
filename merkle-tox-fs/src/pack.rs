use merkle_tox_core::dag::NodeHash;
use merkle_tox_core::vfs::FileSystem;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tox_proto;

pub const INDEX_MAGIC: u32 = 0x4D544F58;
pub const DEFAULT_FANOUT_BITS: u32 = 8;
pub const RECORD_SIZE: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexRecord {
    pub hash: NodeHash,
    pub offset: u64,
    pub rank: u64,
    pub payload_length: u32,
    pub node_type: u8,
    pub status: u8,
    pub flags: u8,
}

impl IndexRecord {
    pub fn to_bytes(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), RECORD_SIZE);
        buf[0..32].copy_from_slice(self.hash.as_bytes());
        buf[32..40].copy_from_slice(&self.offset.to_le_bytes());
        buf[40..48].copy_from_slice(&self.rank.to_le_bytes());
        buf[48..52].copy_from_slice(&self.payload_length.to_le_bytes());
        buf[52] = self.node_type;
        buf[53] = self.status;
        buf[54] = self.flags;
        buf[55] = 0; // Reserved
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), RECORD_SIZE);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[0..32]);
        let offset = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let rank = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let payload_length = u32::from_le_bytes(buf[48..52].try_into().unwrap());
        let node_type = buf[52];
        let status = buf[53];
        let flags = buf[54];
        Self {
            hash: NodeHash::from(hash),
            offset,
            rank,
            payload_length,
            node_type,
            status,
            flags,
        }
    }
}

pub struct PackIndex {
    pub fanout_bits: u32,
    pub bloom_k: u32,
    pub bloom_filter: Vec<u8>,
    pub fanout_table: Vec<u32>,
    pub records: Vec<IndexRecord>,
}

impl PackIndex {
    pub fn build(records: Vec<IndexRecord>, fanout_bits: u32, bloom_k: u32) -> Self {
        let mut sorted_records = records;
        sorted_records.sort_unstable_by_key(|r| r.hash);

        let n = sorted_records.len();
        // Bloom Filter: 10 bits per record
        let bloom_m = (n * 10).div_ceil(8).max(64) as u32;
        let mut bloom_filter = vec![0u8; bloom_m as usize];
        let bits = bloom_m * 8;

        for r in &sorted_records {
            let h = r.hash.as_bytes();
            for k in 0..bloom_k {
                // Simple multi-hash from blake3 hash
                let mut hasher = blake3::Hasher::new();
                hasher.update(&[k as u8]);
                hasher.update(h);
                let out = hasher.finalize();
                let idx = (u64::from_le_bytes(out.as_bytes()[0..8].try_into().unwrap())
                    % bits as u64) as usize;
                bloom_filter[idx / 8] |= 1 << (idx % 8);
            }
        }

        let fanout_size = 1 << fanout_bits;
        let mut fanout_table = vec![0u32; fanout_size];
        for r in &sorted_records {
            let prefix = Self::get_prefix(&r.hash, fanout_bits);
            fanout_table[prefix as usize] += 1;
        }
        // Prefix sum
        let mut sum = 0;
        for entry in fanout_table.iter_mut().take(fanout_size) {
            sum += *entry;
            *entry = sum;
        }

        Self {
            fanout_bits,
            bloom_k,
            bloom_filter,
            fanout_table,
            records: sorted_records,
        }
    }

    fn get_prefix(hash: &NodeHash, bits: u32) -> u32 {
        let bytes = hash.as_bytes();
        let mut prefix = 0u32;
        let full_bytes = (bits / 8) as usize;
        for &b in bytes.iter().take(full_bytes) {
            prefix = (prefix << 8) | b as u32;
        }
        let remaining_bits = bits % 8;
        if remaining_bits > 0 {
            prefix =
                (prefix << remaining_bits) | (bytes[full_bytes] as u32 >> (8 - remaining_bits));
        }
        prefix
    }

    pub fn save<F: FileSystem>(&self, fs: &F, path: &Path) -> io::Result<()> {
        let mut file = fs.open(path, true, true, true)?;
        file.write_all(&INDEX_MAGIC.to_le_bytes())?;
        file.write_all(&self.fanout_bits.to_le_bytes())?;
        file.write_all(&self.bloom_k.to_le_bytes())?;
        file.write_all(&(self.bloom_filter.len() as u32).to_le_bytes())?;
        file.write_all(&self.bloom_filter)?;
        for &f in &self.fanout_table {
            file.write_all(&f.to_le_bytes())?;
        }

        let header = tox_proto::serialize(&self.records.len())
            .map_err(|e| io::Error::other(e.to_string()))?;
        file.write_all(&(header.len() as u32).to_le_bytes())?;
        file.write_all(&header)?;

        let mut buf = [0u8; RECORD_SIZE];
        for r in &self.records {
            r.to_bytes(&mut buf);
            file.write_all(&buf)?;
        }
        Ok(())
    }

    pub fn load<F: FileSystem>(fs: &F, path: &Path) -> io::Result<Self> {
        let mut file = fs.open(path, false, false, false)?;
        let mut u32_buf = [0u8; 4];

        file.read_exact(&mut u32_buf)?;
        let magic = u32::from_le_bytes(u32_buf);
        if magic != INDEX_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid index magic",
            ));
        }

        file.read_exact(&mut u32_buf)?;
        let fanout_bits = u32::from_le_bytes(u32_buf);

        file.read_exact(&mut u32_buf)?;
        let bloom_k = u32::from_le_bytes(u32_buf);

        file.read_exact(&mut u32_buf)?;
        let bloom_m = u32::from_le_bytes(u32_buf);

        let mut bloom_filter = vec![0u8; bloom_m as usize];
        file.read_exact(&mut bloom_filter)?;

        let fanout_size = 1 << fanout_bits;
        let mut fanout_table = vec![0u32; fanout_size];
        for entry in fanout_table.iter_mut().take(fanout_size) {
            file.read_exact(&mut u32_buf)?;
            *entry = u32::from_le_bytes(u32_buf);
        }

        file.read_exact(&mut u32_buf)?;
        let header_len = u32::from_le_bytes(u32_buf);
        let mut header = vec![0u8; header_len as usize];
        file.read_exact(&mut header)?;
        let count: usize =
            tox_proto::deserialize(&header).map_err(|e| io::Error::other(e.to_string()))?;

        let mut records = Vec::with_capacity(count);
        let mut buf = [0u8; RECORD_SIZE];
        for _ in 0..count {
            file.read_exact(&mut buf)?;
            records.push(IndexRecord::from_bytes(&buf));
        }

        Ok(Self {
            fanout_bits,
            bloom_k,
            bloom_filter,
            fanout_table,
            records,
        })
    }

    pub fn lookup(&self, hash: &NodeHash) -> Option<&IndexRecord> {
        // 1. Bloom Filter Check
        let h = hash.as_bytes();
        let bits = (self.bloom_filter.len() * 8) as u32;
        for k in 0..self.bloom_k {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[k as u8]);
            hasher.update(h);
            let out = hasher.finalize();
            let idx = (u64::from_le_bytes(out.as_bytes()[0..8].try_into().unwrap()) % bits as u64)
                as usize;
            if (self.bloom_filter[idx / 8] & (1 << (idx % 8))) == 0 {
                return None;
            }
        }

        // 2. Fanout Table Lookup
        let prefix = Self::get_prefix(hash, self.fanout_bits);
        let low = if prefix == 0 {
            0
        } else {
            self.fanout_table[prefix as usize - 1] as usize
        };
        let high = self.fanout_table[prefix as usize] as usize;

        // 3. Binary Search
        let range = &self.records[low..high];
        range
            .binary_search_by_key(hash, |r| r.hash)
            .ok()
            .map(|idx| &range[idx])
    }
}

pub struct Pack<F: FileSystem> {
    pub data_path: PathBuf,
    pub index: PackIndex,
    pub fs: Arc<F>,
}

impl<F: FileSystem> Pack<F> {
    pub fn open(fs: Arc<F>, data_path: PathBuf, index_path: &Path) -> io::Result<Self> {
        let index = PackIndex::load(&*fs, index_path)?;
        Ok(Self {
            data_path,
            index,
            fs,
        })
    }

    pub fn get_node_data(&self, hash: &NodeHash) -> io::Result<Option<Vec<u8>>> {
        let record = match self.index.lookup(hash) {
            Some(r) => r,
            None => return Ok(None),
        };

        let mut handle = self.fs.open(&self.data_path, false, false, false)?;
        // Frame: [u32 length] [u8[32] hash] [u8 type] [payload]
        // Skip header to get to payload
        handle.seek(SeekFrom::Start(record.offset + 4 + 32 + 1))?;

        let mut payload = vec![0u8; record.payload_length as usize];
        handle.read_exact(&mut payload)?;

        Ok(Some(payload))
    }
}
