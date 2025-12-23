use merkle_tox_core::dag::{ChainKey, NodeHash, PhysicalDevicePk};
use merkle_tox_core::vfs::{FileHandle, FileSystem};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tox_proto::{self, ToxProto};

#[derive(Debug, Clone, ToxProto)]
pub struct ConvState {
    pub heads: Vec<NodeHash>,
    pub admin_heads: Vec<NodeHash>,
    pub message_count: u32,
    pub last_rotation_time: i64,
    pub active_packs: Vec<u64>,
    pub active_journal_id: u64,
}

pub struct StateFile<F: FileSystem> {
    path: PathBuf,
    fs: Arc<F>,
}

impl<F: FileSystem> StateFile<F> {
    pub fn new(fs: Arc<F>, path: PathBuf) -> Self {
        Self { fs, path }
    }

    pub fn load(&self) -> io::Result<ConvState> {
        let data = self.fs.read(&self.path)?;
        tox_proto::deserialize(&data).map_err(|e| io::Error::other(e.to_string()))
    }

    pub fn save(&self, state: &ConvState) -> io::Result<()> {
        let data = tox_proto::serialize(state).map_err(|e| io::Error::other(e.to_string()))?;
        let mut tmp_path = self.path.clone();
        tmp_path.set_extension("tmp");
        self.fs.write(&tmp_path, &data)?;
        self.fs.rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

pub struct RatchetSlot {
    pub device_pk: PhysicalDevicePk,
    pub chain_key: ChainKey,
    pub last_sequence_number: u64,
}

impl RatchetSlot {
    pub const SIZE: usize = 32 + 32 + 8; // 72 bytes

    pub fn to_bytes(&self, buf: &mut [u8]) {
        buf[0..32].copy_from_slice(self.device_pk.as_bytes());
        buf[32..64].copy_from_slice(self.chain_key.as_bytes());
        buf[64..72].copy_from_slice(&self.last_sequence_number.to_le_bytes());
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[0..32]);
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&buf[32..64]);
        let seq = u64::from_le_bytes(buf[64..72].try_into().unwrap());
        Self {
            device_pk: PhysicalDevicePk::from(pk),
            chain_key: ChainKey::from(ck),
            last_sequence_number: seq,
        }
    }
}

pub struct RatchetFile<F: FileSystem> {
    handle: Box<dyn FileHandle>,
    _marker: std::marker::PhantomData<F>,
}

// Section 6.2: Ratchet Checkpoints
// Atomic In-Place double-buffered pattern
// [Header: u32 magic, u32 active_buffer, u32 count0, u32 count1]
// [Buffer 0: RatchetSlot * N]
// [Buffer 1: RatchetSlot * N]

pub const RATCHET_MAGIC: u32 = 0x52415443; // 'RATC'

impl<F: FileSystem> RatchetFile<F> {
    pub fn open(fs: Arc<F>, path: PathBuf) -> io::Result<Self> {
        let mut handle = fs.open(&path, true, true, false)?;
        let meta = handle.metadata()?;
        if meta.len == 0 {
            handle.write_all(&RATCHET_MAGIC.to_le_bytes())?;
            handle.write_all(&0u32.to_le_bytes())?; // active_buffer
            handle.write_all(&0u32.to_le_bytes())?; // count0
            handle.write_all(&0u32.to_le_bytes())?; // count1
        }
        Ok(Self {
            handle,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn load(&mut self) -> io::Result<Vec<RatchetSlot>> {
        self.handle.seek(SeekFrom::Start(4))?;
        let mut buf = [0u8; 4];
        self.handle.read_exact(&mut buf)?;
        let active = u32::from_le_bytes(buf);

        self.handle.read_exact(&mut buf)?;
        let count0 = u32::from_le_bytes(buf);
        self.handle.read_exact(&mut buf)?;
        let count1 = u32::from_le_bytes(buf);

        let (count, offset) = if active == 0 {
            (count0, 16)
        } else {
            (count1, 16 + 1024 * RatchetSlot::SIZE) // Assume max 1024 slots for now
        };

        self.handle.seek(SeekFrom::Start(offset as u64))?;
        let mut slots = Vec::with_capacity(count as usize);
        let mut slot_buf = [0u8; RatchetSlot::SIZE];
        for _ in 0..count {
            self.handle.read_exact(&mut slot_buf)?;
            slots.push(RatchetSlot::from_bytes(&slot_buf));
        }
        Ok(slots)
    }

    pub fn save(&mut self, slots: &[RatchetSlot]) -> io::Result<()> {
        self.handle.seek(SeekFrom::Start(4))?;
        let mut buf = [0u8; 4];
        self.handle.read_exact(&mut buf)?;
        let active = u32::from_le_bytes(buf);
        let next = 1 - active;

        let offset = 16 + (next as usize * 1024 * RatchetSlot::SIZE);
        self.handle.seek(SeekFrom::Start(offset as u64))?;
        let mut slot_buf = [0u8; RatchetSlot::SIZE];
        for slot in slots {
            slot.to_bytes(&mut slot_buf);
            self.handle.write_all(&slot_buf)?;
        }

        // Update counts and active buffer
        if next == 0 {
            self.handle.seek(SeekFrom::Start(8))?;
            self.handle.write_all(&(slots.len() as u32).to_le_bytes())?;
        } else {
            self.handle.seek(SeekFrom::Start(12))?;
            self.handle.write_all(&(slots.len() as u32).to_le_bytes())?;
        }

        self.handle.seek(SeekFrom::Start(4))?;
        self.handle.write_all(&next.to_le_bytes())?;
        Ok(())
    }
}
