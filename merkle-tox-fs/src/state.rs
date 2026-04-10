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
        // Tmp+rename atomicity requires three barriers, not two:
        // 1. Write tmp file contents.
        // 2. fsync tmp file so data hits disk before the directory
        //    metadata change.
        // 3. Rename tmp → final (atomic on POSIX).
        // 4. fsync the parent directory so the rename is durable.
        // Without (2) the rename can land on a file whose contents
        // haven't yet hit disk; without (4) the rename itself can
        // be lost across crash on filesystems that don't guarantee
        // metadata-write ordering against data writes (ext4 default,
        // btrfs, zfs without sync=always).
        {
            let mut handle = self.fs.open(&tmp_path, true, true, true)?;
            handle.write_all(&data)?;
            handle.sync_data()?;
        }
        self.fs.rename(&tmp_path, &self.path)?;
        if let Some(parent) = self.path.parent() {
            self.fs.sync_dir(parent)?;
        }
        Ok(())
    }
}

pub struct RatchetSlot {
    pub device_pk: PhysicalDevicePk,
    pub chain_key: ChainKey,
    pub last_sequence_number: u64,
    pub epoch_id: u64,
}

impl RatchetSlot {
    pub const SIZE: usize = 32 + 32 + 8 + 8; // 80 bytes

    pub fn to_bytes(&self, buf: &mut [u8]) {
        buf[0..32].copy_from_slice(self.device_pk.as_bytes());
        buf[32..64].copy_from_slice(self.chain_key.as_bytes());
        buf[64..72].copy_from_slice(&self.last_sequence_number.to_le_bytes());
        buf[72..80].copy_from_slice(&self.epoch_id.to_le_bytes());
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&buf[0..32]);
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&buf[32..64]);
        let seq = u64::from_le_bytes(buf[64..72].try_into().unwrap());
        let epoch = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        Self {
            device_pk: PhysicalDevicePk::from(pk),
            chain_key: ChainKey::from(ck),
            last_sequence_number: seq,
            epoch_id: epoch,
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
            (count1, 16 + 1024 * RatchetSlot::SIZE) // Assume a maximum of 1024 slots
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

        // Update counts (the per-buffer slot count) before the active
        // pointer flip.
        if next == 0 {
            self.handle.seek(SeekFrom::Start(8))?;
            self.handle.write_all(&(slots.len() as u32).to_le_bytes())?;
        } else {
            self.handle.seek(SeekFrom::Start(12))?;
            self.handle.write_all(&(slots.len() as u32).to_le_bytes())?;
        }

        // CRITICAL durability ordering for the double-buffer trick:
        // the new buffer's payload + count MUST be on disk before
        // the active-pointer flip, otherwise crash recovery loads
        // a buffer pointer that points at zeros (or torn data),
        // wiping all per-device sequence-number state. Without this
        // fsync, ext4 with deferred allocation can land the 4-byte
        // active-pointer metadata write before the buffer payload —
        // silent loss of the next batch of inbound packets.
        self.handle.sync_data()?;

        self.handle.seek(SeekFrom::Start(4))?;
        self.handle.write_all(&next.to_le_bytes())?;
        // Second fsync so the active-pointer flip itself is durable;
        // otherwise a crash between the flip and the next routine
        // fsync could let the receiver come back believing the
        // *prior* buffer is still active, losing any updates that
        // had been written into `next` and counted on for sequence
        // monotonicity by the caller.
        self.handle.sync_data()?;
        Ok(())
    }
}
