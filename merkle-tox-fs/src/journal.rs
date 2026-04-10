use merkle_tox_core::dag::NodeHash;
use merkle_tox_core::vfs::{FileHandle, FileSystem};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRecordType {
    Node = 0x01,
    Vouch = 0x02,
    Blacklist = 0x03,
    Promotion = 0x04,
    RatchetAdvance = 0x05,
}

impl TryFrom<u8> for JournalRecordType {
    type Error = io::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(JournalRecordType::Node),
            0x02 => Ok(JournalRecordType::Vouch),
            0x03 => Ok(JournalRecordType::Blacklist),
            0x04 => Ok(JournalRecordType::Promotion),
            0x05 => Ok(JournalRecordType::RatchetAdvance),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid journal record type",
            )),
        }
    }
}

pub struct JournalRecord {
    pub hash: NodeHash,
    pub record_type: JournalRecordType,
    pub payload: Vec<u8>,
    pub offset: u64,
}

pub const JOURNAL_FOOTER_MAGIC: u32 = 0x454E4421;

pub struct Journal<F: FileSystem> {
    handle: Box<dyn FileHandle>,
    generation_id: u64,
    has_footer: bool,
    _marker: std::marker::PhantomData<F>,
}

impl<F: FileSystem> Journal<F> {
    pub fn open(fs: Arc<F>, path: PathBuf) -> io::Result<Self> {
        let mut handle = fs.open(&path, true, true, false)?;
        let metadata = handle.metadata()?;
        let generation_id;
        let mut has_footer = false;

        if metadata.len < 16 {
            // New or corrupt journal - restart
            generation_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            handle.set_len(0)?;
            handle.write_all(&generation_id.to_le_bytes())?;
            handle.write_all(&[0u8; 8])?; // reserved
        } else {
            let mut header = [0u8; 16];
            handle.read_exact(&mut header)?;
            generation_id = u64::from_le_bytes(header[0..8].try_into().unwrap());

            // Check for footer
            if metadata.len > 16 + 4 + 4 + 32 {
                handle.seek(SeekFrom::Start(metadata.len - 40))?;
                let mut footer_buf = [0u8; 4];
                handle.read_exact(&mut footer_buf)?;
                if u32::from_le_bytes(footer_buf) == JOURNAL_FOOTER_MAGIC {
                    has_footer = true;
                }
            }
        }

        Ok(Journal {
            handle,
            generation_id,
            has_footer,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn generation_id(&self) -> u64 {
        self.generation_id
    }

    pub fn append(
        &mut self,
        record_type: JournalRecordType,
        payload: &[u8],
    ) -> io::Result<(NodeHash, u64)> {
        if self.has_footer {
            // SPEC: Section 4.1 - Cleanup: ftruncate() the file to remove the footer.
            // We find the data end offset by reading all records. While slightly
            // inefficient, it guarantees we truncate at the correct boundary.
            let records = self.read_all()?;
            let end_offset = if let Some(last) = records.last() {
                last.offset + 4 + 32 + 1 + last.payload.len() as u64
            } else {
                16
            };
            self.handle.set_len(end_offset)?;
            self.has_footer = false;
        }

        let hash = blake3::hash(payload);
        let node_hash = NodeHash::from(*hash.as_bytes());

        let length = payload.len() as u32;

        let offset = self.handle.seek(SeekFrom::End(0))?;
        self.handle.write_all(&length.to_le_bytes())?;
        self.handle.write_all(node_hash.as_bytes())?;
        self.handle.write_all(&[record_type as u8])?;
        self.handle.write_all(payload)?;
        // fsync each appended record so it survives a crash. The
        // journal is the on-disk record of recently-added nodes;
        // without this, a power loss between `append` and the next
        // compaction can lose all volatile records (compaction
        // truncates the journal — see `truncate` below). Spec
        // §4.1 ("Recovery") relies on per-record durability for
        // correct mid-batch resumption.
        self.handle.sync_data()?;

        Ok((node_hash, offset))
    }

    pub fn write_footer(&mut self) -> io::Result<()> {
        let records = self.read_all()?;
        let mut hasher = blake3::Hasher::new();
        for rec in &records {
            hasher.update(&(rec.payload.len() as u32).to_le_bytes());
            hasher.update(rec.hash.as_bytes());
            hasher.update(&[rec.record_type as u8]);
            hasher.update(&rec.payload);
        }
        let checksum = hasher.finalize();

        self.handle.seek(SeekFrom::End(0))?;
        self.handle.write_all(&JOURNAL_FOOTER_MAGIC.to_le_bytes())?;
        self.handle
            .write_all(&(records.len() as u32).to_le_bytes())?;
        self.handle.write_all(checksum.as_bytes())?;
        // fsync the footer so the "this journal is sealed" marker
        // is durable; otherwise a crash before compaction could
        // leave a journal that looks open and gets re-truncated.
        self.handle.sync_data()?;
        // IndexTable omitted for simplicity in this iteration, but footer magic is present
        self.has_footer = true;
        Ok(())
    }

    pub fn read_all(&mut self) -> io::Result<Vec<JournalRecord>> {
        self.handle.seek(SeekFrom::Start(16))?;
        let mut records = Vec::new();

        loop {
            let offset = self.handle.stream_position()?;
            let mut len_buf = [0u8; 4];
            if self.handle.read_exact(&mut len_buf).is_err() {
                break;
            }
            let length = u32::from_le_bytes(len_buf);

            let mut hash_buf = [0u8; 32];
            if self.handle.read_exact(&mut hash_buf).is_err() {
                self.handle.set_len(offset)?;
                break;
            }
            let hash = NodeHash::from(hash_buf);

            let mut type_buf = [0u8; 1];
            if self.handle.read_exact(&mut type_buf).is_err() {
                self.handle.set_len(offset)?;
                break;
            }
            let record_type = match JournalRecordType::try_from(type_buf[0]) {
                Ok(t) => t,
                Err(_) => {
                    self.handle.set_len(offset)?;
                    break;
                }
            };

            let mut payload = vec![0u8; length as usize];
            if self.handle.read_exact(&mut payload).is_err() {
                self.handle.set_len(offset)?;
                break;
            }

            // Verify hash
            let actual_hash = blake3::hash(&payload);
            if actual_hash.as_bytes() != hash.as_bytes() {
                // Stop and truncate at corruption as per Section 4.1 "Recovery"
                self.handle.set_len(offset)?;
                break;
            }

            records.push(JournalRecord {
                hash,
                record_type,
                payload,
                offset,
            });
        }

        Ok(records)
    }

    pub fn read_record_at(&mut self, offset: u64) -> io::Result<JournalRecord> {
        self.handle.seek(SeekFrom::Start(offset))?;

        let mut len_buf = [0u8; 4];
        self.handle.read_exact(&mut len_buf)?;
        let length = u32::from_le_bytes(len_buf);

        let mut hash_buf = [0u8; 32];
        self.handle.read_exact(&mut hash_buf)?;
        let hash = NodeHash::from(hash_buf);

        let mut type_buf = [0u8; 1];
        self.handle.read_exact(&mut type_buf)?;
        let record_type = JournalRecordType::try_from(type_buf[0])?;

        let mut payload = vec![0u8; length as usize];
        self.handle.read_exact(&mut payload)?;

        Ok(JournalRecord {
            hash,
            record_type,
            payload,
            offset,
        })
    }

    pub fn truncate(&mut self, generation_id: u64) -> io::Result<()> {
        self.handle.set_len(16)?;
        self.handle.seek(SeekFrom::Start(0))?;
        self.handle.write_all(&generation_id.to_le_bytes())?;
        self.handle.write_all(&[0u8; 8])?; // reserved
        // CRITICAL durability boundary. `truncate` is called by the
        // compaction path after the new pack has been finalised but
        // before `state.bin` is updated to point at it. If we don't
        // fsync here, the truncate's `set_len(16)` may hit disk
        // before the new pack data — recovery would then see a
        // wiped journal AND no pack to recover from. The
        // post-truncate fsync ensures the new generation_id and
        // truncated tail are durable in lockstep. Caller is
        // responsible for fsyncing the new pack before calling this.
        self.handle.sync_data()?;
        self.generation_id = generation_id;
        Ok(())
    }
}
