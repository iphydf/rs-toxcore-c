use merkle_tox_core::dag::NodeHash;
use merkle_tox_core::vfs::FileSystem;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use zstd;

pub const OPAQUE_SEGMENT_MAX_SIZE: u64 = 10 * 1024 * 1024; // 10MB
pub const OPAQUE_TOTAL_MAX_SIZE: u64 = 100 * 1024 * 1024; // 100MB

pub struct OpaqueIndexRecord {
    pub hash: NodeHash,
    pub segment_id: u64,
    pub offset: u32,
}

impl OpaqueIndexRecord {
    pub const SIZE: usize = 32 + 8 + 4; // 44 bytes
    pub fn to_bytes(&self, buf: &mut [u8]) {
        buf[0..32].copy_from_slice(self.hash.as_bytes());
        buf[32..40].copy_from_slice(&self.segment_id.to_le_bytes());
        buf[40..44].copy_from_slice(&self.offset.to_le_bytes());
    }
    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[0..32]);
        let segment_id = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let offset = u32::from_le_bytes(buf[40..44].try_into().unwrap());
        Self {
            hash: NodeHash::from(hash),
            segment_id,
            offset,
        }
    }
}

pub struct OpaqueStore<F: FileSystem> {
    root: PathBuf,
    fs: Arc<F>,
}

impl<F: FileSystem> OpaqueStore<F> {
    pub fn new(root: PathBuf, fs: Arc<F>) -> Self {
        Self { root, fs }
    }

    pub fn put_node(&self, hash: &NodeHash, data: &[u8]) -> io::Result<()> {
        let (segment_id, offset) = self.write_to_newest(data)?;
        self.update_index(hash, segment_id, offset)?;
        self.check_eviction()?;
        Ok(())
    }

    fn write_to_newest(&self, data: &[u8]) -> io::Result<(u64, u32)> {
        let mut segments = Vec::new();
        if let Ok(entries) = self.fs.read_dir(&self.root) {
            for path in entries {
                if path.extension().is_some_and(|ext| ext == "bin")
                    && path.file_name().unwrap() != "index.bin"
                    && let Some(name) = path.file_stem().and_then(|s| s.to_str())
                    && let Ok(id) = name.parse::<u64>()
                {
                    segments.push((id, path));
                }
            }
        }
        segments.sort_by_key(|s| s.0);

        let (segment_id, path) = if let Some((id, path)) = segments.last() {
            let meta = self.fs.metadata(path)?;
            if meta.len + data.len() as u64 + 4 <= OPAQUE_SEGMENT_MAX_SIZE {
                (*id, path.clone())
            } else {
                let new_id = *id + 1;
                (new_id, self.root.join(format!("{:020}.bin", new_id)))
            }
        } else {
            let new_id = 1u64;
            (new_id, self.root.join(format!("{:020}.bin", new_id)))
        };

        if let Some(parent) = path.parent() {
            self.fs.create_dir_all(parent)?;
        }

        let mut handle = self.fs.open(&path, true, true, false)?;
        let offset = handle.seek(SeekFrom::End(0))?;

        handle.write_all(&(data.len() as u32).to_le_bytes())?;
        handle.write_all(data)?;
        drop(handle);

        Ok((segment_id, offset as u32))
    }

    fn check_eviction(&self) -> io::Result<()> {
        let mut total_size = 0;
        let mut segments = Vec::new();
        if let Ok(entries) = self.fs.read_dir(&self.root) {
            for path in entries {
                if path.extension().is_some_and(|ext| ext == "bin")
                    && path.file_name().unwrap() != "index.bin"
                    && let Some(name) = path.file_stem().and_then(|s| s.to_str())
                    && let Ok(id) = name.parse::<u64>()
                {
                    let meta = self.fs.metadata(&path)?;
                    total_size += meta.len;
                    segments.push((id, path));
                }
            }
        }

        if total_size > OPAQUE_TOTAL_MAX_SIZE {
            segments.sort_by_key(|s| s.0);
            for (id, path) in segments {
                if total_size <= OPAQUE_TOTAL_MAX_SIZE {
                    break;
                }

                let lock_path = self.root.join(format!("{:020}.bin.lock", id));
                if self.fs.exists(&lock_path) {
                    continue;
                }

                let len = self.fs.metadata(&path)?.len;
                self.prune_segment(id, &path)?;
                total_size -= len;
            }
        }
        Ok(())
    }

    fn prune_segment(&self, segment_id_to_prune: u64, path: &std::path::Path) -> io::Result<()> {
        let mut handle = self.fs.open(path, false, false, false)?;
        let mut anchors = Vec::new();

        loop {
            let mut len_buf = [0u8; 4];
            if handle.read_exact(&mut len_buf).is_err() {
                break;
            }
            let length = u32::from_le_bytes(len_buf);
            let mut data = vec![0u8; length as usize];
            if handle.read_exact(&mut data).is_err() {
                break;
            }

            if let Ok(wire) = tox_proto::deserialize::<merkle_tox_core::dag::WireNode>(&data) {
                let is_admin = matches!(
                    wire.authentication,
                    merkle_tox_core::dag::NodeAuth::Signature(_)
                );

                let mut is_key_wrap = false;
                if !wire
                    .flags
                    .contains(merkle_tox_core::dag::WireFlags::ENCRYPTED)
                {
                    let mut payload = wire.encrypted_payload.clone();
                    if merkle_tox_core::dag::remove_padding(&mut payload).is_ok() {
                        if wire
                            .flags
                            .contains(merkle_tox_core::dag::WireFlags::COMPRESSED)
                            && let Ok(decompressed) = zstd::decode_all(&payload[..])
                        {
                            payload = decompressed;
                        }

                        if payload.len() >= 40 {
                            let mut cursor = std::io::Cursor::new(&payload[40..]);
                            if let Ok(content) = <merkle_tox_core::dag::Content as tox_proto::ToxDeserialize>::deserialize(&mut cursor, &tox_proto::ToxContext::empty())
                                && matches!(content, merkle_tox_core::dag::Content::KeyWrap { .. })
                            {
                                is_key_wrap = true;
                            }
                        }
                    }
                }

                if is_admin || is_key_wrap {
                    let wire_data =
                        tox_proto::serialize(&wire).map_err(|e| io::Error::other(e.to_string()))?;
                    let hash =
                        merkle_tox_core::dag::NodeHash::from(*blake3::hash(&wire_data).as_bytes());
                    anchors.push((hash, data));
                }
            }
        }
        drop(handle);

        let mut records = self.load_index()?;
        records.retain(|r| r.segment_id != segment_id_to_prune);

        for (hash, data) in anchors {
            let (new_seg_id, new_offset) = self.write_to_newest(&data)?;
            if let Ok(idx) = records.binary_search_by_key(&hash, |r| r.hash) {
                records[idx].segment_id = new_seg_id;
                records[idx].offset = new_offset;
            } else {
                records.push(OpaqueIndexRecord {
                    hash,
                    segment_id: new_seg_id,
                    offset: new_offset,
                });
                records.sort_unstable_by_key(|r| r.hash);
            }
        }

        self.save_index(&records)?;
        self.fs.remove_file(path)?;
        Ok(())
    }

    fn update_index(&self, hash: &NodeHash, segment_id: u64, offset: u32) -> io::Result<()> {
        let mut records = self.load_index()?;
        if let Ok(idx) = records.binary_search_by_key(hash, |r| r.hash) {
            records[idx].segment_id = segment_id;
            records[idx].offset = offset;
        } else {
            records.push(OpaqueIndexRecord {
                hash: *hash,
                segment_id,
                offset,
            });
            records.sort_unstable_by_key(|r| r.hash);
        }
        self.save_index(&records)
    }

    pub fn load_index(&self) -> io::Result<Vec<OpaqueIndexRecord>> {
        if !self.fs.exists(&self.root.join("index.bin")) {
            return Ok(Vec::new());
        }
        let data = self.fs.read(&self.root.join("index.bin"))?;
        let mut records = Vec::with_capacity(data.len() / OpaqueIndexRecord::SIZE);
        for chunk in data.chunks_exact(OpaqueIndexRecord::SIZE) {
            records.push(OpaqueIndexRecord::from_bytes(chunk));
        }
        Ok(records)
    }

    fn save_index(&self, records: &[OpaqueIndexRecord]) -> io::Result<()> {
        let index_path = self.root.join("index.bin");
        let mut data = Vec::with_capacity(records.len() * OpaqueIndexRecord::SIZE);
        let mut buf = [0u8; OpaqueIndexRecord::SIZE];
        for r in records {
            r.to_bytes(&mut buf);
            data.extend_from_slice(&buf);
        }
        let mut tmp_path = index_path.clone();
        tmp_path.set_extension("tmp");
        self.fs.write(&tmp_path, &data)?;
        self.fs.rename(&tmp_path, &index_path)?;
        Ok(())
    }

    pub fn get_node(&self, hash: &NodeHash) -> io::Result<Option<Vec<u8>>> {
        let records = self.load_index()?;
        if let Ok(idx) = records.binary_search_by_key(hash, |r| r.hash) {
            let record = &records[idx];
            let path = self.root.join(format!("{:020}.bin", record.segment_id));
            let mut handle = self.fs.open(&path, false, false, false)?;
            handle.seek(SeekFrom::Start(record.offset as u64))?;

            let mut len_buf = [0u8; 4];
            handle.read_exact(&mut len_buf)?;
            let length = u32::from_le_bytes(len_buf);

            let mut data = vec![0u8; length as usize];
            handle.read_exact(&mut data)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    pub fn remove_node(&self, hash: &NodeHash) -> io::Result<()> {
        let mut records = self.load_index()?;
        if let Ok(idx) = records.binary_search_by_key(hash, |r| r.hash) {
            records.remove(idx);
            self.save_index(&records)?;
        }
        Ok(())
    }
}
