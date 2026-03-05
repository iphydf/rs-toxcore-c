use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::NodeHash;
use merkle_tox_core::vfs::FileSystem;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tox_proto;

pub struct BlobStore<F: FileSystem> {
    root: PathBuf,
    fs: Arc<F>,
}

impl<F: FileSystem> BlobStore<F> {
    pub fn new(root: PathBuf, fs: Arc<F>) -> Self {
        Self { root, fs }
    }

    fn get_blob_path(&self, hash: &NodeHash) -> PathBuf {
        let hex = encode_hex_32(hash.as_bytes());
        self.root.join(&hex[0..2]).join(format!("{}.data", hex))
    }

    fn get_info_path(&self, hash: &NodeHash) -> PathBuf {
        let hex = encode_hex_32(hash.as_bytes());
        self.root.join(&hex[0..2]).join(format!("{}.info", hex))
    }

    pub fn get_info(&self, hash: &NodeHash) -> io::Result<Option<BlobInfo>> {
        let path = self.get_info_path(hash);
        if !self.fs.exists(&path) {
            return Ok(None);
        }
        let data = self.fs.read(&path)?;
        let info = tox_proto::deserialize(&data).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Some(info))
    }

    pub fn put_info(&self, info: &BlobInfo) -> io::Result<()> {
        let path = self.get_info_path(&info.hash);
        if let Some(parent) = path.parent() {
            self.fs.create_dir_all(parent)?;
        }
        let data = tox_proto::serialize(info).map_err(|e| io::Error::other(e.to_string()))?;
        let mut tmp_path = path.clone();
        tmp_path.set_extension("tmp");
        // tmp+rename atomicity with explicit fsyncs: see
        // `merkle-tox-fs/src/state.rs::StateFile::save` for the
        // rationale. The write-tmp-then-rename shape isn't durable
        // without barriers between the data and metadata writes.
        {
            let mut handle = self.fs.open(&tmp_path, true, true, true)?;
            handle.write_all(&data)?;
            handle.sync_data()?;
        }
        self.fs.rename(&tmp_path, &path)?;
        if let Some(parent) = path.parent() {
            self.fs.sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn put_chunk(&self, hash: &NodeHash, offset: u64, data: &[u8]) -> io::Result<()> {
        let path = self.get_blob_path(hash);
        if let Some(parent) = path.parent() {
            self.fs.create_dir_all(parent)?;
        }
        let mut handle = self.fs.open(&path, true, true, false)?;
        handle.seek(SeekFrom::Start(offset))?;
        handle.write_all(data)?;
        Ok(())
    }

    pub fn get_chunk(&self, hash: &NodeHash, offset: u64, length: u32) -> io::Result<Vec<u8>> {
        let path = self.get_blob_path(hash);
        let mut handle = self.fs.open(&path, false, false, false)?;
        handle.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length as usize];
        handle.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Mark a fully-received blob as Available. Chunk-boundary Merkle
    /// verification already happened in the BlobData receive path (see
    /// doc/merkle-tox-cas.md §3), so finalize is just a status update.
    /// Returns NotFound if there is no BlobInfo on record for `hash`.
    pub fn finalize(&self, hash: &NodeHash) -> io::Result<()> {
        let mut info = self
            .get_info(hash)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob info not found"))?;
        info.status = BlobStatus::Available;
        let num_chunks = info.size.div_ceil(CHUNK_SIZE);
        let mask_size = (num_chunks as usize).div_ceil(8);
        let mut mask = vec![0u8; mask_size];
        for i in 0..num_chunks {
            mask[(i / 8) as usize] |= 1 << (i % 8);
        }
        info.received_mask = Some(mask);
        self.put_info(&info)?;
        Ok(())
    }
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
