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

    fn get_bao_path(&self, hash: &NodeHash) -> PathBuf {
        let hex = encode_hex_32(hash.as_bytes());
        self.root.join(&hex[0..2]).join(format!("{}.bao", hex))
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
        self.fs.write(&tmp_path, &data)?;
        self.fs.rename(&tmp_path, &path)?;
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

    pub fn get_chunk_with_proof(
        &self,
        hash: &NodeHash,
        offset: u64,
        length: u32,
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let blob_path = self.get_blob_path(hash);
        let outboard_path = self.get_bao_path(hash);

        let blob_data = self.fs.read(&blob_path)?;
        let outboard_data = match self.fs.read(&outboard_path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut raw_data = vec![0u8; length as usize];
                raw_data.copy_from_slice(
                    &blob_data[offset as usize..(offset + length as u64) as usize],
                );
                return Ok((raw_data, Vec::new()));
            }
            Err(e) => return Err(e),
        };

        let mut slice = Vec::new();
        let mut extractor = bao::encode::SliceExtractor::new_outboard(
            std::io::Cursor::new(&blob_data),
            std::io::Cursor::new(&outboard_data),
            offset,
            length as u64,
        );
        extractor.read_to_end(&mut slice)?;

        let mut raw_data = vec![0u8; length as usize];
        raw_data.copy_from_slice(&blob_data[offset as usize..(offset + length as u64) as usize]);

        Ok((raw_data, slice))
    }

    pub fn finalize(&self, hash: &NodeHash) -> io::Result<()> {
        let data_path = self.get_blob_path(hash);
        let data = self.fs.read(&data_path)?;
        let (outboard, root) = bao::encode::outboard(&data);

        let bao_path = self.get_bao_path(hash);
        self.fs.write(&bao_path, &outboard)?;

        if let Some(mut info) = self.get_info(hash)? {
            info.status = BlobStatus::Available;
            info.bao_root = Some(root.into());
            let num_chunks = info.size.div_ceil(CHUNK_SIZE);
            let mask_size = (num_chunks as usize).div_ceil(8);
            let mut mask = vec![0u8; mask_size];
            for i in 0..num_chunks {
                mask[(i / 8) as usize] |= 1 << (i % 8);
            }
            info.received_mask = Some(mask);
            self.put_info(&info)?;
        }
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
