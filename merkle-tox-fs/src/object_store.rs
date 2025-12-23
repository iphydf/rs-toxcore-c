use merkle_tox_core::dag::Hash;
use merkle_tox_core::vfs::FileSystem;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

pub struct ObjectStore<F: FileSystem> {
    root: PathBuf,
    fs: Arc<F>,
}

impl<F: FileSystem> ObjectStore<F> {
    pub fn new(root: PathBuf, fs: Arc<F>) -> Self {
        Self { root, fs }
    }

    pub fn get_path(&self, hash: &Hash, verified: bool) -> PathBuf {
        let sub = if verified { "verified" } else { "speculative" };
        let hash_hex = encode_hex_32(hash);
        self.root.join(sub).join(&hash_hex[0..2]).join(hash_hex)
    }

    pub fn init(&self) -> io::Result<()> {
        self.fs.create_dir_all(&self.root.join("verified"))?;
        self.fs.create_dir_all(&self.root.join("speculative"))?;
        Ok(())
    }
}

pub fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}
