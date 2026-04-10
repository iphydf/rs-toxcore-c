use crate::cas::{BlobInfo, BlobStatus};
use crate::dag::NodeHash;

pub fn create_blob_info(hash: NodeHash, size: u64) -> BlobInfo {
    BlobInfo {
        hash,
        size,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    }
}

pub fn create_available_blob_info(hash: NodeHash, size: u64) -> BlobInfo {
    BlobInfo {
        hash,
        size,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    }
}
