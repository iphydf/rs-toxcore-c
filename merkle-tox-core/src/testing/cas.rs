use crate::cas::{BlobData, BlobInfo, BlobStatus};
use crate::dag::NodeHash;

pub fn create_blob_info(hash: NodeHash, size: u64) -> BlobInfo {
    BlobInfo {
        hash,
        size,
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
    }
}

pub fn create_available_blob_info(hash: NodeHash, size: u64) -> BlobInfo {
    BlobInfo {
        hash,
        size,
        bao_root: None,
        status: BlobStatus::Available,
        received_mask: None,
    }
}

pub fn create_blob_data(hash: NodeHash, offset: u64, data: Vec<u8>) -> BlobData {
    BlobData {
        hash,
        offset,
        data,
        proof: vec![],
    }
}
