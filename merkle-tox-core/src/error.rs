use crate::dag::{ConversationId, NodeHash, PhysicalDevicePk, ValidationError};
use crate::identity::IdentityError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleToxError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] tox_proto::Error),
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Permission denied for {pk:?}: required bits {required:08x}, actual {actual:08x}")]
    PermissionDenied {
        pk: PhysicalDevicePk,
        required: u32,
        actual: u32,
    },
    #[error("Node not found: {0:?}")]
    NodeNotFound(NodeHash),
    #[error("Conversation key not found for {0:?} epoch {1}")]
    KeyNotFound(ConversationId, u64),
    #[error("Blob not found: {0:?}")]
    BlobNotFound(NodeHash),
    #[error("Ratchet error: {0}")]
    Ratchet(String),
    #[error("Reconciliation error: {0}")]
    Reconciliation(String),
    #[error("Node quarantined: {0:?}")]
    Quarantined(NodeHash),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub type MerkleToxResult<T> = Result<T, MerkleToxError>;
