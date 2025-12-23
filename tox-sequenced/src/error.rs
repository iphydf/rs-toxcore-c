use thiserror::Error;

/// Errors that can occur in the sequenced reliable transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SequencedError {
    #[error("Message too large")]
    MessageTooLarge,
    /// Serialization failed. Stored as a string because underlying errors may not be Clone/Eq.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Outgoing queue full")]
    QueueFull,
    #[error("Invalid fragment index")]
    InvalidFragmentIndex,
    #[error("Invalid MTU size")]
    InvalidMtu,
    #[error("Invalid total fragments count")]
    InvalidTotalFragments,
}
