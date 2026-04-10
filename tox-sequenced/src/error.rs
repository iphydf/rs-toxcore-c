use thiserror::Error;

/// Errors that can occur in the sequenced transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SequencedError {
    #[error("Datagram too large (exceeds MAX_DATAGRAM_SIZE)")]
    DatagramTooLarge,
    #[error("Message too large for fragmentation (exceeds MAX_FRAGMENT_MESSAGE)")]
    MessageTooLarge,
    /// Serialization failed. Stored as a string because underlying errors may not be Clone/Eq.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Send window full")]
    WindowFull,
}
