//! The messages two devices exchange in a sync session.

use crate::event::{BlobId, EventId, GraphId};
use crate::fact::{Subject, Value};
use sha2::{Digest, Sha256};
use tox_proto::ToxProto;
use toxcore::types::PublicKey;

pub use crate::event::DecodeError;

pub const VERSION: u64 = 1;

/// The Tox file kind a blob is sent as, after the sync packet ID.
pub const BLOB_FILE_KIND: u32 = crate::frame::PACKET_ID as u32;

/// What a device offers, sent in `Hello`. Unknown bits are kept, so a
/// newer device's features pass through unharmed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ToxProto)]
#[tox(flat)]
pub struct Features(u64);

impl Features {
    pub const NONE: Self = Self(0);
    pub const ACCOUNT_SYNC: Self = Self(1);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Equal on two devices exactly when they have the same heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToxProto)]
#[tox(flat)]
pub struct HeadsDigest(pub [u8; 32]);

impl HeadsDigest {
    pub fn of(heads: &[EventId]) -> Self {
        let mut heads = heads.to_vec();
        heads.sort();
        let mut hash = Sha256::new();
        for head in heads {
            hash.update(head.0);
        }
        Self(hash.finalize().into())
    }
}

/// What a device asks of a friend's call.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum CallAction {
    /// Answers it, or places it, and has the home device call this device
    /// once it's connected.
    Connect { video: bool } = 0,
    /// Ends it, or declines it while it rings.
    HangUp = 1,
    #[tox(catch_all)]
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Each variant's discriminant is its tag on the wire.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum SessionMessage {
    Hello {
        version: u64,
        features: Features,
    } = 0,
    Summary(Vec<(GraphId, HeadsDigest)>) = 1,
    Heads {
        graph: GraphId,
        heads: Vec<EventId>,
    } = 2,
    Want(Vec<EventId>) = 3,
    /// Encoded events, as stored.
    Events(Vec<Vec<u8>>) = 4,
    /// Asks for up to `limit` ancestors of `before`, newest first.
    History {
        graph: GraphId,
        before: Vec<EventId>,
        limit: u64,
    } = 5,
    /// Asks for a blob, sent as a file transfer whose file ID is the blob's.
    WantBlob(BlobId) = 6,
    NoBlob(BlobId) = 7,
    /// Live facts, which aren't stored: with `all`, every one there is.
    Facts {
        facts: Vec<(Subject, Value)>,
        all: bool,
    } = 8,
    /// From a device, about the account's call with `friend`.
    Call {
        friend: PublicKey,
        action: CallAction,
    } = 9,
    /// From a newer version, which this one ignores.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

impl SessionMessage {
    pub fn hello(features: Features) -> Self {
        Self::Hello {
            version: VERSION,
            features,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        tox_proto::serialize(self).expect("session messages always encode")
    }

    /// `Ok(None)` for messages this version doesn't know.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        Ok(match tox_proto::deserialize_exact(bytes)? {
            Self::Unknown { .. } => None,
            message => Some(message),
        })
    }
}
