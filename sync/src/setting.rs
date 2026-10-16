//! Settings: what the account chooses for itself or its conversations, the
//! same on every device of it, as account-sync.md defines them.

use tox_proto::ToxProto;
pub use tox_proto::{Kept, Variant};

use crate::event::GraphId;

/// The longest a setting's encoding may be, as every device keeps them all.
pub const MAX_SETTING: usize = 1024;

/// What a setting applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToxProto)]
#[repr(u8)]
pub enum Scope {
    Account = 0,
    /// One of the account's conversations, by its graph.
    Conversation(GraphId) = 1,
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// Each variant's discriminant is its kind on the wire; a scope has at most
/// one setting of each kind.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[tox(lenient)]
#[repr(u8)]
pub enum Setting {
    Mute(Mute) = 0,
    PictureFormat(PictureFormat) = 1,
    /// Of a kind this version doesn't know, or that doesn't decode: kept and
    /// passed on, but not acted on.
    #[tox(catch_all)]
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

/// Whether `setting`'s encoding is at most `MAX_SETTING` bytes.
pub fn fits(setting: &Kept<Setting>) -> bool {
    tox_proto::serialize(setting).is_ok_and(|bytes| bytes.len() <= MAX_SETTING)
}

/// The conversation doesn't notify until `until`, in ms since the Unix
/// epoch, or ever where it's none, but for messages naming the account where
/// `mentions`.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub struct Mute {
    pub until: Option<u64>,
    pub mentions: bool,
}

/// Pictures sent in the conversation are encoded as `format`.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
pub struct PictureFormat {
    pub format: PictureEncoding,
}

/// How pictures sent in a conversation are encoded.
#[derive(Debug, Clone, PartialEq, Eq, ToxProto)]
#[repr(u8)]
pub enum PictureEncoding {
    /// As they were taken or chosen.
    Original = 0,
    /// As lossless QOI.
    Qoi = 1,
    #[tox(catch_all)]
    Unknown { discriminant: u32, data: Vec<u8> },
}
