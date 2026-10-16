//! The tox-proto encoding of the types other protocols carry: keys and IDs
//! as `bin`, message types as their values in tox.h.

use std::io::{Read, Write};

use tox_proto::{Result, ToxDeserialize, ToxSerialize, ToxSize};

use crate::types::{ConferenceId, FileId, GroupChatId, MessageType, PublicKey};

macro_rules! impl_bytes {
    ($($name:ident),*) => {$(
        impl ToxSize for $name {}

        impl ToxSerialize for $name {
            fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
                self.0.serialize(writer)
            }
        }

        impl ToxDeserialize for $name {
            fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
                ToxDeserialize::deserialize(reader).map(Self)
            }
        }
    )*};
}

impl_bytes!(ConferenceId, FileId, GroupChatId, PublicKey);

const NORMAL: u8 = 0;
const ACTION: u8 = 1;

impl ToxSize for MessageType {}

impl ToxSerialize for MessageType {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            MessageType::TOX_MESSAGE_TYPE_NORMAL => NORMAL,
            MessageType::TOX_MESSAGE_TYPE_ACTION => ACTION,
        }
        .serialize(writer)
    }
}

impl ToxDeserialize for MessageType {
    /// Kinds this version doesn't know read as normal messages.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(match u8::deserialize(reader)? {
            ACTION => MessageType::TOX_MESSAGE_TYPE_ACTION,
            _ => MessageType::TOX_MESSAGE_TYPE_NORMAL,
        })
    }
}
