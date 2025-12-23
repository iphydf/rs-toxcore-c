use std::io::{Read, Write};
use std::sync::Arc;

pub mod constants;
pub use rmp;
pub use tox_proto_derive::{ToxDeserialize, ToxProto, ToxSerialize};

extern crate self as tox_proto;

#[macro_export]
macro_rules! merkle_tox_newtype {
    ($name:ident, $inner:ty, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, $crate::ToxProto, PartialOrd, Ord)]
        pub struct $name($inner);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for byte in self.0.as_ref() {
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, ")")
            }
        }

        impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl AsRef<$inner> for $name {
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        impl $name {
            pub fn as_bytes(&self) -> &$inner {
                &self.0
            }
        }
    };

    ($name:ident, $inner:ty, $doc:expr, secret) => {
        #[doc = $doc]
        #[derive(
            Clone,
            PartialEq,
            Eq,
            Hash,
            $crate::ToxProto,
            PartialOrd,
            Ord,
            ::zeroize::Zeroize,
            ::zeroize::ZeroizeOnDrop,
        )]
        pub struct $name($inner);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}([REDACTED])", stringify!($name))
            }
        }

        impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl AsRef<$inner> for $name {
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        impl $name {
            pub fn as_bytes(&self) -> &$inner {
                &self.0
            }
        }
    };
}

merkle_tox_newtype!(NodeHash, [u8; 32], "Identifies a specific Merkle Node.");
merkle_tox_newtype!(
    ConversationId,
    [u8; 32],
    "Identifies a specific Merkle-Tox conversation (Genesis node hash)."
);
merkle_tox_newtype!(
    LogicalIdentityPk,
    [u8; 32],
    "The Ed25519 public key of the user (Master PK)."
);
merkle_tox_newtype!(
    PhysicalDevicePk,
    [u8; 32],
    "The Ed25519 public key of a specific device (Tox ID)."
);
merkle_tox_newtype!(EphemeralX25519Pk, [u8; 32], "Short-lived keys for X3DH.");
merkle_tox_newtype!(
    ShardHash,
    [u8; 32],
    "A hash of a range of nodes in a sync shard."
);
merkle_tox_newtype!(PowNonce, [u8; 32], "A proof-of-work challenge nonce.");

merkle_tox_newtype!(
    LogicalIdentitySk,
    [u8; 32],
    "The Ed25519 secret key of the user.",
    secret
);
merkle_tox_newtype!(
    PhysicalDeviceSk,
    [u8; 32],
    "The Ed25519 secret key of a specific device.",
    secret
);
merkle_tox_newtype!(
    PhysicalDeviceDhSk,
    [u8; 32],
    "The X25519 secret key (scalar) of a specific device.",
    secret
);
merkle_tox_newtype!(
    EphemeralX25519Sk,
    [u8; 32],
    "Short-lived secret keys for X3DH.",
    secret
);

merkle_tox_newtype!(
    KConv,
    [u8; 32],
    "The conversation root key (epoch key).",
    secret
);
merkle_tox_newtype!(
    ChainKey,
    [u8; 32],
    "The current ratchet state (chain key).",
    secret
);
merkle_tox_newtype!(
    MessageKey,
    [u8; 32],
    "A key derived from a ratchet for a single message.",
    secret
);
merkle_tox_newtype!(
    SharedSecretKey,
    [u8; 32],
    "A shared secret derived from DH (e.g. X3DH).",
    secret
);
merkle_tox_newtype!(
    EncryptionKey,
    [u8; 32],
    "A symmetric encryption key.",
    secret
);
merkle_tox_newtype!(
    MacKey,
    [u8; 32],
    "A key for message authentication codes.",
    secret
);

merkle_tox_newtype!(
    NodeMac,
    [u8; 32],
    "A message authentication code for a Merkle node."
);
merkle_tox_newtype!(Ed25519Signature, [u8; 64], "An Ed25519 signature.");

impl From<NodeHash> for ConversationId {
    fn from(hash: NodeHash) -> Self {
        Self(hash.0)
    }
}

impl ConversationId {
    /// Semantically converts a Conversation ID to a Node Hash.
    /// A conversation ID is defined as the hash of its genesis node.
    pub fn to_node_hash(&self) -> NodeHash {
        NodeHash(self.0)
    }
}

impl LogicalIdentityPk {
    /// Semantically converts a Master Identity PK to a Physical Device PK.
    /// Used when a master identity acts as its own root device.
    pub fn to_physical(&self) -> PhysicalDevicePk {
        PhysicalDevicePk(self.0)
    }
}

impl PhysicalDevicePk {
    /// Semantically converts a Physical Device PK to a Logical Identity PK.
    /// This assumes the device PK is bit-compatible with the logical identity PK it represents.
    pub fn to_logical(&self) -> LogicalIdentityPk {
        LogicalIdentityPk(self.0)
    }
}

impl PhysicalDeviceSk {
    /// Semantically converts a Physical Device Secret Key to a Logical Identity Secret Key.
    pub fn to_logical(&self) -> LogicalIdentitySk {
        LogicalIdentitySk(self.0)
    }
}

impl KConv {
    /// Semantically converts a Conversation Key to a Chain Key.
    /// Used when initializing a new ratchet from a conversation root key.
    pub fn to_chain_key(&self) -> ChainKey {
        ChainKey(self.0)
    }
}

impl ChainKey {
    /// Semantically converts a Chain Key to a Conversation Key.
    /// This is used during rekeying processes where the current ratchet state becomes the new root.
    pub fn to_conversation_key(&self) -> KConv {
        KConv(self.0)
    }
}

impl NodeHash {
    /// Semantically converts a Node Hash to a Conversation ID.
    /// A conversation ID is defined as the hash of its genesis node.
    pub fn to_conversation_id(&self) -> ConversationId {
        ConversationId(self.0)
    }
}

pub trait TimeProvider: Send + Sync + std::fmt::Debug {
    fn now_instant(&self) -> std::time::Instant;
    fn now_system_ms(&self) -> i64;
}

impl ToxSize for Arc<dyn TimeProvider> {}
impl ToxSerialize for Arc<dyn TimeProvider> {
    fn serialize<W: Write>(&self, _writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        Ok(())
    }
}

impl ToxDeserialize for Arc<dyn TimeProvider> {
    fn deserialize<R: Read>(_reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        ctx.time_provider
            .clone()
            .ok_or_else(|| Error::Deserialize("TimeProvider missing in context".to_string()))
    }
}

#[derive(Debug)]
pub struct SystemTimeProvider;

impl ToxSize for SystemTimeProvider {}
impl ToxSerialize for SystemTimeProvider {
    fn serialize<W: Write>(&self, _writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        Ok(())
    }
}

impl TimeProvider for SystemTimeProvider {
    fn now_instant(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn now_system_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as i64
    }
}

pub struct ToxContext {
    pub time_provider: Option<Arc<dyn TimeProvider>>,
}

impl ToxContext {
    pub fn new(time_provider: Arc<dyn TimeProvider>) -> Self {
        Self {
            time_provider: Some(time_provider),
        }
    }

    pub fn empty() -> Self {
        Self {
            time_provider: None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Deserialize error: {0}")]
    Deserialize(String),
    #[error("Serialize error: {0}")]
    Serialize(String),
}

pub trait ToxSize {
    const SIZE: Option<usize> = None;
    const IS_BYTE_LIKE: bool = false;
    fn flat_len(&self) -> usize {
        Self::SIZE.expect("flat_len called on dynamic type")
    }
}

pub trait ToxSerialize: ToxSize {
    /// Serializes the type into a MessagePack binary stream using positional arrays.
    ///
    /// # Serialization Rules
    ///
    /// To ensure maximum wire efficiency and compatibility with the Merkle-Tox
    /// wire format, `ToxProto` follows these rules:
    ///
    /// 1. **Structs**: Serialized as a MessagePack array of length `N` (number of fields).
    ///    Example: `struct S { a: u32, b: u32 }` -> `[a, b]`
    ///
    /// 2. **Enums**: Serialized as a 2-element nested array: `[variant_tag, payload]`.
    ///    - **Multi-field variants**: `payload` is an array: `[tag, [f0, f1, ...]]`.
    ///    - **Single-field variants**: `payload` is the field: `[tag, f0]`.
    ///    - **Unit variants**: Serialized as a naked integer (the tag).
    ///
    /// 3. **Flat Structs**: `#[tox(flat)]` skips the array header (Transparent Wrapping).
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()>;

    #[inline]
    fn serialize_flat<W: Write>(&self, _writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        Err(Error::Serialize(
            "Type does not support flat serialization".into(),
        ))
    }
}

pub trait ToxDeserialize: Sized + ToxSize {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self>;

    #[inline]
    fn deserialize_flat<R: Read>(_reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        Err(Error::Deserialize(
            "Type does not support flat deserialization".into(),
        ))
    }
}

impl<T: ToxSize + ?Sized> ToxSize for &T {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for &T {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (*self).serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (*self).serialize_flat(writer, ctx)
    }
}

impl ToxSize for str {}
impl ToxSerialize for str {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_str(writer, self).map_err(|e| Error::Serialize(e.to_string()))
    }
}

impl<T: ToxSize + ?Sized> ToxSize for Box<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for Box<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (**self).serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (**self).serialize_flat(writer, ctx)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Box<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Box::new(T::deserialize(reader, ctx)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Box::new(T::deserialize_flat(reader, ctx)?))
    }
}

impl<T: ToxSize + ?Sized> ToxSize for Arc<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for Arc<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (**self).serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        (**self).serialize_flat(writer, ctx)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Arc<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Arc::new(T::deserialize(reader, ctx)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(Arc::new(T::deserialize_flat(reader, ctx)?))
    }
}

/// Helper to skip a single MessagePack value from the reader.
pub fn skip_value<R: Read>(reader: &mut R) -> Result<()> {
    use rmp::Marker;
    let marker =
        rmp::decode::read_marker(reader).map_err(|e| Error::Deserialize(format!("{:?}", e)))?;
    match marker {
        Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::True | Marker::False => {}
        Marker::U8 | Marker::I8 => {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
        }
        Marker::U16 | Marker::I16 => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
        }
        Marker::U32 | Marker::I32 | Marker::F32 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
        }
        Marker::U64 | Marker::I64 | Marker::F64 => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixStr(len) => {
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf)?;
        }
        Marker::Str8 | Marker::Bin8 => {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf)?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
        }
        Marker::Str16 | Marker::Bin16 => {
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
        }
        Marker::Str32 | Marker::Bin32 => {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixArray(len) => {
            for _ in 0..len {
                skip_value(reader)?;
            }
        }
        Marker::Array16 => {
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf);
            for _ in 0..len {
                skip_value(reader)?;
            }
        }
        Marker::Array32 => {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf);
            for _ in 0..len {
                skip_value(reader)?;
            }
        }
        Marker::FixMap(len) => {
            for _ in 0..len * 2 {
                skip_value(reader)?;
            }
        }
        Marker::Map16 => {
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf);
            for _ in 0..len * 2 {
                skip_value(reader)?;
            }
        }
        Marker::Map32 => {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf);
            for _ in 0..len * 2 {
                skip_value(reader)?;
            }
        }
        Marker::FixExt1 => {
            let mut buf = [0u8; 1 + 1];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixExt2 => {
            let mut buf = [0u8; 1 + 2];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixExt4 => {
            let mut buf = [0u8; 1 + 4];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixExt8 => {
            let mut buf = [0u8; 1 + 8];
            reader.read_exact(&mut buf)?;
        }
        Marker::FixExt16 => {
            let mut buf = [0u8; 1 + 16];
            reader.read_exact(&mut buf)?;
        }
        Marker::Ext8 => {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf)?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; 1 + len];
            reader.read_exact(&mut buf)?;
        }
        Marker::Ext16 => {
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf)?;
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; 1 + len];
            reader.read_exact(&mut buf)?;
        }
        Marker::Ext32 => {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; 1 + len];
            reader.read_exact(&mut buf)?;
        }
        Marker::Reserved => {
            return Err(Error::Deserialize(
                "Reserved marker encountered".to_string(),
            ));
        }
    }
    Ok(())
}

/// Helper to read an enum header, supporting both naked discriminators and array-wrapped variants.
pub fn read_enum_header<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<(u8, u32)> {
    use rmp::Marker;
    let marker =
        rmp::decode::read_marker(reader).map_err(|e| Error::Deserialize(format!("{:?}", e)))?;
    match marker {
        Marker::FixPos(idx) => Ok((idx, 1)),
        Marker::U8 => {
            let idx =
                rmp::decode::read_u8(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
            Ok((idx, 1))
        }
        Marker::FixArray(len) => {
            let idx = u8::deserialize(reader, ctx)?;
            Ok((idx, len as u32))
        }
        Marker::Array16 => {
            let len =
                rmp::decode::read_u16(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
            let idx = u8::deserialize(reader, ctx)?;
            Ok((idx, len as u32))
        }
        Marker::Array32 => {
            let len =
                rmp::decode::read_u32(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
            let idx = u8::deserialize(reader, ctx)?;
            Ok((idx, len))
        }
        _ => Err(Error::Deserialize(format!(
            "Unexpected marker for enum: {:?}",
            marker
        ))),
    }
}

impl<T: ToxSize> ToxSize for std::sync::Mutex<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize> ToxSerialize for std::sync::Mutex<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.lock()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.lock()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize_flat(writer, ctx)
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::sync::Mutex<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(std::sync::Mutex::new(T::deserialize(reader, ctx)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(std::sync::Mutex::new(T::deserialize_flat(reader, ctx)?))
    }
}

impl<T: ToxSize> ToxSize for std::sync::RwLock<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize> ToxSerialize for std::sync::RwLock<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.read()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.read()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize_flat(writer, ctx)
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::sync::RwLock<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(std::sync::RwLock::new(T::deserialize(reader, ctx)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        Ok(std::sync::RwLock::new(T::deserialize_flat(reader, ctx)?))
    }
}

// Primitives
macro_rules! impl_rmp_int {
    ($ty:ty, $encoder:ident, $decoder:ident) => {
        impl ToxSize for $ty {
            const SIZE: Option<usize> = Some(std::mem::size_of::<$ty>());
        }
        impl ToxSerialize for $ty {
            fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
                rmp::encode::$encoder(writer, *self as _)
                    .map(|_| ())
                    .map_err(|e| Error::Serialize(e.to_string()))
            }
            #[inline]
            fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
                writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
            }
        }
        impl ToxDeserialize for $ty {
            fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
                rmp::decode::$decoder(reader).map_err(|e| Error::Deserialize(e.to_string()))
            }
            #[inline]
            fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
                let mut buf = [0u8; std::mem::size_of::<$ty>()];
                reader.read_exact(&mut buf).map_err(Error::Io)?;
                Ok(<$ty>::from_be_bytes(buf))
            }
        }
    };
}

impl ToxSize for u8 {
    const SIZE: Option<usize> = Some(1);
    const IS_BYTE_LIKE: bool = true;
}

impl ToxSerialize for u8 {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_uint(writer, *self as u64)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(&[*self]).map_err(Error::Io)
    }
}

impl ToxDeserialize for u8 {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        rmp::decode::read_int(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(buf[0])
    }
}
impl_rmp_int!(u16, write_uint, read_int);
impl_rmp_int!(u32, write_uint, read_int);
impl_rmp_int!(u64, write_uint, read_int);
impl_rmp_int!(usize, write_uint, read_int);
impl_rmp_int!(i8, write_sint, read_int);
impl_rmp_int!(i16, write_sint, read_int);
impl_rmp_int!(i32, write_sint, read_int);
impl_rmp_int!(i64, write_sint, read_int);
impl_rmp_int!(isize, write_sint, read_int);

impl ToxSize for f32 {
    const SIZE: Option<usize> = Some(4);
}
impl ToxSerialize for f32 {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_f32(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for f32 {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        rmp::decode::read_f32(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(f32::from_be_bytes(buf))
    }
}

impl ToxSize for f64 {
    const SIZE: Option<usize> = Some(8);
}
impl ToxSerialize for f64 {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_f64(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for f64 {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        rmp::decode::read_f64(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(f64::from_be_bytes(buf))
    }
}

impl ToxSize for char {
    const SIZE: Option<usize> = Some(4);
}
impl ToxSerialize for char {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_uint(writer, *self as u64)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer
            .write_all(&(*self as u32).to_be_bytes())
            .map_err(Error::Io)
    }
}

impl ToxDeserialize for char {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let u = rmp::decode::read_int::<u32, _>(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))?;
        std::char::from_u32(u).ok_or_else(|| Error::Deserialize(format!("Invalid char: {}", u)))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        let u = u32::from_be_bytes(buf);
        std::char::from_u32(u).ok_or_else(|| Error::Deserialize(format!("Invalid char: {}", u)))
    }
}

impl ToxSize for bool {
    const SIZE: Option<usize> = Some(1);
}
impl ToxSerialize for bool {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_bool(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer
            .write_all(&[if *self { 1 } else { 0 }])
            .map_err(Error::Io)
    }
}
impl ToxDeserialize for bool {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        rmp::decode::read_bool(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(buf[0] != 0)
    }
}

impl ToxSize for u128 {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for u128 {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_bin(writer, &self.to_le_bytes())
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(&self.to_le_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for u128 {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let len =
            rmp::decode::read_bin_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len != 16 {
            return Err(Error::Deserialize("Invalid u128 length".to_string()));
        }
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf)?;
        Ok(u128::from_le_bytes(buf))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(u128::from_le_bytes(buf))
    }
}
impl ToxSize for i128 {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for i128 {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_bin(writer, &self.to_le_bytes())
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(&self.to_le_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for i128 {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let len =
            rmp::decode::read_bin_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len != 16 {
            return Err(Error::Deserialize("Invalid i128 length".to_string()));
        }
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf)?;
        Ok(i128::from_le_bytes(buf))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(i128::from_le_bytes(buf))
    }
}

// Strings and Byte Arrays
impl ToxSize for String {
    const IS_BYTE_LIKE: bool = true;
    fn flat_len(&self) -> usize {
        self.len()
    }
}
impl ToxSerialize for String {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_str(writer, self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        writer.write_all(self.as_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for String {
    fn deserialize<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let len =
            rmp::decode::read_str_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        String::from_utf8(buf).map_err(|e| Error::Deserialize(e.to_string()))
    }
}

impl ToxSize for [u8] {}
impl ToxSerialize for [u8] {
    fn serialize<W: Write>(&self, writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_bin(writer, self)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
}

impl<T: ToxSize> ToxSize for Vec<T> {
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
    fn flat_len(&self) -> usize {
        if let Some(item_size) = T::SIZE {
            self.len() * item_size
        } else {
            panic!("flat_len called on dynamic Vec")
        }
    }
}
impl<T: ToxSerialize> ToxSerialize for Vec<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        if T::SIZE == Some(1) {
            let ptr = self.as_ptr() as *const u8;
            let slice = unsafe { std::slice::from_raw_parts(ptr, self.len()) };
            rmp::encode::write_bin(writer, slice)
                .map(|_| ())
                .map_err(|e| Error::Serialize(e.to_string()))?;
            return Ok(());
        }
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        if T::SIZE.is_some() {
            for item in self {
                item.serialize_flat(writer, ctx)?;
            }
            Ok(())
        } else {
            Err(Error::Serialize(
                "Vec item must have fixed size for flat serialization".into(),
            ))
        }
    }
}
impl<T: ToxDeserialize> ToxDeserialize for Vec<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        if T::SIZE == Some(1) {
            let len =
                rmp::decode::read_bin_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
            let mut vec = vec![0u8; len as usize];
            reader.read_exact(&mut vec)?;
            return Ok(unsafe { std::mem::transmute::<Vec<u8>, Vec<T>>(vec) });
        }
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        let mut vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            vec.push(T::deserialize(reader, ctx)?);
        }
        Ok(vec)
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        if T::SIZE == Some(1) {
            let mut vec = Vec::new();
            reader.read_to_end(&mut vec)?;
            return Ok(unsafe { std::mem::transmute::<Vec<u8>, Vec<T>>(vec) });
        }
        if T::SIZE.is_some() {
            let mut vec = Vec::new();
            while let Ok(item) = T::deserialize_flat(reader, ctx) {
                vec.push(item);
            }
            Ok(vec)
        } else {
            Err(Error::Deserialize(
                "Vec item must have fixed size for flat deserialization".into(),
            ))
        }
    }
}

impl<T: ToxSize, const N: usize> ToxSize for smallvec::SmallVec<T, N> {}
impl<T: ToxSerialize, const N: usize> ToxSerialize for smallvec::SmallVec<T, N> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
}
impl<T: ToxDeserialize, const N: usize> ToxDeserialize for smallvec::SmallVec<T, N> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut vec = smallvec::SmallVec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::deserialize(reader, ctx)?);
        }
        Ok(vec)
    }
}

impl<T: ToxSize> ToxSize for std::collections::VecDeque<T> {}
impl<T: ToxSerialize> ToxSerialize for std::collections::VecDeque<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::collections::VecDeque<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut deque = std::collections::VecDeque::with_capacity(len);
        for _ in 0..len {
            deque.push_back(T::deserialize(reader, ctx)?);
        }
        Ok(deque)
    }
}

impl<T: ToxSize, const N: usize> ToxSize for [T; N] {
    const SIZE: Option<usize> = match T::SIZE {
        Some(s) => Some(s * N),
        None => None,
    };
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize, const N: usize> ToxSerialize for [T; N] {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        // Specialization: Use bin for [u8; N]
        if T::SIZE == Some(1) {
            let ptr = self.as_ptr() as *const u8;
            let slice = unsafe { std::slice::from_raw_parts(ptr, N) };
            rmp::encode::write_bin(writer, slice)
                .map(|_| ())
                .map_err(|e| Error::Serialize(e.to_string()))?;
            return Ok(());
        }
        rmp::encode::write_array_len(writer, N as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        for item in self {
            item.serialize_flat(writer, ctx)?;
        }
        Ok(())
    }
}
impl<T: ToxDeserialize, const N: usize> ToxDeserialize for [T; N] {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        if T::SIZE == Some(1) {
            let len =
                rmp::decode::read_bin_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
            if len as usize != N {
                return Err(Error::Deserialize(format!(
                    "Binary length mismatch: expected {}, got {}",
                    N, len
                )));
            }
            let mut buf = [0u8; N];
            reader.read_exact(&mut buf)?;
            // This is safe because we know T is u8
            return Ok(unsafe { std::mem::transmute_copy::<[u8; N], [T; N]>(&buf) });
        }
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len as usize != N {
            return Err(Error::Deserialize(format!(
                "Array length mismatch: expected {}, got {}",
                N, len
            )));
        }
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::deserialize(reader, ctx)?);
        }
        vec.try_into()
            .map_err(|_| Error::Deserialize("Array conversion failed".to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::deserialize_flat(reader, ctx)?);
        }
        vec.try_into()
            .map_err(|_| Error::Deserialize("Array conversion failed".to_string()))
    }
}

macro_rules! count_tuple_elements {
    ($($ty:ident),*) => {
        <[()]>::len(&[$(count_tuple_elements!(@sub $ty)),*])
    };
    (@sub $ty:ident) => { () };
}

macro_rules! sum_sizes {
    () => { Some(0) };
    ($head:ident $(, $tail:ident)*) => {
        match ($head::SIZE, sum_sizes!($($tail),*)) {
            (Some(s1), Some(s2)) => Some(s1 + s2),
            _ => None,
        }
    };
}

macro_rules! impl_tox_tuple {
    ($($ty:ident),*) => {
        impl<$($ty: ToxSize),*> ToxSize for ($($ty,)*) {
            const SIZE: Option<usize> = sum_sizes!($($ty),*);
            const IS_BYTE_LIKE: bool = true $(&& $ty::IS_BYTE_LIKE)*;
        }
        impl<$($ty: ToxSerialize),*> ToxSerialize for ($($ty,)*) {
            fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
                #[allow(non_snake_case)]
                let ($($ty,)*) = self;
                let count = count_tuple_elements!($($ty),*);
                rmp::encode::write_array_len(writer, count as u32).map(|_| ()).map_err(|e| Error::Serialize(e.to_string()))?;
                $($ty.serialize(writer, ctx)?;)*
                Ok(())
            }
            #[inline]
            fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
                #[allow(non_snake_case)]
                let ($($ty,)*) = self;
                $($ty.serialize_flat(writer, ctx)?;)*
                Ok(())
            }
        }

        impl<$($ty: ToxDeserialize),*> ToxDeserialize for ($($ty,)*) {
            fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
                let count = count_tuple_elements!($($ty),*);
                let len = rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
                if len != count as u32 {
                    return Err(Error::Deserialize(format!("Tuple length mismatch: expected {}, got {}", count, len)));
                }
                Ok(($($ty::deserialize(reader, ctx)?,)*))
            }
            #[inline]
            fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
                Ok(($($ty::deserialize_flat(reader, ctx)?,)*))
            }
        }
    };
}

impl_tox_tuple!(T1, T2);
impl_tox_tuple!(T1, T2, T3);
impl_tox_tuple!(T1, T2, T3, T4);
impl_tox_tuple!(T1, T2, T3, T4, T5);
impl_tox_tuple!(T1, T2, T3, T4, T5, T6);
impl_tox_tuple!(T1, T2, T3, T4, T5, T6, T7);
impl_tox_tuple!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_tox_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_tox_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);

impl<K: ToxSize, V: ToxSize, S> ToxSize for std::collections::HashMap<K, V, S> {}
impl<K: ToxSerialize, V: ToxSerialize, S> ToxSerialize for std::collections::HashMap<K, V, S> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_map_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for (k, v) in self {
            k.serialize(writer, ctx)?;
            v.serialize(writer, ctx)?;
        }
        Ok(())
    }
}

impl<
    K: ToxDeserialize + Eq + std::hash::Hash,
    V: ToxDeserialize,
    S: std::hash::BuildHasher + Default,
> ToxDeserialize for std::collections::HashMap<K, V, S>
{
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_map_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut map = std::collections::HashMap::with_capacity_and_hasher(len, S::default());
        for _ in 0..len {
            let k = K::deserialize(reader, ctx)?;
            let v = V::deserialize(reader, ctx)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<K: ToxSize, V: ToxSize> ToxSize for std::collections::BTreeMap<K, V> {}
impl<K: ToxSerialize, V: ToxSerialize> ToxSerialize for std::collections::BTreeMap<K, V> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_map_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for (k, v) in self {
            k.serialize(writer, ctx)?;
            v.serialize(writer, ctx)?;
        }
        Ok(())
    }
}

impl<K: ToxDeserialize + Ord, V: ToxDeserialize> ToxDeserialize
    for std::collections::BTreeMap<K, V>
{
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_map_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut map = std::collections::BTreeMap::new();
        for _ in 0..len {
            let k = K::deserialize(reader, ctx)?;
            let v = V::deserialize(reader, ctx)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<T: ToxSize, S> ToxSize for std::collections::HashSet<T, S> {}
impl<T: ToxSerialize, S> ToxSerialize for std::collections::HashSet<T, S> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
}

impl<T: ToxDeserialize + Eq + std::hash::Hash, S: std::hash::BuildHasher + Default> ToxDeserialize
    for std::collections::HashSet<T, S>
{
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut set = std::collections::HashSet::with_capacity_and_hasher(len, S::default());
        for _ in 0..len {
            set.insert(T::deserialize(reader, ctx)?);
        }
        Ok(set)
    }
}

impl<T: ToxSize> ToxSize for std::collections::BTreeSet<T> {}
impl<T: ToxSerialize> ToxSerialize for std::collections::BTreeSet<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer, ctx)?;
        }
        Ok(())
    }
}

impl<T: ToxDeserialize + Ord> ToxDeserialize for std::collections::BTreeSet<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut set = std::collections::BTreeSet::new();
        for _ in 0..len {
            set.insert(T::deserialize(reader, ctx)?);
        }
        Ok(set)
    }
}

impl<T: ToxSize, E: ToxSize> ToxSize for std::result::Result<T, E> {}
impl<T: ToxSerialize, E: ToxSerialize> ToxSerialize for std::result::Result<T, E> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        rmp::encode::write_array_len(writer, 2)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        match self {
            Ok(v) => {
                1u8.serialize(writer, ctx)?;
                v.serialize(writer, ctx)?;
            }
            Err(e) => {
                0u8.serialize(writer, ctx)?;
                e.serialize(writer, ctx)?;
            }
        }
        Ok(())
    }
}

impl<T: ToxDeserialize, E: ToxDeserialize> ToxDeserialize for std::result::Result<T, E> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len != 2 {
            return Err(Error::Deserialize(format!(
                "Result length mismatch: expected 2, got {}",
                len
            )));
        }
        let variant = u8::deserialize(reader, ctx)?;
        match variant {
            1 => Ok(Ok(T::deserialize(reader, ctx)?)),
            0 => Ok(Err(E::deserialize(reader, ctx)?)),
            _ => Err(Error::Deserialize(format!(
                "Unknown Result variant: {}",
                variant
            ))),
        }
    }
}

impl<T: ToxSize> ToxSize for Option<T> {}
impl<T: ToxSerialize> ToxSerialize for Option<T> {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        match self {
            Some(v) => {
                rmp::encode::write_array_len(writer, 1)
                    .map(|_| ())
                    .map_err(|e| Error::Serialize(e.to_string()))?;
                v.serialize(writer, ctx)
            }
            None => rmp::encode::write_array_len(writer, 0)
                .map(|_| ())
                .map_err(|e| Error::Serialize(e.to_string())),
        }
    }
}
impl<T: ToxDeserialize> ToxDeserialize for Option<T> {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        match len {
            0 => Ok(None),
            1 => Ok(Some(T::deserialize(reader, ctx)?)),
            _ => {
                for _ in 0..len {
                    skip_value(reader)?;
                }
                Ok(None)
            }
        }
    }
}

impl ToxSize for std::time::Duration {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for std::time::Duration {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.as_nanos().serialize(writer, ctx)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        self.as_nanos().serialize_flat(writer, ctx)
    }
}

impl ToxDeserialize for std::time::Duration {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let nanos = u128::deserialize(reader, ctx)?;
        Ok(std::time::Duration::from_nanos(nanos as u64))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let nanos = u128::deserialize_flat(reader, ctx)?;
        Ok(std::time::Duration::from_nanos(nanos as u64))
    }
}

impl ToxSize for std::time::Instant {}
impl ToxSerialize for std::time::Instant {
    fn serialize<W: Write>(&self, writer: &mut W, ctx: &ToxContext) -> Result<()> {
        let tp = ctx.time_provider.as_ref().ok_or_else(|| {
            Error::Serialize(
                "TimeProvider missing in context for Instant serialization".to_string(),
            )
        })?;

        let now_inst = tp.now_instant();
        let now_sys = tp.now_system_ms();

        let age_micros = if *self <= now_inst {
            -(now_inst.duration_since(*self).as_micros() as i128)
        } else {
            self.duration_since(now_inst).as_micros() as i128
        };

        rmp::encode::write_array_len(writer, 2)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        age_micros.serialize(writer, ctx)?;
        now_sys.serialize(writer, ctx)?;
        Ok(())
    }
}

impl ToxDeserialize for std::time::Instant {
    fn deserialize<R: Read>(reader: &mut R, ctx: &ToxContext) -> Result<Self> {
        let tp = ctx.time_provider.as_ref().ok_or_else(|| {
            Error::Deserialize(
                "TimeProvider missing in context for Instant deserialization".to_string(),
            )
        })?;

        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len != 2 {
            return Err(Error::Deserialize(format!(
                "Instant length mismatch: expected 2, got {}",
                len
            )));
        }

        let age_micros = i128::deserialize(reader, ctx)?;
        let system_time_at_send = i64::deserialize(reader, ctx)?;

        let now_inst = tp.now_instant();
        let now_sys = tp.now_system_ms();

        let time_passed_ms = now_sys.saturating_sub(system_time_at_send);
        let adjusted_age_micros = age_micros - (time_passed_ms as i128 * 1000);

        if adjusted_age_micros >= 0 {
            Ok(now_inst)
        } else {
            Ok(now_inst
                .checked_sub(std::time::Duration::from_micros(
                    (-adjusted_age_micros) as u64,
                ))
                .unwrap_or(now_inst))
        }
    }
}

impl ToxSize for rand::rngs::StdRng {}
impl ToxSerialize for rand::rngs::StdRng {
    fn serialize<W: Write>(&self, _writer: &mut W, _ctx: &ToxContext) -> Result<()> {
        Ok(())
    }
}

impl ToxDeserialize for rand::rngs::StdRng {
    fn deserialize<R: Read>(_reader: &mut R, _ctx: &ToxContext) -> Result<Self> {
        use rand::SeedableRng;
        Ok(rand::rngs::StdRng::seed_from_u64(0))
    }
}

// Serialization Entry Points
pub fn serialize<T: ToxSerialize>(val: &T) -> Result<Vec<u8>> {
    serialize_with_ctx(val, &ToxContext::empty())
}

pub fn serialize_with_ctx<T: ToxSerialize>(val: &T, ctx: &ToxContext) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    val.serialize(&mut buf, ctx)?;
    Ok(buf)
}

pub fn deserialize<T: ToxDeserialize>(bytes: &[u8]) -> Result<T> {
    deserialize_with_ctx(bytes, &ToxContext::empty())
}

pub fn deserialize_with_ctx<T: ToxDeserialize>(bytes: &[u8], ctx: &ToxContext) -> Result<T> {
    let mut cursor = std::io::Cursor::new(bytes);
    T::deserialize(&mut cursor, ctx)
}
