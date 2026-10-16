use std::io::{Read, Write};
use std::sync::Arc;

mod kept;

pub use kept::{Kept, carry};
pub use rmp;
pub use tox_proto_derive::{ToxDeserialize, ToxProto, ToxSerialize};

extern crate self as tox_proto;

/// The longest string or byte string a value may claim, so a claimed length
/// can't make the reader allocate more.
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Deserialize(String),
    Serialize(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Deserialize(e) => write!(f, "Deserialize error: {}", e),
            Error::Serialize(e) => write!(f, "Serialize error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
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
    /// `ToxProto` follows these rules, described in full in `ENCODING.md`:
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()>;

    #[inline]
    fn serialize_flat<W: Write>(&self, _writer: &mut W) -> Result<()> {
        Err(Error::Serialize(
            "Type does not support flat serialization".into(),
        ))
    }

    /// Writes `items` as one array. Bytes write theirs as a `bin` instead.
    fn serialize_seq<W: Write>(items: &[Self], writer: &mut W) -> Result<()>
    where
        Self: Sized,
    {
        rmp::encode::write_array_len(writer, items.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in items {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

pub trait ToxDeserialize: Sized + ToxSize {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self>;

    #[inline]
    fn deserialize_flat<R: Read>(_reader: &mut R) -> Result<Self> {
        Err(Error::Deserialize(
            "Type does not support flat deserialization".into(),
        ))
    }

    /// Reads what [`ToxSerialize::serialize_seq`] wrote.
    fn deserialize_seq<R: Read>(reader: &mut R) -> Result<Vec<Self>> {
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        let mut vec = Vec::with_capacity(bounded_capacity(len as usize));
        for _ in 0..len {
            vec.push(Self::deserialize(reader)?);
        }
        Ok(vec)
    }

    /// Reads items without a header until the reader is done.
    fn deserialize_flat_seq<R: Read>(reader: &mut R) -> Result<Vec<Self>> {
        if Self::SIZE.is_none() {
            return Err(Error::Deserialize(
                "Vec item must have fixed size for flat deserialization".into(),
            ));
        }
        let mut vec = Vec::new();
        while let Ok(item) = Self::deserialize_flat(reader) {
            vec.push(item);
        }
        Ok(vec)
    }
}

/// Encoded as an array of its fields, so it can gain fields at the end; the
/// derive implements it for every struct that isn't `#[tox(flat)]`.
pub trait Fields {}

/// The type one variant of the `#[tox(lenient)]` enum `E` wraps, so that the
/// variant can be found by type. The derive implements it.
pub trait Variant<E>: Sized + Into<E> {
    /// The variant's tag.
    const KIND: u32;

    fn of(value: &E) -> Option<&Self>;
}

impl<T: ToxSize + ?Sized> ToxSize for &T {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for &T {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        (*self).serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        (*self).serialize_flat(writer)
    }
}

impl ToxSize for str {}
impl ToxSerialize for str {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_str(writer, self).map_err(|e| Error::Serialize(e.to_string()))
    }
}

impl<T: ToxSize + ?Sized> ToxSize for Box<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for Box<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        (**self).serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        (**self).serialize_flat(writer)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Box<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Box::new(T::deserialize(reader)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Box::new(T::deserialize_flat(reader)?))
    }
}

impl<T: ToxSize + ?Sized> ToxSize for Arc<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize + ?Sized> ToxSerialize for Arc<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        (**self).serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        (**self).serialize_flat(writer)
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Arc<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Arc::new(T::deserialize(reader)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Arc::new(T::deserialize_flat(reader)?))
    }
}

/// Skips a single MessagePack value. It walks the value without recursion,
/// counting what is left of it, and reads a claimed length into nothing, so a
/// peer's value can neither overflow the stack by nesting nor make it
/// allocate more than it sends.
pub fn skip_value<R: Read>(reader: &mut R) -> Result<()> {
    use rmp::Marker;
    fn length<R: Read, const N: usize>(reader: &mut R) -> Result<u64> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf[8 - N..])?;
        Ok(u64::from_be_bytes(buf))
    }
    let mut left: u64 = 1;
    while left > 0 {
        left -= 1;
        let marker =
            rmp::decode::read_marker(reader).map_err(|e| Error::Deserialize(format!("{:?}", e)))?;
        // The bytes it holds, and the values it's made of.
        let (bytes, values) = match marker {
            Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::True | Marker::False => {
                (0, 0)
            }
            Marker::U8 | Marker::I8 => (1, 0),
            Marker::U16 | Marker::I16 => (2, 0),
            Marker::U32 | Marker::I32 | Marker::F32 => (4, 0),
            Marker::U64 | Marker::I64 | Marker::F64 => (8, 0),
            Marker::FixStr(len) => (u64::from(len), 0),
            Marker::Str8 | Marker::Bin8 => (length::<_, 1>(reader)?, 0),
            Marker::Str16 | Marker::Bin16 => (length::<_, 2>(reader)?, 0),
            Marker::Str32 | Marker::Bin32 => (length::<_, 4>(reader)?, 0),
            Marker::FixArray(len) => (0, u64::from(len)),
            Marker::Array16 => (0, length::<_, 2>(reader)?),
            Marker::Array32 => (0, length::<_, 4>(reader)?),
            Marker::FixMap(len) => (0, 2 * u64::from(len)),
            Marker::Map16 => (0, 2 * length::<_, 2>(reader)?),
            Marker::Map32 => (0, 2 * length::<_, 4>(reader)?),
            // An extension's type, then its data.
            Marker::FixExt1 => (1 + 1, 0),
            Marker::FixExt2 => (1 + 2, 0),
            Marker::FixExt4 => (1 + 4, 0),
            Marker::FixExt8 => (1 + 8, 0),
            Marker::FixExt16 => (1 + 16, 0),
            Marker::Ext8 => (1 + length::<_, 1>(reader)?, 0),
            Marker::Ext16 => (1 + length::<_, 2>(reader)?, 0),
            Marker::Ext32 => (1 + length::<_, 4>(reader)?, 0),
            Marker::Reserved => {
                return Err(Error::Deserialize(
                    "Reserved marker encountered".to_string(),
                ));
            }
        };
        if std::io::copy(&mut reader.by_ref().take(bytes), &mut std::io::sink())? != bytes {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        left += values;
    }
    Ok(())
}

/// Upper bound on the initial preallocation hint for peer-supplied
/// collection lengths. The wire may legitimately carry collections
/// larger than this — the container simply grows naturally past the
/// hint — but a hostile peer cannot force a huge allocation up
/// front before a single element is read. Sized well above the largest
/// batches the protocols send.
const DESERIALIZE_CAPACITY_HINT_CAP: usize = 1024;

#[inline]
fn bounded_capacity(claimed_len: usize) -> usize {
    claimed_len.min(DESERIALIZE_CAPACITY_HINT_CAP)
}

/// Reads a single msgpack value from the reader and returns its raw bytes,
/// as many as were read: a claimed length makes it allocate no more.
///
/// This is used by the `#[tox(catch_all)]` derive macro to capture unknown
/// enum variant payloads for transparent forwarding.
pub fn capture_value<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    struct CaptureReader<'a, R> {
        inner: &'a mut R,
        buf: &'a mut Vec<u8>,
    }
    impl<R: Read> Read for CaptureReader<'_, R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(out)?;
            self.buf.extend_from_slice(&out[..n]);
            Ok(n)
        }
    }
    let mut buf = Vec::new();
    skip_value(&mut CaptureReader {
        inner: reader,
        buf: &mut buf,
    })?;
    Ok(buf)
}

/// Helper to read an enum header, supporting both naked discriminators and array-wrapped variants.
pub fn read_enum_header<R: Read>(reader: &mut R) -> Result<(u8, u32)> {
    use rmp::Marker;
    let marker =
        rmp::decode::read_marker(reader).map_err(|e| Error::Deserialize(format!("{:?}", e)))?;
    match marker {
        Marker::FixPos(idx) => Ok((idx, 1)),
        Marker::U8 => {
            // Read raw data byte. Marker was already consumed by read_marker.
            // rmp::decode::read_u8 would re-read the marker (reads marker+data).
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            Ok((buf[0], 1))
        }
        Marker::FixArray(len) => {
            let idx = u8::deserialize(reader)?;
            Ok((idx, len as u32))
        }
        Marker::Array16 => {
            // Read raw 2-byte big-endian length. Marker already consumed.
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            let len = u16::from_be_bytes(buf);
            let idx = u8::deserialize(reader)?;
            Ok((idx, len as u32))
        }
        Marker::Array32 => {
            // Read raw 4-byte big-endian length. Marker already consumed.
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            let len = u32::from_be_bytes(buf);
            let idx = u8::deserialize(reader)?;
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.lock()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.lock()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize_flat(writer)
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::sync::Mutex<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(std::sync::Mutex::new(T::deserialize(reader)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(std::sync::Mutex::new(T::deserialize_flat(reader)?))
    }
}

impl<T: ToxSize> ToxSize for std::sync::RwLock<T> {
    const SIZE: Option<usize> = T::SIZE;
    const IS_BYTE_LIKE: bool = T::IS_BYTE_LIKE;
}
impl<T: ToxSerialize> ToxSerialize for std::sync::RwLock<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.read()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.read()
            .map_err(|e| Error::Serialize(e.to_string()))?
            .serialize_flat(writer)
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::sync::RwLock<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(std::sync::RwLock::new(T::deserialize(reader)?))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(std::sync::RwLock::new(T::deserialize_flat(reader)?))
    }
}

// Primitives
macro_rules! impl_rmp_int {
    ($ty:ty, $encoder:ident, $decoder:ident) => {
        impl ToxSize for $ty {
            const SIZE: Option<usize> = Some(std::mem::size_of::<$ty>());
        }
        impl ToxSerialize for $ty {
            fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
                rmp::encode::$encoder(writer, *self as _)
                    .map(|_| ())
                    .map_err(|e| Error::Serialize(e.to_string()))
            }
            #[inline]
            fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
                writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
            }
        }
        impl ToxDeserialize for $ty {
            fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
                rmp::decode::$decoder(reader).map_err(|e| Error::Deserialize(e.to_string()))
            }
            #[inline]
            fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_uint(writer, *self as u64)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[*self]).map_err(Error::Io)
    }
    fn serialize_seq<W: Write>(items: &[Self], writer: &mut W) -> Result<()> {
        rmp::encode::write_bin(writer, items).map_err(|e| Error::Serialize(e.to_string()))
    }
}

/// `len` bytes, taking room only for those there are, as a claimed length
/// may be far more.
fn read_bytes<R: Read>(reader: &mut R, len: u32) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(u64::from(len)).read_to_end(&mut bytes)?;
    if bytes.len() != len as usize {
        return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(bytes)
}

impl ToxDeserialize for u8 {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        rmp::decode::read_int(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(buf[0])
    }
    fn deserialize_seq<R: Read>(reader: &mut R) -> Result<Vec<Self>> {
        let len =
            rmp::decode::read_bin_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len as usize > MAX_MESSAGE_SIZE {
            return Err(Error::Deserialize(format!(
                "oversized Vec<u8>: claimed len {} exceeds MAX_MESSAGE_SIZE {}",
                len, MAX_MESSAGE_SIZE,
            )));
        }
        read_bytes(reader, len)
    }
    fn deserialize_flat_seq<R: Read>(reader: &mut R) -> Result<Vec<Self>> {
        let mut vec = Vec::new();
        reader.read_to_end(&mut vec)?;
        Ok(vec)
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_f32(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for f32 {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        rmp::decode::read_f32(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(f32::from_be_bytes(buf))
    }
}

impl ToxSize for f64 {
    const SIZE: Option<usize> = Some(8);
}
impl ToxSerialize for f64 {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_f64(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_be_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for f64 {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        rmp::decode::read_f64(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(f64::from_be_bytes(buf))
    }
}

impl ToxSize for char {
    const SIZE: Option<usize> = Some(4);
}
impl ToxSerialize for char {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_uint(writer, *self as u64)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer
            .write_all(&(*self as u32).to_be_bytes())
            .map_err(Error::Io)
    }
}

impl ToxDeserialize for char {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let u = rmp::decode::read_int::<u32, _>(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))?;
        std::char::from_u32(u).ok_or_else(|| Error::Deserialize(format!("Invalid char: {}", u)))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_bool(writer, *self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer
            .write_all(&[if *self { 1 } else { 0 }])
            .map_err(Error::Io)
    }
}
impl ToxDeserialize for bool {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        rmp::decode::read_bool(reader).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(buf[0] != 0)
    }
}

impl ToxSize for u128 {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for u128 {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_bin(writer, &self.to_le_bytes())
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_le_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for u128 {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
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
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf).map_err(Error::Io)?;
        Ok(u128::from_le_bytes(buf))
    }
}
impl ToxSize for i128 {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for i128 {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_bin(writer, &self.to_le_bytes())
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_le_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for i128 {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
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
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_str(writer, self).map_err(|e| Error::Serialize(e.to_string()))
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.as_bytes()).map_err(Error::Io)
    }
}
impl ToxDeserialize for String {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len =
            rmp::decode::read_str_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len as usize > MAX_MESSAGE_SIZE {
            return Err(Error::Deserialize(format!(
                "oversized String: claimed len {} exceeds MAX_MESSAGE_SIZE {}",
                len, MAX_MESSAGE_SIZE,
            )));
        }
        String::from_utf8(read_bytes(reader, len)?).map_err(|e| Error::Deserialize(e.to_string()))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        String::from_utf8(buf).map_err(|e| Error::Deserialize(e.to_string()))
    }
}

impl ToxSize for [u8] {}
impl ToxSerialize for [u8] {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        T::serialize_seq(self, writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        if T::SIZE.is_some() {
            for item in self {
                item.serialize_flat(writer)?;
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        T::deserialize_seq(reader)
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        T::deserialize_flat_seq(reader)
    }
}

impl<T: ToxSize> ToxSize for std::collections::VecDeque<T> {}
impl<T: ToxSerialize> ToxSerialize for std::collections::VecDeque<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer)?;
        }
        Ok(())
    }
}
impl<T: ToxDeserialize> ToxDeserialize for std::collections::VecDeque<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut deque = std::collections::VecDeque::with_capacity(bounded_capacity(len));
        for _ in 0..len {
            deque.push_back(T::deserialize(reader)?);
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        T::serialize_seq(self, writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        for item in self {
            item.serialize_flat(writer)?;
        }
        Ok(())
    }
}
impl<T: ToxDeserialize, const N: usize> ToxDeserialize for [T; N] {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let items = T::deserialize_seq(reader)?;
        let len = items.len();
        items.try_into().map_err(|_| {
            Error::Deserialize(format!("Length mismatch: expected {}, got {}", N, len))
        })
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::deserialize_flat(reader)?);
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
            fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
                #[allow(non_snake_case)]
                let ($($ty,)*) = self;
                let count = count_tuple_elements!($($ty),*);
                rmp::encode::write_array_len(writer, count as u32).map(|_| ()).map_err(|e| Error::Serialize(e.to_string()))?;
                $($ty.serialize(writer)?;)*
                Ok(())
            }
            #[inline]
            fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
                #[allow(non_snake_case)]
                let ($($ty,)*) = self;
                $($ty.serialize_flat(writer)?;)*
                Ok(())
            }
        }

        impl<$($ty: ToxDeserialize),*> ToxDeserialize for ($($ty,)*) {
            fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
                let count = count_tuple_elements!($($ty),*);
                let len = rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
                if len != count as u32 {
                    return Err(Error::Deserialize(format!("Tuple length mismatch: expected {}, got {}", count, len)));
                }
                Ok(($($ty::deserialize(reader)?,)*))
            }
            #[inline]
            fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
                Ok(($($ty::deserialize_flat(reader)?,)*))
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
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_map_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for (k, v) in self {
            k.serialize(writer)?;
            v.serialize(writer)?;
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len = rmp::decode::read_map_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut map = std::collections::HashMap::with_capacity_and_hasher(
            bounded_capacity(len),
            S::default(),
        );
        for _ in 0..len {
            let k = K::deserialize(reader)?;
            let v = V::deserialize(reader)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<K: ToxSize, V: ToxSize> ToxSize for std::collections::BTreeMap<K, V> {}
impl<K: ToxSerialize, V: ToxSerialize> ToxSerialize for std::collections::BTreeMap<K, V> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_map_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for (k, v) in self {
            k.serialize(writer)?;
            v.serialize(writer)?;
        }
        Ok(())
    }
}

impl<K: ToxDeserialize + Ord, V: ToxDeserialize> ToxDeserialize
    for std::collections::BTreeMap<K, V>
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len = rmp::decode::read_map_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut map = std::collections::BTreeMap::new();
        for _ in 0..len {
            let k = K::deserialize(reader)?;
            let v = V::deserialize(reader)?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

impl<T: ToxSize, S> ToxSize for std::collections::HashSet<T, S> {}
impl<T: ToxSerialize, S> ToxSerialize for std::collections::HashSet<T, S> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<T: ToxDeserialize + Eq + std::hash::Hash, S: std::hash::BuildHasher + Default> ToxDeserialize
    for std::collections::HashSet<T, S>
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut set = std::collections::HashSet::with_capacity_and_hasher(
            bounded_capacity(len),
            S::default(),
        );
        for _ in 0..len {
            set.insert(T::deserialize(reader)?);
        }
        Ok(set)
    }
}

impl<T: ToxSize> ToxSize for std::collections::BTreeSet<T> {}
impl<T: ToxSerialize> ToxSerialize for std::collections::BTreeSet<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_array_len(writer, self.len() as u32)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        for item in self {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<T: ToxDeserialize + Ord> ToxDeserialize for std::collections::BTreeSet<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len = rmp::decode::read_array_len(reader)
            .map_err(|e| Error::Deserialize(e.to_string()))? as usize;
        let mut set = std::collections::BTreeSet::new();
        for _ in 0..len {
            set.insert(T::deserialize(reader)?);
        }
        Ok(set)
    }
}

impl<T: ToxSize, E: ToxSize> ToxSize for std::result::Result<T, E> {}
impl<T: ToxSerialize, E: ToxSerialize> ToxSerialize for std::result::Result<T, E> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        rmp::encode::write_array_len(writer, 2)
            .map(|_| ())
            .map_err(|e| Error::Serialize(e.to_string()))?;
        match self {
            Ok(v) => {
                1u8.serialize(writer)?;
                v.serialize(writer)?;
            }
            Err(e) => {
                0u8.serialize(writer)?;
                e.serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl<T: ToxDeserialize, E: ToxDeserialize> ToxDeserialize for std::result::Result<T, E> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        if len != 2 {
            return Err(Error::Deserialize(format!(
                "Result length mismatch: expected 2, got {}",
                len
            )));
        }
        let variant = u8::deserialize(reader)?;
        match variant {
            1 => Ok(Ok(T::deserialize(reader)?)),
            0 => Ok(Err(E::deserialize(reader)?)),
            _ => Err(Error::Deserialize(format!(
                "Unknown Result variant: {}",
                variant
            ))),
        }
    }
}

impl<T: ToxSize> ToxSize for Option<T> {}
impl<T: ToxSerialize> ToxSerialize for Option<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Some(v) => {
                rmp::encode::write_array_len(writer, 1)
                    .map(|_| ())
                    .map_err(|e| Error::Serialize(e.to_string()))?;
                v.serialize(writer)
            }
            None => rmp::encode::write_array_len(writer, 0)
                .map(|_| ())
                .map_err(|e| Error::Serialize(e.to_string())),
        }
    }
}
impl<T: ToxDeserialize> ToxDeserialize for Option<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let len =
            rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))?;
        match len {
            0 => Ok(None),
            1 => Ok(Some(T::deserialize(reader)?)),
            _ => Err(Error::Deserialize(format!(
                "Option of {} items, not at most 1",
                len
            ))),
        }
    }
}

impl ToxSize for std::time::Duration {
    const SIZE: Option<usize> = Some(16);
}
impl ToxSerialize for std::time::Duration {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.as_nanos().serialize(writer)
    }
    #[inline]
    fn serialize_flat<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.as_nanos().serialize_flat(writer)
    }
}

impl ToxDeserialize for std::time::Duration {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let nanos = u128::deserialize(reader)?;
        Ok(std::time::Duration::from_nanos(nanos as u64))
    }
    #[inline]
    fn deserialize_flat<R: Read>(reader: &mut R) -> Result<Self> {
        let nanos = u128::deserialize_flat(reader)?;
        Ok(std::time::Duration::from_nanos(nanos as u64))
    }
}

// Serialization Entry Points
pub fn serialize<T: ToxSerialize>(val: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(128);
    val.serialize(&mut buf)?;
    Ok(buf)
}

pub fn deserialize<T: ToxDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut cursor = std::io::Cursor::new(bytes);
    T::deserialize(&mut cursor)
}

/// Like [`deserialize`], but `bytes` must hold exactly one value.
pub fn deserialize_exact<T: ToxDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = T::deserialize(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Deserialize("Trailing bytes after value".into()));
    }
    Ok(value)
}
