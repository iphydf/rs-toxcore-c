use std::io::{Read, Write};
use std::ops::Deref;

use crate::{
    Error, Result, ToxDeserialize, ToxSerialize, ToxSize, Variant, capture_value,
    deserialize_exact, read_enum_header, serialize, skip_value,
};

/// A value with the bytes it was read from, written back as they came, so
/// what this version doesn't know of it is kept. Equal by value.
#[derive(Debug, Clone)]
pub struct Kept<T> {
    value: T,
    bytes: Option<Vec<u8>>,
}

impl<T> Kept<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

impl<E: ToxSerialize> Kept<E> {
    /// `value` in place of the variant of the `#[tox(lenient)]` enum this
    /// holds, with the fields of it after `value`'s own as they came.
    pub fn with<T: Variant<E> + ToxSerialize>(&self, value: T) -> Result<Self> {
        let mut fields = serialize(&value)?;
        if let Some(old) = &self.bytes {
            let mut reader = old.as_slice();
            if read_enum_header(&mut reader)? == (T::KIND as u8, 2) {
                fields = carry(reader, &fields)?;
            }
        }
        let mut bytes = Vec::new();
        rmp::encode::write_array_len(&mut bytes, 2).map_err(|e| Error::Serialize(e.to_string()))?;
        (T::KIND as u8).serialize(&mut bytes)?;
        bytes.extend(fields);
        Ok(Self {
            value: value.into(),
            bytes: Some(bytes),
        })
    }
}

/// `new`, the encoding of a structure, with the fields of `old`, an
/// encoding of it by a version that knows more of them, after its own.
pub fn carry(old: &[u8], new: &[u8]) -> Result<Vec<u8>> {
    let length = |reader: &mut &[u8]| {
        rmp::decode::read_array_len(reader).map_err(|e| Error::Deserialize(e.to_string()))
    };
    let (mut old_fields, mut new_fields) = (old, new);
    let (had, has) = (length(&mut old_fields)?, length(&mut new_fields)?);
    if had <= has {
        return Ok(new.to_vec());
    }
    for _ in 0..has {
        skip_value(&mut old_fields)?;
    }
    let mut bytes = Vec::new();
    rmp::encode::write_array_len(&mut bytes, had).map_err(|e| Error::Serialize(e.to_string()))?;
    bytes.extend(new_fields);
    bytes.extend(old_fields);
    Ok(bytes)
}

impl<T> From<T> for Kept<T> {
    fn from(value: T) -> Self {
        Self { value, bytes: None }
    }
}

impl<T> Deref for Kept<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: PartialEq> PartialEq for Kept<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for Kept<T> {}

impl<T> ToxSize for Kept<T> {}

impl<T: ToxSerialize> ToxSerialize for Kept<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        match &self.bytes {
            Some(bytes) => Ok(writer.write_all(bytes)?),
            None => self.value.serialize(writer),
        }
    }
}

impl<T: ToxDeserialize> ToxDeserialize for Kept<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let bytes = capture_value(reader)?;
        Ok(Self {
            value: deserialize_exact(&bytes)?,
            bytes: Some(bytes),
        })
    }
}
