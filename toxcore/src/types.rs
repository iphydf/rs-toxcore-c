//! Safe type wrappers for the Tox C API.
//!
//! This file is the hand-written half: the four `macro_rules!`, the extra
//! `Address` crypto helpers and the private `hex` module. apigen generates
//! the declarations (size constants, the macro invocations and `ToxError`)
//! into `core/generated/types.rs`, which comes after the macros so they're in
//! scope.

macro_rules! impl_byte_array_type {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $size]);

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&hex::encode(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                let bytes = hex::decode(&s)
                    .ok_or_else(|| serde::de::Error::custom("Invalid hex string"))?;
                if bytes.len() != $size {
                    return Err(serde::de::Error::custom(format!(
                        "Invalid length for {}: expected {}, got {}",
                        stringify!($name),
                        $size,
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(&bytes);
                Ok($name(arr))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

macro_rules! impl_secret_array_type {
    ($name:ident, $size:expr) => {
        /// A secret: nothing formats, serialises or copies it.
        #[cfg_attr(tokstyle, tokstyle::secret)]
        pub struct $name(pub [u8; $size]);
    };
}

macro_rules! impl_safe_newtype {
    ($name:ident, $number:ty) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub $number);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! impl_tox_enum {
    ($name:ident, $ffi:path, { $($variant:ident = $c:ident),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $($variant),*
        }

        impl From<$ffi> for $name {
            fn from(e: $ffi) -> Self {
                match e {
                    $(<$ffi>::$c => $name::$variant),*
                }
            }
        }

        impl From<$name> for $ffi {
            fn from(e: $name) -> Self {
                match e {
                    $($name::$variant => <$ffi>::$c),*
                }
            }
        }
    };
}

// An enum C passes as `uint32_t`, so a client can pass a value the header
// doesn't name: `FileKind::AVATAR`.
macro_rules! impl_tox_open_enum {
    ($name:ident, $ffi:path, { $($value:ident = $c:ident),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub u32);

        impl $name {
            $(pub const $value: $name = $name(<$ffi>::$c as u32);)*
        }

        impl From<u32> for $name {
            fn from(value: u32) -> Self {
                $name(value)
            }
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

// A set of flags: `AvFriendCallState::SENDING_A | AvFriendCallState::SENDING_V`.
macro_rules! impl_tox_flags {
    ($name:ident, $ffi:path, { $($value:ident = $c:ident),* $(,)? }) => {
        impl_tox_open_enum!($name, $ffi, { $($value = $c),* });

        impl $name {
            pub fn contains(self, flags: $name) -> bool {
                self.0 & flags.0 == flags.0
            }
        }

        impl std::ops::BitOr for $name {
            type Output = $name;

            fn bitor(self, flags: $name) -> $name {
                $name(self.0 | flags.0)
            }
        }
    };
}

#[path = "core/generated/types.rs"]
mod generated;
pub use generated::*;

impl Address {
    pub fn from_public_key(pk: PublicKey, nospam: u32) -> Self {
        let mut arr = [0u8; ADDRESS_SIZE];
        arr[0..PUBLIC_KEY_SIZE].copy_from_slice(&pk.0);
        arr[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + 4].copy_from_slice(&nospam.to_be_bytes());

        let mut checksum = [0u8; 2];
        for i in (0..PUBLIC_KEY_SIZE + 4).step_by(2) {
            checksum[0] ^= arr[i];
            checksum[1] ^= arr[i + 1];
        }

        arr[ADDRESS_SIZE - 2] = checksum[0];
        arr[ADDRESS_SIZE - 1] = checksum[1];
        Address(arr)
    }

    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        pk.copy_from_slice(&self.0[0..PUBLIC_KEY_SIZE]);
        PublicKey(pk)
    }

    pub fn nospam(&self) -> u32 {
        let a = &self.0;
        let n = PUBLIC_KEY_SIZE;
        u32::from_be_bytes([a[n], a[n + 1], a[n + 2], a[n + 3]])
    }

    pub fn checksum(&self) -> u16 {
        let a = &self.0;
        let n = PUBLIC_KEY_SIZE + 4;
        u16::from_be_bytes([a[n], a[n + 1]])
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }
}
