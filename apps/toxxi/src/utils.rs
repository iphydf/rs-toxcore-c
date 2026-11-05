use std::fs::{self, File, Permissions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use toxcore::tox::Address;
use toxcore::types::{ADDRESS_SIZE, PUBLIC_KEY_SIZE};

/// Writes a new file and then renames it into place, so a crash can't leave
/// half a file. Only the owner can read it, as savedata.tox holds the secret
/// key.
pub fn write_atomically(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut new = path.as_os_str().to_owned();
    new.push(".new");
    let mut file = File::create(&new)?;
    #[cfg(unix)]
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&new, path)
}

/// Creates the profile directory, or fixes an existing one, so only the owner
/// can read the chat history in it.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| char::from(c).to_digit(16);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| Some((digit(pair[0])? << 4 | digit(pair[1])?) as u8))
        .collect()
}

/// Reads an ID of exactly `N` bytes, like a Tox ID or a group's chat ID.
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode_hex(s)?.try_into().ok()
}

/// Reads an ID of exactly `N` bytes, or says what's wrong with it; `what`
/// names it, as in "a Tox ID".
pub fn parse_id<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    if let Some((i, c)) = s.chars().enumerate().find(|(_, c)| !c.is_ascii_hexdigit()) {
        return Err(format!("'{c}' (character {}) isn't a hex digit", i + 1));
    }
    parse_hex(s).ok_or_else(|| format!("it has {} characters, {what} has {}", s.len(), N * 2))
}

/// Reads a Tox ID, or says what's wrong with it.
pub fn parse_address(s: &str) -> Result<Address, String> {
    if s.len() == PUBLIC_KEY_SIZE * 2 && parse_hex::<PUBLIC_KEY_SIZE>(s).is_some() {
        return Err(format!(
            "it's a public key ({} characters): ask for the whole Tox ID ({})",
            s.len(),
            ADDRESS_SIZE * 2
        ));
    }
    let address = Address(parse_id(s, "a Tox ID")?);
    if Address::from_public_key(address.public_key(), address.nospam()) != address {
        return Err("its checksum doesn't match: a character is wrong somewhere".to_owned());
    }
    Ok(address)
}

/// Keeps bytes as hex in JSON, like a Tox ID.
pub mod hex_json {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode_hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let hex = String::deserialize(deserializer)?;
        super::decode_hex(&hex).ok_or_else(|| D::Error::custom(format!("not hex: {hex}")))
    }
}

/// The start of a key, enough to tell friends apart where names don't.
pub fn short_key(pk: &toxcore::types::PublicKey) -> String {
    encode_hex(&pk.0[..4])
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn split_message(text: &str, limit: usize) -> Vec<String> {
    if text.len() <= limit {
        return vec![text.to_string()];
    }
    let mut parts = Vec::new();
    let mut start = 0;

    while start < text.len() {
        let mut end = start + limit;
        if end >= text.len() {
            parts.push(text[start..].to_string());
            break;
        }

        // Don't split a character.
        while !text.is_char_boundary(end) {
            end -= 1;
        }

        parts.push(text[start..end].to_string());
        start = end;
    }
    parts
}

pub fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_speed(speed: f64) -> String {
    format!("{}/s", format_size(speed as u64))
}

pub fn format_duration(seconds: f64) -> String {
    if seconds.is_infinite() || seconds.is_nan() || seconds <= 0.0 {
        return "--s".to_owned();
    }
    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0}m {:.0}s", seconds / 60.0, seconds % 60.0)
    } else {
        format!("{:.0}h {:.0}m", seconds / 3600.0, (seconds % 3600.0) / 60.0)
    }
}

/// Sends to another of toxxi's threads.
pub trait Tell<T> {
    fn tell(&self, value: T);
}

impl<T> Tell<T> for std::sync::mpsc::Sender<T> {
    fn tell(&self, value: T) {
        #[expect(clippy::let_underscore_must_use, reason = "the other thread has quit")]
        let _ = self.send(value);
    }
}
