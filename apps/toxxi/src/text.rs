//! Message bytes, as Tox carries them, shown as text.

pub fn of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
