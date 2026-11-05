#![cfg(unix)]

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;
use toxxi::utils::{private_dir, write_atomically};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// savedata.tox holds the secret key, so only the owner can read it, also
/// after replacing an old 0644 file.
#[test]
fn saved_files_are_ours_only() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("savedata.tox");
    write_atomically(&path, b"new").unwrap();
    assert_eq!(mode(&path), 0o600);

    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    write_atomically(&path, b"again").unwrap();
    assert_eq!(mode(&path), 0o600);
}

/// The chat history is in the profile directory, so only the owner can open
/// it. Older toxxis made it 0750.
#[test]
fn the_profile_directory_is_ours_only() {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("share/toxxi");
    private_dir(&profile).unwrap();
    assert_eq!(mode(&profile), 0o700);

    fs::set_permissions(&profile, Permissions::from_mode(0o750)).unwrap();
    private_dir(&profile).unwrap();
    assert_eq!(mode(&profile), 0o700);
}
