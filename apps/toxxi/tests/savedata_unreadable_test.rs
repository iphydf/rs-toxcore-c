use tempfile::TempDir;
use toxxi::worker::get_initial_state;

/// A profile that's there but can't be read isn't replaced by a new one,
/// which would be saved over it and lose the Tox ID for good.
#[test]
fn an_unreadable_profile_stops_toxxi() {
    let dir = TempDir::new().unwrap();
    // A directory: it exists, but reading it fails.
    let path = dir.path().join("savedata.tox");
    std::fs::create_dir(&path).unwrap();

    assert!(get_initial_state(&Some(path.clone())).is_err());
    assert!(path.is_dir(), "the profile's place was written over");
}
