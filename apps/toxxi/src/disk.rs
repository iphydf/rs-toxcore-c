use std::path::Path;

/// The file system for the model, which must not touch it itself: tests can
/// pass in a fake one.
pub trait Disk: Send + Sync + std::fmt::Debug {
    /// The names in `dir`, each with whether it's a directory.
    fn list(&self, dir: &Path) -> Vec<(String, bool)>;
    /// The size of the file at `path`, or None if it can't be read.
    fn size(&self, path: &Path) -> Option<u64>;
}

#[derive(Debug)]
pub struct RealDisk;

impl Disk for RealDisk {
    fn list(&self, dir: &Path) -> Vec<(String, bool)> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| {
                let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
                (entry.file_name().to_string_lossy().into_owned(), is_dir)
            })
            .collect()
    }

    fn size(&self, path: &Path) -> Option<u64> {
        std::fs::metadata(path).ok().map(|m| m.len())
    }
}
