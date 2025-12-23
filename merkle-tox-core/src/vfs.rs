use crate::clock::TimeProvider;
use std::collections::BTreeMap;
use std::fmt::{self, Debug};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait FileHandle: Read + Write + Seek + Send + Sync + Debug {
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn metadata(&self) -> io::Result<FileMetadata>;
    fn try_lock_exclusive(&self) -> io::Result<()>;
    fn try_lock_shared(&self) -> io::Result<()>;
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub len: u64,
    pub is_dir: bool,
    pub modified: SystemTime,
}

pub trait FileSystem: Send + Sync + Debug {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir(&self, path: &Path) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn metadata(&self, path: &Path) -> io::Result<FileMetadata>;
    fn exists(&self, path: &Path) -> bool;

    fn open(
        &self,
        path: &Path,
        write: bool,
        create: bool,
        truncate: bool,
    ) -> io::Result<Box<dyn FileHandle>>;
}

#[derive(Clone, Copy)]
pub struct StdFileSystem;

impl Debug for StdFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StdFileSystem")
    }
}

impl FileSystem for StdFileSystem {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        fs::write(path, contents)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        Ok(fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect())
    }
    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let meta = fs::metadata(path)?;
        Ok(FileMetadata {
            len: meta.len(),
            is_dir: meta.is_dir(),
            modified: meta.modified().unwrap_or(SystemTime::now()),
        })
    }
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
    fn open(
        &self,
        path: &Path,
        write: bool,
        create: bool,
        truncate: bool,
    ) -> io::Result<Box<dyn FileHandle>> {
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .create(create)
            .truncate(truncate)
            .open(path)?;
        Ok(Box::new(file))
    }
}

impl FileHandle for File {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }
    fn metadata(&self) -> io::Result<FileMetadata> {
        let meta = self.metadata()?;
        Ok(FileMetadata {
            len: meta.len(),
            is_dir: meta.is_dir(),
            modified: meta.modified().unwrap_or(SystemTime::now()),
        })
    }
    fn try_lock_exclusive(&self) -> io::Result<()> {
        fs2::FileExt::try_lock_exclusive(self)
    }
    fn try_lock_shared(&self) -> io::Result<()> {
        fs2::FileExt::try_lock_shared(self)
    }
}

#[derive(Debug, Clone)]
pub struct MemFileSystem {
    inner: Arc<RwLock<MemFiles>>,
    time_provider: Option<Arc<dyn TimeProvider>>,
}

#[derive(Debug)]
struct MemFiles {
    files: BTreeMap<PathBuf, (Vec<u8>, SystemTime)>,
    dirs: BTreeMap<PathBuf, SystemTime>,
}

impl MemFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_provider(time_provider: Arc<dyn TimeProvider>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MemFiles {
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
            })),
            time_provider: Some(time_provider),
        }
    }

    fn now(&self) -> SystemTime {
        if let Some(tp) = &self.time_provider {
            UNIX_EPOCH + Duration::from_millis(tp.now_system_ms() as u64)
        } else {
            SystemTime::now()
        }
    }
}

impl Default for MemFileSystem {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MemFiles {
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
            })),
            time_provider: None,
        }
    }
}

impl FileSystem for MemFileSystem {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner
            .files
            .get(path)
            .map(|(d, _)| d.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found"))
    }
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner
            .files
            .insert(path.to_path_buf(), (contents.to_vec(), self.now()));
        Ok(())
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        if let Some(data) = inner.files.remove(from) {
            inner.files.insert(to.to_path_buf(), (data.0, self.now()));
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
        }
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner
            .files
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found"))
    }
    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        // Only remove if empty
        let is_empty = !inner.files.keys().any(|p| p.starts_with(path))
            && !inner.dirs.keys().any(|p| p.starts_with(path) && p != path);
        if is_empty {
            inner
                .dirs
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Dir not found"))
        } else {
            Err(io::Error::other("Directory not empty"))
        }
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        let mut p = PathBuf::new();
        let now = self.now();
        for component in path.components() {
            p.push(component);
            inner.dirs.entry(p.clone()).or_insert(now);
        }
        Ok(())
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let inner = self.inner.read().unwrap();
        let mut results = Vec::new();
        for p in inner.files.keys().chain(inner.dirs.keys()) {
            if p.parent() == Some(path) {
                results.push(p.clone());
            }
        }
        Ok(results)
    }
    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let inner = self.inner.read().unwrap();
        if let Some((data, modified)) = inner.files.get(path) {
            Ok(FileMetadata {
                len: data.len() as u64,
                is_dir: false,
                modified: *modified,
            })
        } else if let Some(modified) = inner.dirs.get(path) {
            Ok(FileMetadata {
                len: 0,
                is_dir: true,
                modified: *modified,
            })
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Not found"))
        }
    }
    fn exists(&self, path: &Path) -> bool {
        let inner = self.inner.read().unwrap();
        inner.files.contains_key(path) || inner.dirs.contains_key(path)
    }
    fn open(
        &self,
        path: &Path,
        _write: bool,
        create: bool,
        truncate: bool,
    ) -> io::Result<Box<dyn FileHandle>> {
        let mut inner = self.inner.write().unwrap();
        let (data, modified) = if truncate {
            let now = self.now();
            inner.files.insert(path.to_path_buf(), (Vec::new(), now));
            (Vec::new(), now)
        } else if let Some(existing) = inner.files.get(path) {
            existing.clone()
        } else if create {
            let now = self.now();
            inner.files.insert(path.to_path_buf(), (Vec::new(), now));
            (Vec::new(), now)
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "File not found"));
        };
        drop(inner);

        Ok(Box::new(MemFileHandle {
            data,
            pos: 0,
            path: path.to_path_buf(),
            fs: self.clone(),
            modified,
            writable: _write,
        }))
    }
}

#[derive(Debug)]
struct MemFileHandle {
    data: Vec<u8>,
    pos: u64,
    path: PathBuf,
    fs: MemFileSystem,
    modified: SystemTime,
    writable: bool,
}

impl Read for MemFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cursor = Cursor::new(&self.data);
        cursor.set_position(self.pos);
        let n = cursor.read(buf)?;
        self.pos = cursor.position();
        Ok(n)
    }
}

impl Write for MemFileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cursor = Cursor::new(&mut self.data);
        cursor.set_position(self.pos);
        let n = cursor.write(buf)?;
        self.pos = cursor.position();
        self.modified = self.fs.now();
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.writable {
            return Ok(());
        }
        let mut inner = self.fs.inner.write().unwrap();
        inner
            .files
            .insert(self.path.clone(), (self.data.clone(), self.modified));
        Ok(())
    }
}

impl Drop for MemFileHandle {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl Seek for MemFileHandle {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let mut cursor = Cursor::new(&self.data);
        cursor.set_position(self.pos);
        let res = cursor.seek(pos)?;
        self.pos = cursor.position();
        Ok(res)
    }
}

impl FileHandle for MemFileHandle {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.data.resize(size as usize, 0);
        self.modified = self.fs.now();
        Ok(())
    }
    fn metadata(&self) -> io::Result<FileMetadata> {
        Ok(FileMetadata {
            len: self.data.len() as u64,
            is_dir: false,
            modified: self.modified,
        })
    }
    fn try_lock_exclusive(&self) -> io::Result<()> {
        Ok(())
    }
    fn try_lock_shared(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct FaultInjectingFileSystem {
    inner: Arc<dyn FileSystem>,
    fail_probability: Arc<AtomicU64>, // scaled by 10^6
    enospc_at: Arc<AtomicU64>,
    total_written: Arc<AtomicU64>,
}

impl FaultInjectingFileSystem {
    pub fn new(inner: Arc<dyn FileSystem>) -> Self {
        Self {
            inner,
            fail_probability: Arc::new(AtomicU64::new(0)),
            enospc_at: Arc::new(AtomicU64::new(u64::MAX)),
            total_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_fail_probability(&self, prob: f64) {
        self.fail_probability
            .store((prob * 1_000_000.0) as u64, Ordering::SeqCst);
    }

    pub fn set_enospc_at(&self, limit: u64) {
        self.enospc_at.store(limit, Ordering::SeqCst);
    }

    fn should_fail(&self) -> bool {
        let prob = self.fail_probability.load(Ordering::SeqCst);
        if prob == 0 {
            return false;
        }
        use rand::Rng;
        rand::thread_rng().gen_range(0..1_000_000) < prob
    }

    fn check_write(&self, len: u64) -> io::Result<()> {
        if self.should_fail() {
            return Err(io::Error::other("Injected fault"));
        }
        let total = self.total_written.fetch_add(len, Ordering::SeqCst) + len;
        if total > self.enospc_at.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "No space left on device",
            ));
        }
        Ok(())
    }
}

impl FileSystem for FaultInjectingFileSystem {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.should_fail() {
            return Err(io::Error::other("Injected fault"));
        }
        self.inner.read(path)
    }
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.check_write(contents.len() as u64)?;
        self.inner.write(path, contents)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        if self.should_fail() {
            return Err(io::Error::other("Injected fault"));
        }
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_dir(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.inner.read_dir(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        self.inner.metadata(path)
    }
    fn exists(&self, path: &Path) -> bool {
        self.inner.exists(path)
    }
    fn open(
        &self,
        path: &Path,
        write: bool,
        create: bool,
        truncate: bool,
    ) -> io::Result<Box<dyn FileHandle>> {
        let handle = self.inner.open(path, write, create, truncate)?;
        Ok(Box::new(FaultInjectingHandle {
            inner: handle,
            fail_probability: self.fail_probability.clone(),
            enospc_at: self.enospc_at.clone(),
            total_written: self.total_written.clone(),
        }))
    }
}

#[derive(Debug)]
struct FaultInjectingHandle {
    inner: Box<dyn FileHandle>,
    fail_probability: Arc<AtomicU64>,
    enospc_at: Arc<AtomicU64>,
    total_written: Arc<AtomicU64>,
}

impl FaultInjectingHandle {
    fn should_fail(&self) -> bool {
        let prob = self.fail_probability.load(Ordering::SeqCst);
        if prob == 0 {
            return false;
        }
        use rand::Rng;
        rand::thread_rng().gen_range(0..1_000_000) < prob
    }

    fn check_write(&self, len: u64) -> io::Result<()> {
        if self.should_fail() {
            return Err(io::Error::other("Injected fault"));
        }
        let total = self.total_written.fetch_add(len, Ordering::SeqCst) + len;
        if total > self.enospc_at.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "No space left on device",
            ));
        }
        Ok(())
    }
}

impl Read for FaultInjectingHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for FaultInjectingHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_write(buf.len() as u64)?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.should_fail() {
            return Err(io::Error::other("Injected fault on flush"));
        }
        self.inner.flush()
    }
}

impl Seek for FaultInjectingHandle {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl FileHandle for FaultInjectingHandle {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.check_write(size)?;
        self.inner.set_len(size)
    }
    fn metadata(&self) -> io::Result<FileMetadata> {
        self.inner.metadata()
    }
    fn try_lock_exclusive(&self) -> io::Result<()> {
        self.inner.try_lock_exclusive()
    }
    fn try_lock_shared(&self) -> io::Result<()> {
        self.inner.try_lock_shared()
    }
}
