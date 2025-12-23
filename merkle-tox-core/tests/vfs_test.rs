use merkle_tox_core::vfs::{FileSystem, MemFileSystem, StdFileSystem};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

fn test_fs_behavior<F: FileSystem>(fs: &F, root: &Path) {
    // 1. Basic Write/Read
    let file1 = root.join("file1.txt");
    fs.write(&file1, b"hello world").unwrap();
    assert!(fs.exists(&file1));
    assert_eq!(fs.read(&file1).unwrap(), b"hello world");

    // 2. Metadata
    let meta = fs.metadata(&file1).unwrap();
    assert_eq!(meta.len, 11);
    assert!(!meta.is_dir);

    // 3. Directories
    let dir1 = root.join("dir1");
    let dir1_sub = dir1.join("sub");
    fs.create_dir_all(&dir1_sub).unwrap();
    assert!(fs.exists(&dir1));
    assert!(fs.exists(&dir1_sub));
    assert!(fs.metadata(&dir1).unwrap().is_dir);

    // 4. read_dir
    let file2 = dir1.join("file2.txt");
    fs.write(&file2, b"content").unwrap();
    let entries = fs.read_dir(&dir1).unwrap();
    let entry_names: std::collections::HashSet<String> = entries
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
        .collect();
    assert!(entry_names.contains("sub"));
    assert!(entry_names.contains("file2.txt"));
    assert_eq!(entries.len(), 2);

    // 5. Rename
    let file1_renamed = root.join("file1_new.txt");
    fs.rename(&file1, &file1_renamed).unwrap();
    assert!(!fs.exists(&file1));
    assert!(fs.exists(&file1_renamed));
    assert_eq!(fs.read(&file1_renamed).unwrap(), b"hello world");

    // 6. FileHandle (Seek, Read, Write)
    let mut handle = fs.open(&file1_renamed, true, false, false).unwrap();
    handle.seek(SeekFrom::Start(6)).unwrap();
    let mut buf = [0u8; 5];
    handle.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"world");

    handle.seek(SeekFrom::Start(0)).unwrap();
    handle.write_all(b"HELLO").unwrap();
    handle.flush().unwrap();
    assert_eq!(fs.read(&file1_renamed).unwrap(), b"HELLO world");

    // 7. Truncate
    {
        let mut handle = fs.open(&file1_renamed, true, false, true).unwrap();
        assert_eq!(handle.metadata().unwrap().len, 0);
        handle.write_all(b"truncated").unwrap();
        handle.flush().unwrap();
    }
    assert_eq!(fs.read(&file1_renamed).unwrap(), b"truncated");

    // 8. remove_file
    fs.remove_file(&file1_renamed).unwrap();
    assert!(!fs.exists(&file1_renamed));
}

#[test]
fn test_mem_fs_compliance() {
    let mem_fs = MemFileSystem::new();
    test_fs_behavior(&mem_fs, Path::new("/"));
}

#[test]
fn test_std_fs_compliance() {
    let tmp = TempDir::new().unwrap();
    let std_fs = StdFileSystem;
    test_fs_behavior(&std_fs, tmp.path());
}
