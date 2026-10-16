use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;
use toxcore::types::{FileId, PublicKey};
use toxxi::io::spawn_io_worker;
use toxxi::msg::{IOAction, IOEvent, Msg, ToxAction};
use toxxi::sync::event::BlobId;
use toxxi::sync::files::{blob_path, blobs_dir, file_id, part_path};

const DEVICE: PublicKey = PublicKey([1u8; 32]);

struct Worker {
    dir: TempDir,
    tx_io: mpsc::Sender<IOAction>,
    rx_msg: mpsc::Receiver<Msg>,
    rx_tox: mpsc::Receiver<ToxAction>,
}

fn worker() -> Worker {
    let dir = TempDir::new().unwrap();
    let (tx_msg, rx_msg) = mpsc::channel();
    let (tx_tox, rx_tox) = mpsc::channel();
    let (tx_io, rx_io) = mpsc::channel();
    spawn_io_worker(
        tx_msg,
        tx_tox,
        rx_io,
        dir.path().to_path_buf(),
        dir.path().join("downloads"),
    );
    Worker {
        dir,
        tx_io,
        rx_msg,
        rx_tox,
    }
}

impl Worker {
    fn next(&self) -> IOEvent {
        loop {
            match self.rx_msg.recv_timeout(Duration::from_secs(5)).unwrap() {
                Msg::IO(IOEvent::FileChunkWritten(..)) => {}
                Msg::IO(event) => return event,
                _ => {}
            }
        }
    }

    /// Receives `data` as `blob`, starting with `part` already there.
    fn receive(&self, blob: BlobId, part: &[u8], data: &[u8]) -> IOEvent {
        let dir = blobs_dir(self.dir.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(part_path(&dir, &blob))
            .unwrap()
            .write_all(part)
            .unwrap();
        let size = (part.len() + data.len()) as u64;
        for action in [
            IOAction::ReceiveBlob(DEVICE, blob, size),
            IOAction::WriteChunk(DEVICE, file_id(&blob), part.len() as u64, data.to_vec()),
            IOAction::StoreBlob(DEVICE, blob),
        ] {
            self.tx_io.send(action).unwrap();
        }
        self.next()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_blobs_are_kept_only_with_their_id() {
    let io = worker();
    let blob = BlobId::of(&b"cat"[..]).unwrap();

    // A part from before resumes where it stopped.
    assert!(matches!(
        io.receive(blob, b"c", b"at"),
        IOEvent::BlobStored(DEVICE, b, true) if b == blob
    ));
    assert_eq!(
        io.rx_tox.try_recv().unwrap(),
        ToxAction::FileSeek(DEVICE, file_id(&blob), 1)
    );
    let path = blob_path(&blobs_dir(io.dir.path()), &blob);
    assert_eq!(std::fs::read(&path).unwrap(), b"cat");

    let other = BlobId([9; 32]);
    assert!(matches!(
        io.receive(other, b"", b"dog"),
        IOEvent::BlobStored(DEVICE, b, false) if b == other
    ));
    assert_eq!(
        std::fs::read_dir(blobs_dir(io.dir.path())).unwrap().count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_finished_files_are_kept_as_blobs() {
    let io = worker();
    let file = FileId([2; 32]);
    for action in [
        IOAction::OpenFileForReceiving(DEVICE, file, "cat.png".to_owned(), 3),
        IOAction::WriteChunk(DEVICE, file, 0, b"cat".to_vec()),
        IOAction::FinishFile(DEVICE, file),
    ] {
        io.tx_io.send(action).unwrap();
    }
    let blob = BlobId::of(&b"cat"[..]).unwrap();
    assert!(matches!(
        io.next(),
        IOEvent::FileFinished(DEVICE, f, Some(b)) if f == file && b == blob
    ));
    // Editing the file after doesn't change its blob.
    std::fs::write(io.dir.path().join("downloads").join("cat.png"), b"dog").unwrap();
    assert_eq!(
        std::fs::read(blob_path(&blobs_dir(io.dir.path()), &blob)).unwrap(),
        b"cat"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_a_file_received_over_a_longer_one_is_its_own_bytes() {
    let io = worker();
    let downloads = io.dir.path().join("downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::write(downloads.join("cat.png"), b"a longer cat").unwrap();
    let file = FileId([3; 32]);
    for action in [
        IOAction::OpenFileForReceiving(DEVICE, file, "cat.png".to_owned(), 3),
        IOAction::WriteChunk(DEVICE, file, 0, b"cat".to_vec()),
        IOAction::FinishFile(DEVICE, file),
    ] {
        io.tx_io.send(action).unwrap();
    }
    let blob = BlobId::of(&b"cat"[..]).unwrap();
    assert!(matches!(
        io.next(),
        IOEvent::FileFinished(DEVICE, f, Some(b)) if f == file && b == blob
    ));
    assert_eq!(std::fs::read(downloads.join("cat.png")).unwrap(), b"cat");
}
