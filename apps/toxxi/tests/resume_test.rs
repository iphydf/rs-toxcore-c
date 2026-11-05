use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;
use toxcore::types::{FileControl, FileId, PublicKey};
use toxxi::io::spawn_io_worker;
use toxxi::msg::{IOAction, IOEvent, Msg, ToxAction};

const FRIEND: PublicKey = PublicKey([1; 32]);
const OTHER: PublicKey = PublicKey([2; 32]);
const CAT: FileId = FileId([3; 32]);

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
    fn send(&self, actions: impl IntoIterator<Item = IOAction>) {
        for action in actions {
            self.tx_io.send(action).unwrap();
        }
    }

    /// What it tells Tox when it opens a download: a seek, then the start.
    fn started(&self) -> Vec<ToxAction> {
        let mut told = Vec::new();
        loop {
            let action = self.rx_tox.recv_timeout(Duration::from_secs(5)).unwrap();
            let start = matches!(action, ToxAction::FileControl(_, _, FileControl::Resume));
            told.push(action);
            if start {
                return told;
            }
        }
    }

    fn finished(&self) {
        loop {
            if let Msg::IO(IOEvent::FileFinished(..)) =
                self.rx_msg.recv_timeout(Duration::from_secs(5)).unwrap()
            {
                return;
            }
        }
    }

    fn download(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.path().join("downloads").join(name)).unwrap()
    }

    /// "ca" of the cat came from `pk` before the transfer stopped.
    fn stopped_after_ca(&self, pk: PublicKey) {
        self.send([
            IOAction::OpenFileForReceiving(pk, CAT, "cat.png".to_owned(), 3),
            IOAction::WriteChunk(pk, CAT, 0, b"ca".to_vec()),
            IOAction::CloseFile(pk, CAT),
        ]);
        self.started();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_resumes_where_its_transfer_stopped() {
    let io = worker();
    io.stopped_after_ca(FRIEND);

    io.send([IOAction::OpenFileForReceiving(
        FRIEND,
        CAT,
        "cat.png".to_owned(),
        3,
    )]);
    assert_eq!(
        io.started(),
        vec![
            ToxAction::FileSeek(FRIEND, CAT, 2),
            ToxAction::FileControl(FRIEND, CAT, FileControl::Resume),
        ]
    );
    io.send([
        IOAction::WriteChunk(FRIEND, CAT, 2, b"t".to_vec()),
        IOAction::FinishFile(FRIEND, CAT),
    ]);
    io.finished();
    assert_eq!(io.download("cat.png"), b"cat");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_doesnt_resume_into_another_friends_file() {
    let io = worker();
    io.stopped_after_ca(OTHER);

    io.send([IOAction::OpenFileForReceiving(
        FRIEND,
        CAT,
        "cat.png".to_owned(),
        3,
    )]);
    assert_eq!(
        io.started(),
        vec![ToxAction::FileControl(FRIEND, CAT, FileControl::Resume)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_leaves_a_file_of_its_name_alone() {
    let io = worker();
    let downloads = io.dir.path().join("downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::write(downloads.join("cat.png"), b"a longer cat").unwrap();

    io.send([IOAction::OpenFileForReceiving(
        FRIEND,
        CAT,
        "cat.png".to_owned(),
        3,
    )]);
    assert_eq!(
        io.started(),
        vec![ToxAction::FileControl(FRIEND, CAT, FileControl::Resume)]
    );
    io.send([
        IOAction::WriteChunk(FRIEND, CAT, 0, b"cat".to_vec()),
        IOAction::FinishFile(FRIEND, CAT),
    ]);
    io.finished();
    assert_eq!(io.download("cat.png"), b"a longer cat");
    assert_eq!(io.download("cat (2).png"), b"cat");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_download_starts_over() {
    let io = worker();
    io.send([
        IOAction::OpenFileForReceiving(FRIEND, CAT, "cat.png".to_owned(), 3),
        IOAction::WriteChunk(FRIEND, CAT, 0, b"ca".to_vec()),
        IOAction::CancelFile(FRIEND, CAT),
    ]);
    io.started();

    io.send([IOAction::OpenFileForReceiving(
        FRIEND,
        CAT,
        "cat.png".to_owned(),
        3,
    )]);
    assert_eq!(
        io.started(),
        vec![ToxAction::FileControl(FRIEND, CAT, FileControl::Resume)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_upload_leaves_our_file_alone() {
    let io = worker();
    let ours = io.dir.path().join("cat.png");
    std::fs::write(&ours, b"cat").unwrap();
    io.send([
        IOAction::OpenFileForSending(FRIEND, CAT, ours.clone()),
        IOAction::CancelFile(FRIEND, CAT),
        // The worker answers this, which tells us it has handled the cancel.
        IOAction::OpenFileForReceiving(FRIEND, FileId([4; 32]), "dog.png".to_owned(), 3),
    ]);
    io.started();
    assert_eq!(std::fs::read(&ours).unwrap(), b"cat");
}
