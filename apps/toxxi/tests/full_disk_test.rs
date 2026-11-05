//! We simulate a full disk with a file size limit: a write past it stops part
//! of the way. The limit applies to the whole process, so this test must be
//! the only one in its file.
#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;
use toxcore::types::PublicKey;
use toxxi::io::spawn_io_worker;
use toxxi::msg::{IOAction, IOEvent, Msg, ToxAction};
use toxxi::sync::store::{EVENTS_FILE, read_log};

const DEVICE: PublicKey = PublicKey([1; 32]);

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

const RLIMIT_FSIZE: i32 = 1;
const SIGXFSZ: i32 = 25;
const SIG_IGN: usize = 1;

unsafe extern "C" {
    fn getrlimit(resource: i32, limit: *mut Rlimit) -> i32;
    fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
}

fn limit_files_to(bytes: u64) {
    let mut limit = Rlimit { cur: 0, max: 0 };
    unsafe {
        assert_eq!(getrlimit(RLIMIT_FSIZE, &mut limit), 0);
        limit.cur = bytes.min(limit.max);
        assert_eq!(setrlimit(RLIMIT_FSIZE, &limit), 0);
    }
}

/// A write that fails part of the way leaves the log as it was, and its events
/// are written with the next ones.
#[tokio::test(flavor = "multi_thread")]
async fn events_written_onto_a_full_disk_are_kept_when_there_is_room() {
    // Make writes past the limit fail instead of killing the process.
    unsafe { signal(SIGXFSZ, SIG_IGN) };
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
    let records = [vec![b'a'; 100], vec![b'b'; 100], vec![b'c'; 100]];
    let append = |n: usize| {
        tx_io
            .send(IOAction::AppendEvents(
                vec![records[n].clone()],
                vec![(DEVICE, vec![n as u8])],
            ))
            .unwrap();
    };
    let pushed = || match rx_tox.recv_timeout(Duration::from_secs(5)).unwrap() {
        ToxAction::SyncSend(DEVICE, message) => message[0],
        other => panic!("{other:?}"),
    };

    append(0);
    assert_eq!(pushed(), 0);

    let log = dir.path().join(EVENTS_FILE);
    limit_files_to(std::fs::metadata(&log).unwrap().len() + 10);
    append(1);
    let error = rx_msg.recv_timeout(Duration::from_secs(5)).unwrap();
    limit_files_to(u64::MAX);
    assert!(matches!(error, Msg::IO(IOEvent::Error(_))), "{error:?}");

    append(2);
    assert_eq!([pushed(), pushed()], [1, 2]);
    assert_eq!(read_log(&log).unwrap(), records);
}
