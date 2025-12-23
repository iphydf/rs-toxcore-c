use super::setup::TestHarness;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub fn subtest_file_transfer(harness: &mut TestHarness) {
    println!("Running subtest_file_transfer...");

    struct PendingRequest {
        friend: FriendNumber,
        file: FileNumber,
        position: u64,
        length: usize,
    }

    struct SharedState {
        // Receiver
        received_request: Option<(FriendNumber, FileNumber, u64)>,
        received_data: Vec<u8>,
        receiver_completed: bool,
        canceled: bool,

        // Sender
        pending_request: Option<PendingRequest>,
    }

    struct TestFileHandler {
        state: Arc<Mutex<SharedState>>,
    }

    impl ToxHandler for TestFileHandler {
        fn on_file_recv(
            &mut self,
            friend: FriendNumber,
            file: FileNumber,
            _kind: u32,
            file_size: u64,
            _filename: &[u8],
        ) {
            let mut s = self.state.lock().unwrap();
            s.received_request = Some((friend, file, file_size));
        }

        fn on_file_recv_chunk(
            &mut self,
            _friend: FriendNumber,
            _file: FileNumber,
            _position: u64,
            data: &[u8],
        ) {
            let mut s = self.state.lock().unwrap();
            if data.is_empty() {
                s.receiver_completed = true;
            } else {
                s.received_data.extend_from_slice(data);
            }
        }

        fn on_file_chunk_request(
            &mut self,
            friend: FriendNumber,
            file: FileNumber,
            position: u64,
            length: usize,
        ) {
            let mut s = self.state.lock().unwrap();
            s.pending_request = Some(PendingRequest {
                friend,
                file,
                position,
                length,
            });
        }

        fn on_file_recv_control(
            &mut self,
            _friend: FriendNumber,
            _file: FileNumber,
            control: ToxFileControl,
        ) {
            if control == ToxFileControl::TOX_FILE_CONTROL_CANCEL {
                self.state.lock().unwrap().canceled = true;
            }
        }
    }

    let state = Arc::new(Mutex::new(SharedState {
        received_request: None,
        received_data: Vec::new(),
        receiver_completed: false,
        canceled: false,
        pending_request: None,
    }));

    let mut handler = TestFileHandler {
        state: state.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    let file_data = b"Hello File Transfer World";

    // 1. Alice sends file request
    let _file = harness.toxes[0]
        .tox
        .file_send(
            &f0,
            ToxFileKind::TOX_FILE_KIND_DATA as u32,
            file_data.len() as u64,
            None,
            b"test.txt",
        )
        .unwrap();

    // 2. Wait for Bob to receive request
    let start = Instant::now();
    let mut bob_friend = None;
    let mut bob_file = None;

    while Instant::now().duration_since(start) < Duration::from_secs(2) {
        harness.iterate(&mut handler);
        let s = state.lock().unwrap();
        if let Some((f, file, _)) = s.received_request {
            bob_friend = Some(f);
            bob_file = Some(file);
            break;
        }
    }
    let bob_friend = bob_friend.expect("Bob did not receive file request");
    let bob_file = bob_file.expect("Bob did not receive file number");

    // 3. Bob accepts file
    let bob_friend_obj = harness.toxes[1].tox.friend(bob_friend);
    harness.toxes[1]
        .tox
        .file(&bob_friend_obj, bob_file)
        .control(ToxFileControl::TOX_FILE_CONTROL_RESUME)
        .unwrap();

    // 4. Drive transfer
    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);

        // Check if Alice needs to send a chunk
        let req = {
            let mut s = state.lock().unwrap();
            s.pending_request.take()
        };

        if let Some(req) = req {
            if req.length == 0 {
                // Transfer done from receiver perspective? Or just a check?
            } else {
                let pos = req.position as usize;
                let friend_obj = harness.toxes[0].tox.friend(req.friend);
                let file_obj = harness.toxes[0].tox.file(&friend_obj, req.file);

                // If pos == len, send empty chunk to finish
                if pos >= file_data.len() {
                    file_obj.send_chunk(req.position, &[]).unwrap();
                } else {
                    let end = std::cmp::min(pos + req.length, file_data.len());
                    let chunk = &file_data[pos..end];
                    file_obj.send_chunk(req.position, chunk).unwrap();
                }
            }
        }

        if state.lock().unwrap().receiver_completed {
            break;
        }
    }

    {
        let s = state.lock().unwrap();
        assert!(s.receiver_completed, "File transfer not completed");
        assert_eq!(s.received_data, file_data, "File corrupted");
    }

    // Test File Cancel
    println!("Testing file cancel...");
    let file_data_cancel = b"CancelMe";

    // Reset state
    {
        let mut s = state.lock().unwrap();
        s.received_request = None;
        s.received_data.clear();
        s.receiver_completed = false;
        s.canceled = false;
        s.pending_request = None;
    }

    // Alice sends file
    println!("Alice sending file request...");
    let file_obj = harness.toxes[0]
        .tox
        .file_send(
            &f0,
            ToxFileKind::TOX_FILE_KIND_DATA as u32,
            file_data_cancel.len() as u64,
            None,
            b"cancel.txt",
        )
        .unwrap();
    println!("Alice sent file request. File num: {:?}", file_obj.number());

    // Wait for Bob to receive
    let start = Instant::now();
    let mut bob_friend = None;
    let mut bob_file = None;
    while Instant::now().duration_since(start) < Duration::from_secs(2) {
        harness.iterate(&mut handler);
        let s = state.lock().unwrap();
        if let Some((f, file, _)) = s.received_request {
            bob_friend = Some(f);
            bob_file = Some(file);
            break;
        }
    }
    let bob_friend = bob_friend.expect("Bob did not receive cancel file request");
    let bob_file = bob_file.expect("Bob did not receive cancel file number");
    println!(
        "Bob received request. Friend: {:?}, File: {:?}",
        bob_friend, bob_file
    );

    // Bob accepts
    println!("Bob accepting file...");
    let bob_friend_obj = harness.toxes[1].tox.friend(bob_friend);
    harness.toxes[1]
        .tox
        .file(&bob_friend_obj, bob_file)
        .control(ToxFileControl::TOX_FILE_CONTROL_RESUME)
        .unwrap();
    println!("Bob accepted file.");

    // Alice cancels immediately
    println!("Alice canceling file...");
    file_obj
        .control(ToxFileControl::TOX_FILE_CONTROL_CANCEL)
        .unwrap();
    println!("Alice canceled file.");

    // Wait for cancel event on Bob
    println!("Waiting for cancel event...");
    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(1) {
        harness.iterate(&mut handler);
        if state.lock().unwrap().canceled {
            println!("Cancel event received!");
            break;
        }
    }
}
