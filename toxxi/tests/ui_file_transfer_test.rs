use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    DomainState, FileTransferProgress, FriendInfo, MessageStatus, Model, TransferStatus, WindowId,
};
use toxxi::msg::{IOEvent, Msg, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

fn add_test_friend(model: &mut Model, fid: FriendNumber, pk: PublicKey) {
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: format!("Friend {}", fid.0),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
}

#[test]
fn test_ui_file_transfer_sidebar_removed() {
    let mut model = create_test_model();

    // Setup Friend 1
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    // Add a file transfer for Friend 1
    let file_id = FileId([100u8; 32]);
    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: "secret_plans.txt".to_string(),
            total_size: 1024,
            transferred: 512, // 50%
            is_receiving: true,
            status: TransferStatus::Active,
            file_kind: 0,
            file_path: None,
            speed: 0.0,
            last_update: model.time_provider.now(),
            last_transferred: 512,
            friend_pk: pk,
        },
    );

    // Switch to Friend 1 window
    model.set_active_window(1); // Console is 0, Friend is 1

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // At column 50, there should NOT be a border as the sidebar is removed.
    let border_cell = &buffer[(50, 1)];
    assert_ne!(
        border_cell.symbol(),
        "│",
        "Sidebar border should not be present even with transfers"
    );

    // Ensure the title "Transfers" is not present
    let mut found_transfers_title = false;
    for y in 0..20 {
        let row: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("Transfers") {
            found_transfers_title = true;
            break;
        }
    }
    assert!(
        !found_transfers_title,
        "Sidebar title 'Transfers' should not be present"
    );
}

#[test]
fn test_ui_inline_file_transfer_card() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    let window_id = WindowId::Friend(pk);
    let file_id = FileId([0u8; 32]);
    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        conv.messages.push(toxxi::model::Message {
            internal_id: toxxi::model::InternalMessageId(1),
            sender: "Alice".to_string(),
            sender_pk: None,
            is_self: false,
            content: toxxi::model::MessageContent::FileTransfer {
                file_id: Some(file_id),
                name: "image.png".to_string(),
                size: 1024,
                progress: 0.75,
                speed: "10 KB/s".to_string(),
                is_incoming: true,
            },
            timestamp: model.time_provider.now_local(),
            status: MessageStatus::Incoming,
            message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
            highlighted: false,
        });
    }

    model.set_active_window(1);

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    let mut found_filename = false;
    let mut found_progress = false;

    for y in 0..20 {
        let row: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("image.png") {
            found_filename = true;
        }
        if row.contains("75%") {
            found_progress = true;
        }
    }

    assert!(found_filename, "Inline card filename 'image.png' not found");
    assert!(found_progress, "Inline card progress '75%' not found");
}

#[test]
fn test_ui_multiple_file_transfer_updates() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    // 1. Simulate friend connection
    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(
            fid,
            toxcore::tox::ToxConnection::TOX_CONNECTION_TCP,
            None,
        )),
    );
    // Also ensure friend window exists and is active
    // model.ensure_friend_window(fid); // Done in add_test_friend
    model.set_active_window(1);

    // 2. Receive two file offers
    let file1 = FileId([100u8; 32]);
    let file2 = FileId([101u8; 32]);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file1,
            0,    // kind
            1000, // size
            "file1.txt".to_string(),
        )),
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file2,
            0,    // kind
            2000, // size
            "file2.txt".to_string(),
        )),
    );

    // Verify initial state: both present, 0%
    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Helper to find text in buffer
    let find_text = |text: &str| -> bool {
        for y in 0..20 {
            let row: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
            if row.contains(text) {
                return true;
            }
        }
        false
    };

    assert!(find_text("file1.txt"), "file1.txt should be visible");
    assert!(find_text("file2.txt"), "file2.txt should be visible");

    // 3. Update file1 to 50% (500/1000)
    update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(
            pk, file1, 0,   // position (start)
            500, // length
        )),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    // Find the row with file1.txt, the progress is in the next row
    let (y_idx, _) = (0..20)
        .map(|y| {
            (
                y,
                (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>(),
            )
        })
        .find(|(_, row)| row.contains("file1.txt"))
        .expect("file1.txt not found after update");

    let row_with_progress = (0..80)
        .map(|x| buffer[(x, y_idx + 1)].symbol())
        .collect::<String>();
    assert!(
        row_with_progress.contains("50%"),
        "file1 should show 50% progress in row {}, found: {}",
        y_idx + 1,
        row_with_progress
    );

    // 4. Update file2 to 25% (500/2000)
    update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(
            pk, file2, 0,   // position
            500, // length
        )),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    let (y2_idx, _) = (0..20)
        .map(|y| {
            (
                y,
                (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>(),
            )
        })
        .find(|(_, row)| row.contains("file2.txt"))
        .expect("file2.txt not found after update");

    let row_with_progress2 = (0..80)
        .map(|x| buffer[(x, y2_idx + 1)].symbol())
        .collect::<String>();
    assert!(
        row_with_progress2.contains("25%"),
        "file2 should show 25% progress in row {}, found: {}",
        y2_idx + 1,
        row_with_progress2
    );

    // Ensure file1 is still 50% (didn't change)
    let (y1_again_idx, _) = (0..20)
        .map(|y| {
            (
                y,
                (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>(),
            )
        })
        .find(|(_, row)| row.contains("file1.txt"))
        .expect("file1.txt not found");

    let row_with_progress1_again = (0..80)
        .map(|x| buffer[(x, y1_again_idx + 1)].symbol())
        .collect::<String>();
    assert!(
        row_with_progress1_again.contains("50%"),
        "file1 should still be 50% in row {}, found: {}",
        y1_again_idx + 1,
        row_with_progress1_again
    );
}

#[test]
fn test_ui_file_transfer_reuse() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);
    model.set_active_window(1);

    // 1. First transfer (ID 100)
    let file_id = FileId([100u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1000,
            "old_file.txt".to_string(),
        )),
    );

    // Simulate finish
    update(&mut model, Msg::IO(IOEvent::FileFinished(pk, file_id)));

    // 2. Second transfer (ID 100 reused) -> Wait, reuse ID? Sure, if new ID bytes are same.
    // In new model, ID is 32 bytes hash. It shouldn't collide unless it's the same file.
    // But let's assume we reuse the ID for test purposes.
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            2000,
            "new_file.txt".to_string(),
        )),
    );

    // 3. Update progress for ID 100 (should apply to new_file.txt)
    update(
        &mut model,
        Msg::IO(IOEvent::FileChunkWritten(
            pk, file_id, 0, 500, // 500/2000 = 25%
        )),
    );

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    // Find new_file.txt row
    let (new_y, _) = (0..20)
        .map(|y| {
            (
                y,
                (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>(),
            )
        })
        .find(|(_, row)| row.contains("new_file.txt"))
        .expect("new_file.txt not found");

    let new_progress_row = (0..80)
        .map(|x| buffer[(x, new_y + 1)].symbol())
        .collect::<String>();
    assert!(
        new_progress_row.contains("25%"),
        "new_file.txt should show 25% progress, found: {}",
        new_progress_row
    );
}

#[test]
fn test_ui_ignore_finished_transfer_interaction() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);
    model.set_active_window(1);

    // 1. First transfer (ID 100) -> Finished
    let file_id = FileId([100u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1000,
            "old_file.txt".to_string(),
        )),
    );
    update(&mut model, Msg::IO(IOEvent::FileFinished(pk, file_id)));

    // 2. Second transfer (ID 100 reused) -> Active
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            2000,
            "new_file.txt".to_string(),
        )),
    );

    // 3. Select the OLD message (index 0)
    model.ui.ui_mode = toxxi::model::UiMode::Navigation;
    {
        let state = model
            .ui
            .window_state
            .entry(WindowId::Friend(pk))
            .or_default();
        state.msg_list_state.select(Some(0));
    }

    // 4. Simulate 'x' key to Cancel on the OLD finished message
    let cmds = update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('x')),
        )),
    );

    // 5. Verify NO command generated (ignored)
    let has_cancel = cmds.iter().any(|cmd| {
        if let toxxi::msg::Cmd::Tox(toxxi::msg::ToxAction::FileControl(f, fn_id, ctrl)) = cmd {
            *f == pk
                && *fn_id == file_id
                && *ctrl == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL
        } else {
            false
        }
    });

    assert!(
        !has_cancel,
        "Interaction with finished transfer should be ignored"
    );
}
