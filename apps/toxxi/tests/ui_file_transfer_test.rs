use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::{FileId, MessageType, PublicKey};
use toxxi::model::{FileTransferProgress, MessageStatus, TransferStatus, WindowId};
use toxxi::msg::{IOEvent, Msg, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model};

#[test]
fn test_ui_file_transfer_sidebar_removed() {
    let mut model = create_test_model();

    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    let file_id = FileId([100u8; 32]);
    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: "secret_plans.txt".to_string(),
            total_size: 1024,
            transferred: 512, // 50%
            is_receiving: true,
            status: TransferStatus::Active,
            speed: 0.0,
            last_update: model.time_provider.now(),
            last_transferred: 512,
            friend_pk: pk,
        },
    );

    model.set_active_window(1); // Console is 0, Friend is 1

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // No border at column 50: the sidebar is gone.
    let border_cell = &buffer[(50, 1)];
    assert_ne!(
        border_cell.symbol(),
        "│",
        "Sidebar border should not be present even with transfers"
    );

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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

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
                blob: None,
            },
            timestamp: model.time_provider.now_local(),
            status: MessageStatus::Incoming,
            message_type: MessageType::Normal,
            highlighted: false,
            privately: None,
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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FriendStatus(pk, toxcore::tox::Connection::Tcp)),
    );
    model.set_active_window(1);

    let file1 = FileId([100u8; 32]);
    let file2 = FileId([101u8; 32]);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file1,
            toxcore::types::FileKind::DATA, // kind
            1000,                           // size
            "file1.txt".to_string(),
        )),
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file2,
            toxcore::types::FileKind::DATA, // kind
            2000,                           // size
            "file2.txt".to_string(),
        )),
    );

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

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

    // file1 to 50%.
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

    // file2 to 25%.
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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(1);

    let file_id = FileId([100u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1000,
            "old_file.txt".to_string(),
        )),
    );

    update(
        &mut model,
        Msg::IO(IOEvent::FileFinished(pk, file_id, None)),
    );

    // A second transfer reusing ID 100. Real IDs are random 32 bytes, so they're unlikely to collide.
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            2000,
            "new_file.txt".to_string(),
        )),
    );

    // Progress for ID 100 goes to new_file.txt.
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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(1);

    // The first transfer with ID 100, finished.
    let file_id = FileId([100u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1000,
            "old_file.txt".to_string(),
        )),
    );
    update(
        &mut model,
        Msg::IO(IOEvent::FileFinished(pk, file_id, None)),
    );

    // The second, reusing ID 100, still going.
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            2000,
            "new_file.txt".to_string(),
        )),
    );

    // Select the old message.
    model.ui.ui_mode = toxxi::model::UiMode::Navigation;
    {
        let state = model
            .ui
            .window_state
            .entry(WindowId::Friend(pk))
            .or_default();
        state.msg_list_state.select(Some(0));
    }

    // 'x' on the old, finished transfer's message
    let cmds = update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('x')),
        )),
    );

    // does nothing.
    let has_cancel = cmds.iter().any(|cmd| {
        if let toxxi::msg::Cmd::Tox(toxxi::msg::ToxAction::FileControl(f, fn_id, ctrl)) = cmd {
            *f == pk && *fn_id == file_id && *ctrl == toxcore::types::FileControl::Cancel
        } else {
            false
        }
    });

    assert!(
        !has_cancel,
        "Interaction with finished transfer should be ignored"
    );
}
