use toxcore::types::{FileId, PublicKey};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model};

#[test]
fn test_ignores_unknown_file_transfers() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    let event = ToxEvent::FileRecv(
        pk,
        file_id,
        toxcore::types::FileKind(2),
        1024,
        "unknown".to_string(),
    );

    let cmds = update(&mut model, Msg::Tox(event));

    // The transfer isn't added, and is cancelled.
    assert!(!model.domain.file_transfers.contains_key(&file_id));

    let has_cancel = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::FileControl::Cancel)
    });

    assert!(
        has_cancel,
        "Should send CANCEL for a file of an unknown kind"
    );
}

#[test]
fn test_accepts_data_file_transfers() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([101u8; 32]);

    add_test_friend(&mut model, pk);

    let event = ToxEvent::FileRecv(
        pk,
        file_id,
        toxcore::types::FileKind::DATA,
        1024,
        "doc.pdf".to_string(),
    );

    let cmds = update(&mut model, Msg::Tox(event));

    // The transfer is added, and waits for the user to accept it.
    assert!(model.domain.file_transfers.contains_key(&file_id));

    let has_cancel = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(_, _, control))
        if *control == toxcore::types::FileControl::Cancel)
    });

    assert!(!has_cancel, "Should NOT auto-cancel data transfer");
}
