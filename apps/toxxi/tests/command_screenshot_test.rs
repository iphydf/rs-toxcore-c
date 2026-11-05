use toxxi::msg::{AppCmd, Cmd};
use toxxi::update::handle_enter;
use toxxi_testing::create_test_model;

#[test]
fn test_screenshot_command_extension() {
    let mut model = create_test_model();

    // No extension.
    let cmds = handle_enter(&mut model, "/screenshot myshot");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert_eq!(path, "myshot.svg");
        assert!(cols.is_none());
        assert!(rows.is_none());
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // With an extension.
    let cmds = handle_enter(&mut model, "/screenshot myshot.svg");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert_eq!(path, "myshot.svg");
        assert!(cols.is_none());
        assert!(rows.is_none());
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // The default name: a timestamp.
    let cmds = handle_enter(&mut model, "/screenshot");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert!(path.starts_with("screenshot-"));
        assert!(path.ends_with(".svg"));
        assert!(cols.is_none());
        assert!(rows.is_none());
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // The /sc alias.
    let cmds = handle_enter(&mut model, "/sc alias_shot");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert_eq!(path, "alias_shot.svg");
        assert!(cols.is_none());
        assert!(rows.is_none());
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // With columns and rows.
    let cmds = handle_enter(&mut model, "/screenshot myshot 120 40");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert_eq!(path, "myshot.svg");
        assert_eq!(*cols, Some(120));
        assert_eq!(*rows, Some(40));
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // Only columns and rows, no file name.
    let cmds = handle_enter(&mut model, "/screenshot 120 40");
    assert_eq!(cmds.len(), 1);
    if let Cmd::App(AppCmd::Screenshot(path, cols, rows)) = &cmds[0] {
        assert!(path.starts_with("screenshot-"));
        assert_eq!(*cols, Some(120));
        assert_eq!(*rows, Some(40));
    } else {
        panic!("Expected AppCmd::Screenshot, got {:?}", cmds[0]);
    }

    // An invalid size: only one number.
    let cmds = handle_enter(&mut model, "/screenshot myshot 120");
    assert_eq!(cmds.len(), 0);
    assert!(model.domain.console_messages.iter().any(|m| m.content
        == toxxi::model::MessageContent::Text(
            "Usage: /screenshot [filename] [cols rows]".to_owned()
        )));
}
