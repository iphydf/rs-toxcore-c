use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::MessageType;
use toxxi::model::WindowId;
use toxxi::ui::draw;
use toxxi_testing::create_test_model;

#[test]
fn test_ui_multiline_indent() {
    let mut model = create_test_model();
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model
        .session
        .group_numbers
        .insert(toxcore::tox::GroupNumber(1), chat_id);

    let content = "\
feat-ev-loop (2↑ 1↓)
  tox-event (6↑ 1↓)
    latency
      tcp-vuln
        test-logging
    tcp-test         origin/tcp-test [READY]";

    model.add_group_message(
        chat_id,
        MessageType::Normal,
        "System".to_string(),
        content.to_string(),
        None,
    );

    let window_id = WindowId::Group(chat_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .expect("Group window should exist");

    model.set_active_window(window_index);

    let backend = TestBackend::new(120, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // Each line is there, indented. The message's 6 lines are at the bottom of rows 1-16.

    let mut found_lines = 0;
    for y in 0..20 {
        let row: String = (0..120).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("feat-ev-loop") {
            assert!(row.contains("feat-ev-loop (2↑ 1↓)"));
            found_lines += 1;
        } else if row.contains("tox-event") {
            assert!(row.contains("  tox-event (6↑ 1↓)"));
            found_lines += 1;
        } else if row.contains("latency") {
            assert!(row.contains("    latency"));
            found_lines += 1;
        } else if row.contains("tcp-vuln") {
            assert!(row.contains("      tcp-vuln"));
            found_lines += 1;
        } else if row.contains("test-logging") {
            assert!(row.contains("        test-logging"));
            found_lines += 1;
        } else if row.contains("tcp-test") {
            assert!(row.contains("    tcp-test         origin/tcp-test [READY]"));
            found_lines += 1;
        }
    }

    assert_eq!(
        found_lines, 6,
        "Should have found all 6 lines of the multiline message"
    );
}
