use toxcore::types::PublicKey;
use toxxi::commands::io::COMMANDS;
use toxxi::model::{ConsoleMessageType, Model};
use toxxi_testing as testing;

fn create_test_model() -> Model {
    let mut model = testing::create_test_model();
    // Add a friend, so the command gets to the path expansion we test.
    testing::add_test_friend(&mut model, PublicKey([0xAAu8; 32]));
    model
}

#[test]
fn test_file_send_expands_home_tilde() {
    let mut model = create_test_model();

    let args = vec!["send", "aaaaaaaa", "~/toxxi_test_non_existent.txt"];
    let cmd_def = COMMANDS.iter().find(|c| c.name == "file").unwrap();
    let _ = (cmd_def.exec)(&mut model, &args);

    let last_msg = model
        .domain
        .console_messages
        .last()
        .expect("Should have a console message");

    assert_eq!(last_msg.msg_type, ConsoleMessageType::Error);

    println!("Last message content: {:?}", last_msg.content);

    let text = last_msg
        .content
        .as_text()
        .expect("Message content should be text");

    if let Some(user_dirs) = directories::UserDirs::new() {
        let home = user_dirs.home_dir().to_string_lossy();
        assert!(
            text.contains(&home.to_string()),
            "Error message '{}' does not contain home dir '{}'",
            text,
            home
        );
        assert!(text.ends_with("toxxi_test_non_existent.txt"));
        assert!(!text.contains("~/"), "Tilde was not expanded");
    } else {
        println!("Skipping expansion check because UserDirs could not be determined.");
    }
}
