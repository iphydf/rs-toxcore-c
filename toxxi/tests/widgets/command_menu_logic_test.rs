use toxxi::widgets::{Command, CommandMenuState};
use unicode_width::UnicodeWidthStr;

#[test]
fn test_command_menu_nested_transition() {
    let subcommands = vec![
        Command::new("send", "Send a file").args("<path>"),
        Command::new("list", "List transfers"),
    ];

    let commands = vec![
        Command::new("file", "File management").subcommands(subcommands),
        Command::new("about", "Info"),
    ];

    let mut state = CommandMenuState::new(commands);

    // Filter "fi" should show "file"
    state.set_filter("fi".to_string());
    assert_eq!(state.filtered_commands().len(), 1);
    assert_eq!(state.filtered_commands()[0].name, "file");
    assert!(state.parent_path.is_empty());

    // User types space after "file"
    state.set_filter("file ".to_string());

    // Should transition to subcommands
    assert_eq!(state.parent_path, vec!["file".to_string()]);
    assert_eq!(state.filtered_commands().len(), 2);
    assert_eq!(state.filtered_commands()[0].name, "send");
    assert_eq!(state.filtered_commands()[1].name, "list");

    // New filter should work within subcommands
    state.set_filter("file se".to_string());
    assert_eq!(state.filtered_commands().len(), 1);
    assert_eq!(state.filtered_commands()[0].name, "send");

    // Test Ascending: User backspaces the space
    state.set_filter("file".to_string());
    assert!(state.parent_path.is_empty());
    assert_eq!(state.filtered_commands().len(), 1);
    assert_eq!(state.filtered_commands()[0].name, "file");
}

#[test]
fn test_command_menu_case_insensitivity() {
    let commands = vec![Command::new("File", "Case test")];
    let mut state = CommandMenuState::new(commands);

    state.set_filter("file".to_string());
    assert_eq!(state.filtered_commands().len(), 1);

    state.set_filter("FILE ".to_string());
    // Should still resolve if subcommands existed, but here verifies it doesn't crash
}

#[test]
fn test_command_menu_leading_slash_and_spaces() {
    let subcommands = vec![Command::new("send", "Send file")];
    let commands = vec![Command::new("file", "Files").subcommands(subcommands)];
    let mut state = CommandMenuState::new(commands);

    // Leading slash
    state.set_filter("/file ".to_string());
    assert_eq!(state.parent_path, vec!["file".to_string()]);

    // Multiple spaces
    state.set_filter("/file    send".to_string());
    assert_eq!(state.parent_path, vec!["file".to_string()]);
    assert_eq!(state.filter, "send".to_string());
}

#[test]
fn test_command_menu_deep_nesting() {
    let level3 = vec![Command::new("leaf", "Deep item")];
    let level2 = vec![Command::new("mid", "Mid item").subcommands(level3)];
    let commands = vec![Command::new("root", "Root item").subcommands(level2)];

    let mut state = CommandMenuState::new(commands);

    state.set_filter("root mid ".to_string());
    assert_eq!(
        state.parent_path,
        vec!["root".to_string(), "mid".to_string()]
    );
    assert_eq!(state.filtered_commands()[0].name, "leaf");
}

#[test]
fn test_command_menu_selection_stability() {
    let commands = vec![Command::new("apple", ""), Command::new("apply", "")];
    let mut state = CommandMenuState::new(commands);

    state.set_filter("apple".to_string());
    state.list_state.select(Some(0));

    // Change filter so previous selection might be invalid or different
    state.set_filter("app".to_string());
    assert!(state.list_state.selected().is_some());
    assert!(state.list_state.selected().unwrap() < state.filtered_commands().len());

    // Filter matching nothing
    state.set_filter("xyz".to_string());
    assert_eq!(state.list_state.selected(), None);

    // Filter matching again
    state.set_filter("a".to_string());
    assert_eq!(state.list_state.selected(), Some(0));
}

#[test]
fn test_command_menu_complete_with_alias() {
    let commands = vec![Command::new("message", "Msg").alias("m")];
    let mut state = CommandMenuState::new(commands);

    state.set_filter("m".to_string());
    // Completion should return the canonical name, not the alias
    assert_eq!(state.complete(), Some("/message".to_string()));
}

#[test]
fn test_command_menu_navigation() {
    let commands = vec![Command::new("a", ""), Command::new("b", "")];
    let mut state = CommandMenuState::new(commands);

    assert_eq!(state.list_state.selected(), Some(0));
    state.next();
    assert_eq!(state.list_state.selected(), Some(1));
    state.next();
    assert_eq!(state.list_state.selected(), Some(0));
}

#[test]
fn test_command_menu_filter_ignores_description() {
    let commands = vec![
        Command::new("quit", "Exit the application"),
        Command::new("about", "Show info"),
    ];
    let mut state = CommandMenuState::new(commands);

    // "exit" is in the description of "quit", but not the name.
    // It should NOT match "quit".
    state.set_filter("exit".to_string());
    assert_eq!(state.filtered_commands().len(), 0);

    // "show" is in the description of "about".
    state.set_filter("show".to_string());
    assert_eq!(state.filtered_commands().len(), 0);

    // "ab" should match "about".
    state.set_filter("ab".to_string());
    assert_eq!(state.filtered_commands().len(), 1);
    assert_eq!(state.filtered_commands()[0].name, "about");
}

#[test]
fn test_layout_logic_simulation() {
    // Replicate the logic from command_menu.rs
    let available_width = 78;
    let name_col_width = 12;
    let min_desc_width = 20;
    let min_gap = 2;

    let cmd = Command::new("clear", "Clear the current window's messages")
        .args("[all | system]")
        .short_description("SHORT");

    // 1. Calculate max width
    let calculate_width = |c: &Command| -> usize {
        let name_len = c.name.width();
        let effective_name_len = name_len.max(name_col_width);
        let alias_len = 0;
        let args_len = 1 + c.args.width(); // " " + args
        // 2 for prefix (" /")
        2 + effective_name_len + alias_len + args_len
    };

    let content_width = calculate_width(&cmd);
    // prefix(2) + name(12) + args(1 + 14) = 29
    println!("Content Width: {}", content_width);
    assert_eq!(content_width, 2 + 12 + 1 + 14); // 29

    // 2. Alignment Col
    let max_content_width = content_width; // Assuming single item for simplicity
    let max_allowed_col = available_width - min_desc_width; // 78 - 20 = 58
    let alignment_col = (max_content_width + min_gap).min(max_allowed_col); // (29 + 2).min(58) = 31

    println!("Alignment Col: {}", alignment_col);
    assert_eq!(alignment_col, 31);

    // 3. Current Item Calculation
    let current_content_width = content_width;
    let gap = if current_content_width + min_gap <= alignment_col {
        alignment_col - current_content_width
    } else {
        min_gap
    };
    println!("Gap: {}", gap);
    assert_eq!(gap, 2);

    let description_start = current_content_width + gap; // 29 + 2 = 31
    println!("Desc Start: {}", description_start);
    assert_eq!(description_start, 31);

    let available_desc_width = available_width.saturating_sub(description_start); // 78 - 31 = 47
    println!("Available Desc Width: {}", available_desc_width);
    assert_eq!(available_desc_width, 47);

    let long_desc = &cmd.description;
    let long_width = long_desc.width(); // "Clear the current window's messages".len() = 35
    println!("Long Desc Width: {}", long_width);
    assert_eq!(long_width, 35);

    let fits = long_width <= available_desc_width; // 35 <= 47
    println!("Fits: {}", fits);
    assert!(fits, "Long description SHOULD fit!");
}

#[test]
fn test_command_menu_ranking() {
    let commands = vec![
        Command::new("config", "Configuration"),
        Command::new("conf", "Conference"),
        Command::new("co", "Checkout"),
        Command::new("account", "Account settings").alias("ac"),
    ];
    let mut state = CommandMenuState::new(commands);

    // 1. Exact Match vs Prefix
    // "conf" matches "conf" exactly (Score 1000)
    // "config" is a prefix match (Score ~500)
    state.set_filter("conf".to_string());
    let filtered = state.filtered_commands();
    assert_eq!(filtered[0].name, "conf");
    assert_eq!(filtered[1].name, "config");

    // 2. Prefix Ranking by Length (Shorter is better)
    // Input: "c"
    // Expect: "co" (len 2) > "conf" (len 4) > "config" (len 6) > "account" (fuzzy/internal match)
    state.set_filter("c".to_string());
    let filtered = state.filtered_commands();
    assert_eq!(filtered[0].name, "co");
    assert_eq!(filtered[1].name, "conf");
    assert_eq!(filtered[2].name, "config");
    assert_eq!(filtered[3].name, "account");

    // 3. Alias Exact Match vs Name Prefix
    // "ac" is an exact alias for "account" (Score 1000 - 10 = 990)
    // "action" would be a prefix match for "ac" (Score ~500).
    // So "account" should win over "action" when typing "ac".
    let commands_alias = vec![
        Command::new("action", "Do action"),
        Command::new("account", "Acc").alias("ac"),
    ];
    let mut state_alias = CommandMenuState::new(commands_alias);

    state_alias.set_filter("ac".to_string());
    let filtered_alias = state_alias.filtered_commands();
    assert_eq!(filtered_alias[0].name, "account");
    assert_eq!(filtered_alias[1].name, "action");
}

#[test]
fn test_dynamic_command_completion() {
    let commands =
        vec![Command::new("file", "File ops").subcommands(vec![Command::new("send", "Send file")])];
    let mut state = CommandMenuState::new(commands);

    // Simulate user typing "/file send "
    state.set_filter("file send ".to_string());

    // Verify path resolution
    assert_eq!(
        state.parent_path,
        vec!["file".to_string(), "send".to_string()]
    );

    // Inject dynamic commands (as the Model would do)
    state.set_dynamic_commands(vec![
        Command::new("1", "Alice").dynamic(true),
        Command::new("2", "Bob").dynamic(true),
    ]);

    // Default selection should be the first one ("1")
    assert_eq!(state.selected_command().unwrap().name, "1");

    // Test completion
    let completion = state.complete();
    assert_eq!(completion, Some("/file send 1 ".to_string()));

    // Test filtering dynamic commands
    state.set_filter("file send 2".to_string());
    assert_eq!(state.selected_command().unwrap().name, "2");
    let completion = state.complete();
    assert_eq!(completion, Some("/file send 2 ".to_string()));
}

#[test]
fn test_resolve_path_with_arguments() {
    // "file" has no subcommands in this test, behaving like the real "file" command
    let commands = vec![Command::new("file", "File ops")];
    let mut state = CommandMenuState::new(commands);

    // Case 1: Trailing space -> Argument is consumed
    state.set_filter("file send ".to_string());
    assert_eq!(
        state.parent_path,
        vec!["file".to_string(), "send".to_string()]
    );
    assert_eq!(state.filter, "");

    // Case 2: No trailing space -> Argument is being typed
    state.set_filter("file sen".to_string());
    assert_eq!(state.parent_path, vec!["file".to_string()]);
    assert_eq!(state.filter, "sen");

    // Case 3: Multiple arguments
    state.set_filter("file send 1 ".to_string());
    assert_eq!(
        state.parent_path,
        vec!["file".to_string(), "send".to_string(), "1".to_string()]
    );
    assert_eq!(state.filter, "");
}
