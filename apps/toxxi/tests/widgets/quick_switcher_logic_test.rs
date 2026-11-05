use toxxi::model::WindowId;
use toxxi::widgets::{QuickSwitcherItem, QuickSwitcherState};

#[test]
fn test_quick_switcher_filtering_basics() {
    let items = vec![
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Alice".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Bob".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Rust Group".to_string(),
            description: "Group".to_string(),
            prefix: "g".to_string(),
        },
    ];
    let mut state = QuickSwitcherState::new(items);

    assert_eq!(state.filtered_items().len(), 3);

    // By name.
    state.input_state.text = "al".to_string();
    let filtered = state.filtered_items();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "Alice");

    // By prefix.
    state.input_state.text = "f:".to_string();
    assert_eq!(state.filtered_items().len(), 2);

    state.input_state.text = "g:".to_string();
    let filtered = state.filtered_items();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "Rust Group");

    // By prefix and name.
    state.input_state.text = "f: b".to_string();
    let filtered = state.filtered_items();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "Bob");
}

#[test]
fn test_quick_switcher_navigation() {
    let items = vec![
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Alice".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Bob".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Charlie".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
    ];
    let mut state = QuickSwitcherState::new(items);

    assert_eq!(state.list_state.selected(), Some(0));

    state.next();
    assert_eq!(state.list_state.selected(), Some(1));

    state.next();
    assert_eq!(state.list_state.selected(), Some(2));

    state.next(); // Wrap around
    assert_eq!(state.list_state.selected(), Some(0));

    state.previous(); // Wrap around
    assert_eq!(state.list_state.selected(), Some(2));
}

#[test]
fn test_quick_switcher_navigation_with_filter() {
    let items = vec![
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Alice".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Bob".to_string(),
            description: "Friend".to_string(),
            prefix: "f".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Rust Group".to_string(),
            description: "Group".to_string(),
            prefix: "g".to_string(),
        },
    ];
    let mut state = QuickSwitcherState::new(items);

    state.input_state.text = "f:".to_string();
    assert_eq!(state.filtered_items().len(), 2);

    state.list_state.select(Some(0));
    state.next();
    assert_eq!(state.list_state.selected(), Some(1));

    state.next(); // Wrap around within filtered list
    assert_eq!(state.list_state.selected(), Some(0));
}

#[test]
fn test_quick_switcher_invalid_prefix() {
    let items = vec![QuickSwitcherItem {
        window: WindowId::Console,
        name: "Alice".to_string(),
        description: "Friend".to_string(),
        prefix: "f".to_string(),
    }];
    let mut state = QuickSwitcherState::new(items);

    // "z:" is not a prefix, so it's a normal query.
    state.input_state.text = "z:".to_string();
    assert_eq!(state.filtered_items().len(), 0); // "Alice" does not contain "z:"

    state.input_state.text = "a:".to_string();
    assert_eq!(state.filtered_items().len(), 0); // "Alice" does not contain ":"

    state.input_state.text = "Ali".to_string();
    assert_eq!(state.filtered_items().len(), 1);
}

#[test]
fn test_quick_switcher_history_search() {
    let items = vec![
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Alice".to_string(),
            description: "I want pizza".to_string(),
            prefix: "h".to_string(),
        },
        QuickSwitcherItem {
            window: WindowId::Console,
            name: "Bob".to_string(),
            description: "Pizza is good".to_string(),
            prefix: "h".to_string(),
        },
    ];
    let mut state = QuickSwitcherState::new(items);

    state.input_state.text = "h: pizza".to_string();
    assert_eq!(state.filtered_items().len(), 2);
}
