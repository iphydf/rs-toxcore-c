use toxxi::widgets::{ContactStatus, SidebarItem, SidebarItemType, SidebarState};

#[test]
fn test_sidebar_category_collapsing() {
    let mut state = SidebarState {
        items: vec![
            SidebarItem::new("Friends", SidebarItemType::Category),
            SidebarItem::new("Alice", SidebarItemType::Friend),
            SidebarItem::new("Groups", SidebarItemType::Category),
            SidebarItem::new("Rust Group", SidebarItemType::Group),
        ],
        ..Default::default()
    };

    // Initially nothing collapsed
    assert!(!state.is_collapsed(SidebarItemType::Friend));

    // Toggle Friends category
    state.toggle_category(SidebarItemType::Friend);
    assert!(state.is_collapsed(SidebarItemType::Friend));
    assert!(!state.is_collapsed(SidebarItemType::Group));

    // Toggle back
    state.toggle_category(SidebarItemType::Friend);
    assert!(!state.is_collapsed(SidebarItemType::Friend));
}

#[test]
fn test_sidebar_item_builder() {
    let item = SidebarItem::new("Alice", SidebarItemType::Friend)
        .status(ContactStatus::Away)
        .unread(5);

    assert_eq!(item.name, "Alice");
    assert_eq!(item.status, ContactStatus::Away);
    assert_eq!(item.unread_count, 5);
}
