use toxxi::widgets::{ContactStatus, SidebarItem, SidebarItemType};

#[test]
fn test_sidebar_item_builder() {
    let item = SidebarItem::new("Alice", SidebarItemType::Friend)
        .status(ContactStatus::Away)
        .unread(5);

    assert_eq!(item.name, "Alice");
    assert_eq!(item.status, ContactStatus::Away);
    assert_eq!(item.unread_count, 5);
}
