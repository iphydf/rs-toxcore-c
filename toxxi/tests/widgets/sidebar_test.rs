use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::{ContactStatus, Sidebar, SidebarItem, SidebarItemType, SidebarState};

#[test]
fn test_render_sidebar_contacts() {
    let backend = TestBackend::new(30, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = SidebarState {
        items: vec![
            SidebarItem::new("Friends", SidebarItemType::Category),
            SidebarItem::new("Alice", SidebarItemType::Friend).status(ContactStatus::Online),
            SidebarItem::new("Groups", SidebarItemType::Category),
            SidebarItem::new("Rust Group", SidebarItemType::Group)
                .status(ContactStatus::Online)
                .unread(1),
        ],
        ..Default::default()
    };
    state.list_state.select(Some(1));

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 30, 10);
            let widget = Sidebar::default().focused(true);
            f.render_stateful_widget(widget, area, &mut state);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("sidebar_contacts", rendered);
    });
}

// end of file
