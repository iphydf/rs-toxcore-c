use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ratatui::{Terminal, backend::TestBackend};
use std::hint::black_box;
use toxcore::tox::{Address, FriendNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    DomainState, FriendInfo, InternalMessageId, Message, MessageContent, MessageStatus, Model,
    WindowId,
};
use toxxi::ui;

fn setup_model(msg_count: usize, friend_count: usize) -> Model {
    let mut domain = DomainState::new(
        Address([0; 38]),
        PublicKey([0; 32]),
        "Self".into(),
        "Status".into(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    // Populate Friends
    for i in 0..friend_count {
        let mut pk_bytes = [0u8; 32];
        let bytes = (i as u32).to_le_bytes();
        pk_bytes[0] = bytes[0];
        pk_bytes[1] = bytes[1];
        pk_bytes[2] = bytes[2];
        pk_bytes[3] = bytes[3];
        let pk = PublicKey(pk_bytes);

        domain.friends.insert(
            pk,
            FriendInfo {
                name: format!("Friend {}", i),
                public_key: Some(pk),
                status_message: "Status".into(),
                connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
                last_sent_message_id: None,
                last_read_receipt: None,
                is_typing: false,
            },
        );
    }

    let mut model = Model::new(domain, Config::default(), Config::default());

    // Populate session for Friend 0
    let fid0 = FriendNumber(0);
    let pk0_bytes = [0u8; 32]; // 0 -> all zeros
    let pk0 = PublicKey(pk0_bytes);
    model.session.friend_numbers.insert(fid0, pk0);

    // Populate Messages for Friend 0
    model.ensure_friend_window(pk0);
    let wid = WindowId::Friend(pk0);

    if let Some(conv) = model.domain.conversations.get_mut(&wid) {
        for i in 0..msg_count {
            conv.messages.push(Message {
                internal_id: InternalMessageId(i),
                sender: if i % 2 == 0 {
                    "Self".into()
                } else {
                    "Friend".into()
                },
                sender_pk: None,
                is_self: i % 2 == 0,
                content: MessageContent::Text(format!("Message content {}", i)),
                timestamp: chrono::Local::now().fixed_offset(),
                status: MessageStatus::Received,
                message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                highlighted: false,
            });
        }
    }

    model.set_active_window(model.ui.window_ids.iter().position(|&w| w == wid).unwrap());

    model
}

fn bench_draw_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui_draw_scaling");
    group.sample_size(10);

    let friend_count = 100;
    let message_counts = [100, 1_000, 5_000, 10_000, 20_000, 200_000];

    for &count in &message_counts {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &c| {
            let mut model = setup_model(c, friend_count);
            let backend = TestBackend::new(100, 50);
            let mut terminal = Terminal::new(backend).unwrap();

            // Warm up cache: Perform one draw so internal caches are built
            terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

            b.iter(|| {
                terminal
                    .draw(|f| {
                        ui::draw(f, black_box(&mut model));
                    })
                    .unwrap();
            })
        });
    }

    group.finish();

    let mut group = c.benchmark_group("ui_draw_scrolled_top");
    group.sample_size(10);

    for &count in &message_counts {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &c| {
            let mut model = setup_model(c, friend_count);
            let backend = TestBackend::new(100, 50);
            let mut terminal = Terminal::new(backend).unwrap();

            // Warm up cache
            terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

            // Scroll to top (earliest messages)
            model.scroll_top();

            b.iter(|| {
                terminal
                    .draw(|f| {
                        ui::draw(f, black_box(&mut model));
                    })
                    .unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_draw_messages);
criterion_main!(benches);
