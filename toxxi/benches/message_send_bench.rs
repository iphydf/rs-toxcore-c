use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, FriendNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    DomainState, FriendInfo, InternalMessageId, Message, MessageContent, MessageStatus, Model,
    WindowId,
};
use toxxi::ui;

fn setup_model(msg_count: usize) -> (Model, PublicKey) {
    let mut domain = DomainState::new(
        Address([0; 38]),
        PublicKey([0; 32]),
        "Self".into(),
        "Status".into(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let fid = FriendNumber(0);
    let pk = PublicKey([0; 32]);
    domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk),
            status_message: "Status".into(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(fid, pk);

    model.ensure_friend_window(pk);
    let wid = WindowId::Friend(pk);

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

    (model, pk)
}

fn bench_message_send_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_send_rebuild");
    group.sample_size(10);

    // We test with increasingly large histories to show the O(N) scaling
    let message_counts = [100, 1_000, 5_000, 10_000];

    for &count in &message_counts {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &c| {
            // We use iter_batched to ensure each iteration starts with a clean state
            // (N messages, valid layout before the new message invalidates it)
            // Note: Creating 10k messages in setup is slow, but excluded from measurement.
            b.iter_batched(
                || {
                    let (mut model, pk) = setup_model(c);
                    let backend = TestBackend::new(100, 50);
                    let mut terminal = Terminal::new(backend).unwrap();
                    // Warm up cache so we measure incremental update
                    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();
                    (model, pk, terminal)
                },
                |(mut model, pk, mut terminal)| {
                    // 1. Add a message. This calls invalidate_window_cache() (which now preserves layout)
                    model.add_friend_message(
                        pk,
                        MessageType::TOX_MESSAGE_TYPE_NORMAL,
                        "New message triggering re-layout".into(),
                    );

                    // 2. Draw. This triggers draw_messages -> layout.update()
                    // Should be O(1) now.
                    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_message_send_rebuild);
criterion_main!(benches);
