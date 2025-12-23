use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use toxcore::tox::{ToxConnection, ToxUserStatus};
use toxcore::types::{Address, ChatId, MessageType, PublicKey, ToxGroupRole};
use toxxi::config::Config;
use toxxi::export::buffer_to_svg;
use toxxi::model::{
    Conversation, DomainState, FriendInfo, InternalMessageId, Message, MessageContent,
    MessageStatus, Model, PeerId, PeerInfo, WindowId,
};
use toxxi::time::FakeTimeProvider;
use toxxi::ui;
use unicode_width::UnicodeWidthStr;

#[test]
fn test_svg_full_ui_baseline() {
    let self_pk = PublicKey([1u8; 32]);
    let self_addr = Address::from_public_key(self_pk, 0x12345678);
    let domain = DomainState::new(
        self_addr,
        self_pk,
        "Alice".to_string(),
        "Checking lattices...".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let group_id = ChatId([2u8; 32]);
    let window_id = WindowId::Group(group_id);

    let mut conversation = Conversation {
        name: "Refinement Research".to_string(),
        messages: Vec::new(),
        topic: Some("Strict Hic: Nominal Identity & Type Stability".to_string()),
        peers: Vec::new(),
        self_role: Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
        self_name: Some("Alice".to_string()),
        ignored_peers: HashSet::new(),
    };

    let researchers = [
        "Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
        "Mallory", "Niaj",
    ];

    for (i, name) in researchers.iter().enumerate() {
        let pk = PublicKey([i as u8 + 10; 32]);
        conversation.peers.push(PeerInfo {
            id: PeerId(pk),
            name: name.to_string(),
            role: Some(if i == 0 {
                ToxGroupRole::TOX_GROUP_ROLE_FOUNDER
            } else {
                ToxGroupRole::TOX_GROUP_ROLE_USER
            }),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    let friend_pk = PublicKey([3u8; 32]);
    let mut friends = std::collections::HashMap::new();
    friends.insert(
        friend_pk,
        FriendInfo {
            name: "iphy_toxic".to_string(),
            public_key: Some(friend_pk),
            status_message: "Toxic as always".to_string(),
            connection: ToxConnection::TOX_CONNECTION_UDP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    let mut conversations = std::collections::HashMap::new();
    conversations.insert(window_id, conversation);

    let mut domain = domain;
    domain.friends = friends;
    domain.conversations = conversations;

    let fake_time = Arc::new(FakeTimeProvider::new(Instant::now(), SystemTime::now()));
    let mut model =
        Model::new(domain, Config::default(), Config::default()).with_time_provider(fake_time);

    model.ui.window_ids = vec![
        WindowId::Console,
        window_id,
        WindowId::Friend(friend_pk),
        WindowId::Logs,
        WindowId::Files,
    ];
    model.ui.active_window_index = 1;

    let dialogue = [
        (
            "Alice",
            "I've been reviewing the design for the Refined type system. The totality constraint is absolutely critical.",
        ),
        (
            "Bob",
            "Agreed. If we can't guarantee termination for all possible inputs, the solver is useless for high-assurance work.",
        ),
        (
            "Charlie",
            "How are we planning to handle equi-recursive types? Standard solvers often rely on fuel, but we want something more rigorous.",
        ),
        (
            "Alice",
            "Synchronous product construction. By traversing the finite Cartesian product of graph nodes, we ensure totality without heuristics.",
        ),
        (
            "Bob",
            "That essentially turns the problem into a structural simplification of a finite graph, right?",
        ),
        (
            "Alice",
            "Exactly. No fuel, just monotonicity over a lattice of finite height. 📉",
        ),
        (
            "Charlie",
            "I like that approach. It moves us away from the non-determinism of standard C analyzers.",
        ),
        (
            "Alice",
            "The core idea is 'Strict Hic': we forbid pointer type punning entirely. Memory has a Single Nominal Truth.",
        ),
        (
            "Bob",
            "Wait, so even if two structs have the same layout, they are incompatible?",
        ),
        (
            "Alice",
            "Correct. Distinct nominal declarations mean distinct types. It aligns us with Rust's safety model. 🛡️",
        ),
        (
            "Charlie",
            "That should make nominal ID comparisons O(1) instead of recursive structural bisimulation. Huge performance win.",
        ),
        (
            "Alice",
            "The removal of void* is the next step. Every syntactic void* becomes a fresh template parameter T.",
        ),
        (
            "Bob",
            "Occurrence-based freshness? So void *p, void *q becomes T1 *p, T2 *q?",
        ),
        (
            "Alice",
            "Precisely. We only unify them when a semantic link is discovered in the program flow.",
        ),
        (
            "Charlie",
            "What about something like memcpy? In standard C, it's the ultimate type-eraser.",
        ),
        (
            "Alice",
            "We harden it. memcpy<T>(T *dest, const T *src, size_t n). Source and destination must be nominally unified.",
        ),
        (
            "Bob",
            "That might break some legacy patterns, but for the safety-critical subset we're targeting, it's perfect.",
        ),
        (
            "Charlie",
            "How do we handle the ABI if we're specializing at link time? Monomorphization usually causes code bloat. 📈💥",
        ),
        (
            "Alice",
            "We use a cost model to decide when to specialize and when to use generic versions with runtime checks.",
        ),
        (
            "Bob",
            "The generic versions wouldn't even need void* internally; they'd use the most general refinement that fits all call sites.",
        ),
        (
            "Alice",
            "Join(Mutable, Const) = Const. The lattice rules are quite elegant. 💎",
        ),
        (
            "Charlie",
            "I'm still worried about annotations. Researchers love them, but developers hate writing them.",
        ),
        (
            "Alice",
            "The goal is zero annotations. We infer the refinements from captured access patterns. P->cb(P->userdata) creates a link.",
        ),
        ("Bob", "Liquid Types but for C? 🧪🧪"),
        (
            "Alice",
            "Sort of, but grounding it in the nominal identity of the allocation rather than just logical constraints.",
        ),
        (
            "Charlie",
            "Can we apply this to the Linux kernel? Imagine specialized syscall handlers for constant arguments.",
        ),
        (
            "Alice",
            "It would be a huge security win. No more NULL checks if the refinement says it's definitely non-null. 🛡️✨",
        ),
        (
            "Bob",
            "Removing branches in hot paths is also great for performance. The compiler can optimize straight-line code better.",
        ),
        (
            "Alice",
            "I've implemented a small demo for a subset of C. It specialized qsort based on the PSize property of the elements.",
        ),
        ("Charlie", "Did it beat the standard implementation?"),
        (
            "Alice",
            "By 12% in my initial tests. The compiler unrolled loops that it previously couldn't because it knew the alignment refinements.",
        ),
        (
            "Bob",
            "12% is significant. I'd love to see the formal spec for this. 📚",
        ),
        (
            "Alice",
            "I'm finishing the proposal now. I'll send it over. 📥📂",
        ),
        (
            "Charlie",
            "Great. We should also discuss the escape rules for external libraries tomorrow.",
        ),
        (
            "Alice",
            "Agreed. If it escapes, we have to assume modular soundness is compromised for that specific instance.",
        ),
        (
            "Bob",
            "But we can whitelist safe externalities like pthread_create, right?",
        ),
        (
            "Alice",
            "Yes, whitelisting preserves existential integrity for common patterns. 👋",
        ),
    ];

    for i in 0..200 {
        let (sender, content_str) = dialogue[i % dialogue.len()];
        let sender_idx = researchers.iter().position(|&r| r == sender).unwrap();
        let pk = PublicKey([sender_idx as u8 + 10; 32]);

        if i == 180 {
            let msg = Message {
                internal_id: InternalMessageId(model.domain.next_internal_id.0),
                sender: sender.to_string(),
                sender_pk: Some(pk),
                is_self: sender_idx == 0,
                content: MessageContent::FileTransfer {
                    file_id: None,
                    name: "strict_hic_formal_spec.pdf".to_string(),
                    size: 1024 * 1024 * 8,
                    progress: 0.72,
                    speed: "3.1 MB/s".to_string(),
                    is_incoming: true,
                },
                timestamp: model.time_provider.now_local(),
                status: MessageStatus::Incoming,
                message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
                highlighted: false,
            };
            model.domain.next_internal_id.0 += 1;
            if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
                conv.messages.push(msg);
            }
        } else {
            model.add_group_message(
                group_id,
                MessageType::TOX_MESSAGE_TYPE_NORMAL,
                sender.to_string(),
                content_str.to_string(),
                Some(pk),
            );
        }
    }

    // Width=140, Height=43 (Pixel golden ratio)
    let width = 140;
    let height = 43;

    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let svg = buffer_to_svg(buffer);

    // Print the rendered buffer for visual inspection
    for y in 0..height {
        let mut row = String::new();
        let mut x = 0;
        while x < width {
            let cell = &buffer[(x, y)];
            row.push_str(cell.symbol());
            x += UnicodeWidthStr::width(cell.symbol()).max(1) as u16;
        }
        println!("{}", row);
    }

    let size = svg.len();
    assert_eq!(
        size, 31806,
        "SVG size baseline check (Actual size: {})",
        size
    );
}
