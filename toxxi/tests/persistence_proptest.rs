use chrono::{DateTime, FixedOffset, Local, TimeZone};
use proptest::prelude::*;
use toxcore::types::*;
use toxxi::model::*;

// Strategies for toxcore types
fn arb_public_key() -> impl Strategy<Value = PublicKey> {
    any::<[u8; 32]>().prop_map(PublicKey)
}

fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 38]>().prop_map(Address)
}

fn arb_file_id() -> impl Strategy<Value = FileId> {
    any::<[u8; 32]>().prop_map(FileId)
}

fn arb_tox_connection() -> impl Strategy<Value = ToxConnection> {
    prop_oneof![
        Just(ToxConnection::TOX_CONNECTION_NONE),
        Just(ToxConnection::TOX_CONNECTION_TCP),
        Just(ToxConnection::TOX_CONNECTION_UDP),
    ]
}

fn arb_tox_user_status() -> impl Strategy<Value = ToxUserStatus> {
    prop_oneof![
        Just(ToxUserStatus::TOX_USER_STATUS_NONE),
        Just(ToxUserStatus::TOX_USER_STATUS_AWAY),
        Just(ToxUserStatus::TOX_USER_STATUS_BUSY),
    ]
}

fn arb_tox_group_role() -> impl Strategy<Value = ToxGroupRole> {
    prop_oneof![
        Just(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
        Just(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR),
        Just(ToxGroupRole::TOX_GROUP_ROLE_USER),
        Just(ToxGroupRole::TOX_GROUP_ROLE_OBSERVER),
    ]
}

fn arb_tox_log_level() -> impl Strategy<Value = ToxLogLevel> {
    prop_oneof![
        Just(ToxLogLevel::TOX_LOG_LEVEL_TRACE),
        Just(ToxLogLevel::TOX_LOG_LEVEL_DEBUG),
        Just(ToxLogLevel::TOX_LOG_LEVEL_INFO),
        Just(ToxLogLevel::TOX_LOG_LEVEL_WARNING),
        Just(ToxLogLevel::TOX_LOG_LEVEL_ERROR),
    ]
}

fn arb_message_type() -> impl Strategy<Value = MessageType> {
    prop_oneof![
        Just(MessageType::TOX_MESSAGE_TYPE_NORMAL),
        Just(MessageType::TOX_MESSAGE_TYPE_ACTION),
    ]
}

fn arb_tox_conference_type() -> impl Strategy<Value = ToxConferenceType> {
    prop_oneof![
        Just(ToxConferenceType::TOX_CONFERENCE_TYPE_TEXT),
        Just(ToxConferenceType::TOX_CONFERENCE_TYPE_AV),
    ]
}

fn arb_datetime() -> impl Strategy<Value = DateTime<FixedOffset>> {
    // Generate timestamps between 1970 and 2038 to avoid overflow issues
    (0i64..2_147_483_647i64).prop_map(|t| {
        let local = Local.timestamp_opt(t, 0).unwrap();
        local.with_timezone(local.offset())
    })
}

prop_compose! {
    fn arb_internal_message_id()(id in any::<usize>()) -> InternalMessageId {
        InternalMessageId(id)
    }
}

prop_compose! {
    fn arb_friend_info()(
        name in r"\PC*",
        public_key in prop::option::weighted(0.9, arb_public_key()),
        status_message in r"\PC*",
        connection in arb_tox_connection(),
        last_sent_message_id in any::<Option<u32>>(),
        last_read_receipt in any::<Option<u32>>(),
    ) -> FriendInfo {
        FriendInfo {
            name,
            public_key,
            status_message,
            connection,
            last_sent_message_id,
            last_read_receipt,
            is_typing: false,
        }
    }
}

fn arb_message_status() -> impl Strategy<Value = MessageStatus> {
    prop_oneof![
        Just(MessageStatus::Incoming),
        Just(MessageStatus::Pending),
        any::<u32>().prop_map(MessageStatus::Sent),
        Just(MessageStatus::Received),
    ]
}

fn arb_message_content() -> impl Strategy<Value = MessageContent> {
    prop_oneof![
        r"\PC*".prop_map(MessageContent::Text),
        prop::collection::vec(r"\PC*", 0..10).prop_map(MessageContent::List),
    ]
}

prop_compose! {
    fn arb_message()(
        internal_id in arb_internal_message_id(),
        sender in r"\PC*",
        sender_pk in prop::option::weighted(0.9, arb_public_key()),
        is_self in any::<bool>(),
        content in arb_message_content(),
        timestamp in arb_datetime(),
        status in arb_message_status(),
        message_type in arb_message_type(),
        highlighted in any::<bool>(),
    ) -> Message {
        Message {
            internal_id,
            sender,
            sender_pk,
            is_self,
            content,
            timestamp,
            status,
            message_type,
            highlighted,
        }
    }
}

fn arb_peer_id() -> impl Strategy<Value = PeerId> {
    arb_public_key().prop_map(PeerId)
}

prop_compose! {
    fn arb_peer_info()(
        id in arb_peer_id(),
        name in r"\PC*",
        role in prop::option::weighted(0.5, arb_tox_group_role()),
        status in arb_tox_user_status(),
        is_ignored in any::<bool>(),
        seen_online in any::<bool>(),
    ) -> PeerInfo {
        PeerInfo {
            id,
            name,
            role,
            status,
            is_ignored,
            seen_online,
        }
    }
}

fn arb_chat_id() -> impl Strategy<Value = GroupChatId> {
    any::<[u8; 32]>().prop_map(GroupChatId)
}

fn arb_conference_id() -> impl Strategy<Value = ConferenceId> {
    any::<[u8; 32]>().prop_map(ConferenceId)
}

prop_compose! {
    fn arb_conversation()(
        name in r"\PC*",
        messages in prop::collection::vec(arb_message(), 0..20),
        topic in any::<Option<String>>(),
        peers in prop::collection::vec(arb_peer_info(), 0..10),
        self_role in prop::option::weighted(0.5, arb_tox_group_role()),
        self_name in any::<Option<String>>(),
        ignored_peers in prop::collection::hash_set(arb_public_key(), 0..5),
    ) -> Conversation {
        Conversation {
            name,
            messages,
            topic,
            peers,
            self_role,
            self_name,
            ignored_peers,
        }
    }
}

fn arb_window_id() -> impl Strategy<Value = WindowId> {
    prop_oneof![
        Just(WindowId::Console),
        arb_public_key().prop_map(WindowId::Friend),
        arb_chat_id().prop_map(WindowId::Group),
        arb_conference_id().prop_map(WindowId::Conference),
        Just(WindowId::Logs),
        Just(WindowId::Files),
    ]
}

fn arb_console_message_type() -> impl Strategy<Value = ConsoleMessageType> {
    prop_oneof![
        Just(ConsoleMessageType::Info),
        Just(ConsoleMessageType::Log),
        Just(ConsoleMessageType::Status),
        Just(ConsoleMessageType::Debug),
        Just(ConsoleMessageType::Error),
    ]
}

prop_compose! {
    fn arb_console_message()(
        msg_type in arb_console_message_type(),
        content in arb_message_content(),
        timestamp in arb_datetime(),
    ) -> ConsoleMessage {
        ConsoleMessage {
            msg_type,
            content,
            timestamp,
        }
    }
}

prop_compose! {
    fn arb_tox_log_item()(
        level in arb_tox_log_level(),
        file in r"\PC*",
        line in any::<u32>(),
        func in r"\PC*",
        message in r"\PC*",
        timestamp in arb_datetime(),
    ) -> ToxLogItem {
        ToxLogItem {
            level,
            file,
            line,
            func,
            message,
            timestamp,
        }
    }
}

prop_compose! {
    fn arb_log_filters()(
        levels in prop::collection::vec(arb_tox_log_level(), 0..5),
        file_pattern in any::<Option<String>>(),
        func_pattern in any::<Option<String>>(),
        msg_pattern in any::<Option<String>>(),
        paused in any::<bool>(),
    ) -> LogFilters {
        LogFilters {
            levels,
            file_pattern,
            func_pattern,
            msg_pattern,
            paused,
        }
    }
}

fn arb_pending_item() -> impl Strategy<Value = PendingItem> {
    prop_oneof![
        (arb_public_key(), r"\PC*")
            .prop_map(|(pk, message)| PendingItem::FriendRequest { pk, message }),
        (arb_public_key(), r"\PC*", r"\PC*").prop_map(|(friend, invite_data, group_name)| {
            PendingItem::GroupInvite {
                friend,
                invite_data,
                group_name,
            }
        }),
        (arb_public_key(), arb_tox_conference_type(), r"\PC*").prop_map(
            |(friend, conference_type, cookie)| PendingItem::ConferenceInvite {
                friend,
                conference_type,
                cookie
            }
        ),
    ]
}

prop_compose! {
    fn arb_window_ui_state()(
        unread_count in any::<usize>(),
        show_peers in any::<bool>(),
        last_height in any::<usize>(),
    ) -> WindowUiState {
        WindowUiState {
            msg_list_state: toxxi::widgets::MessageListState::default(),
            unread_count,
            show_peers,
            last_height,
            cached_messages: None,
            layout: toxxi::widgets::ChatLayout::default(),
            dirty_indices: std::collections::HashSet::new(),
        }
    }
}

fn arb_transfer_status() -> impl Strategy<Value = TransferStatus> {
    prop_oneof![
        Just(TransferStatus::Active),
        Just(TransferStatus::Paused),
        Just(TransferStatus::Completed),
        Just(TransferStatus::Failed),
        Just(TransferStatus::Canceled),
    ]
}

prop_compose! {
    fn arb_file_transfer_progress()(
        filename in r"\PC*",
        total_size in any::<u64>(),
        transferred in any::<u64>(),
        is_receiving in any::<bool>(),
        status in arb_transfer_status(),
        file_kind in any::<u32>(),
        file_path in any::<Option<String>>(),
        friend_pk in arb_public_key(),
    ) -> FileTransferProgress {
        FileTransferProgress {
            filename,
            total_size,
            transferred,
            is_receiving,
            status,
            file_kind,
            file_path,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: transferred,
            friend_pk,
        }
    }
}

prop_compose! {
    fn arb_domain_state()(
        tox_id in arb_address(),
        self_public_key in arb_public_key(),
        self_name in r"\PC*",
        self_status_message in r"\PC*",
        self_status_type in arb_tox_user_status(),
        self_connection_status in arb_tox_connection(),
        friends in prop::collection::hash_map(arb_public_key(), arb_friend_info(), 0..10),
        conversations in prop::collection::hash_map(arb_window_id(), arb_conversation(), 0..10),
        console_messages in prop::collection::vec(arb_console_message(), 0..20),
        tox_logs in prop::collection::hash_map(arb_tox_log_level(), prop::collection::vec_deque(arb_tox_log_item(), 0..20), 0..5),
        pending_items in prop::collection::vec(arb_pending_item(), 0..10),
        next_internal_id in arb_internal_message_id(),
        file_transfers in prop::collection::hash_map(arb_file_id(), arb_file_transfer_progress(), 0..5),
    ) -> DomainState {
        DomainState {
            tox_id,
            self_public_key,
            self_name,
            self_status_message,
            self_status_type,
            self_connection_status,
            friends,
            conversations,
            console_messages,
            tox_logs,
            pending_items,
            next_internal_id,
            file_transfers,
        }
    }
}

prop_compose! {
    fn arb_full_state()(
        domain in arb_domain_state(),
        active_window_index in any::<usize>(),
        window_ids in prop::collection::vec(arb_window_id(), 0..10),
        window_state in prop::collection::hash_map(arb_window_id(), arb_window_ui_state(), 0..10),
        input_history in prop::collection::vec(r"\PC*", 0..20),
        log_filters in arb_log_filters(),
    ) -> FullState {
        FullState {
            domain,
            active_window_index,
            window_ids,
            window_state,
            input_history,
            log_filters,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    #[test]
    fn test_persistence_roundtrip(state in arb_full_state()) {
        let serialized = serde_json::to_string(&state).expect("Failed to serialize");
        let mut actual: FullState = serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Normalize state: some fields are skipped during serialization and will be default after deserialization
        let mut expected = state.clone();
        for s in expected.window_state.values_mut() {
            s.last_height = 0;
        }

        // Messages are now skipped and stored in separate files
        for conv in expected.domain.conversations.values_mut() {
            conv.messages.clear();
        }

        // Normalize transient file transfer fields
        let fixed_now = std::time::Instant::now();
        for p in expected.domain.file_transfers.values_mut() {
            p.speed = 0.0;
            p.last_transferred = 0;
            p.last_update = fixed_now;
        }
        for p in actual.domain.file_transfers.values_mut() {
            p.speed = 0.0;
            p.last_transferred = 0;
            p.last_update = fixed_now;
        }

        // InternalMessageId is serialized within DomainState and thus preserved.
        assert_eq!(expected, actual);
    }
}
