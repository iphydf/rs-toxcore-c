use toxcore::tox::{
    ConferenceNumber, ConferencePeerNumber, GroupNumber, GroupPeerNumber, MessageType,
};
use toxcore::types::{ConferenceId, GroupChatId, GroupRole, PublicKey};
use toxxi::model::{Model, PeerId, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;
use toxxi_testing::create_test_model;

const PK: PublicKey = PublicKey([7u8; 32]);

fn tox(model: &mut Model, event: ToxEvent) {
    update(model, Msg::Tox(event));
}

fn last_line(model: &Model, window: WindowId) -> (String, String) {
    let msg = model.domain.conversations[&window].messages.last().unwrap();
    (
        msg.sender.clone(),
        msg.content.as_text().unwrap_or_default().to_owned(),
    )
}

fn listed_name(model: &Model, window: WindowId) -> String {
    let conv = &model.domain.conversations[&window];
    conv.peers
        .iter()
        .find(|p| p.id == PeerId(PK))
        .unwrap()
        .name
        .clone()
}

#[test]
fn a_renamed_group_member_has_the_new_name_everywhere() {
    let mut model = create_test_model();
    let g = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    model.session.group_numbers.insert(g, chat_id);
    model.ensure_group_window(chat_id);
    let window = WindowId::Group(chat_id);
    let p = GroupPeerNumber(1);

    tox(
        &mut model,
        ToxEvent::GroupPeerJoin(g, p, "old".to_owned(), GroupRole::User, PK),
    );
    tox(
        &mut model,
        ToxEvent::GroupMessage(g, p, MessageType::Normal, b"hi".to_vec(), Some(PK)),
    );
    assert_eq!(last_line(&model, window).0, "old");

    tox(
        &mut model,
        ToxEvent::GroupPeerName(g, p, "new".to_owned(), GroupRole::User, PK),
    );
    tox(
        &mut model,
        ToxEvent::GroupMessage(g, p, MessageType::Normal, b"hi".to_vec(), Some(PK)),
    );
    assert_eq!(last_line(&model, window).0, "new");
    tox(
        &mut model,
        ToxEvent::GroupPrivateMessage(g, p, MessageType::Normal, b"psst".to_vec(), PK),
    );
    assert_eq!(last_line(&model, window).0, "new");
    tox(
        &mut model,
        ToxEvent::GroupTopic(g, "topic".to_owned(), Some(PK)),
    );
    assert!(
        last_line(&model, window)
            .1
            .contains("new changed the topic")
    );
    assert_eq!(listed_name(&model, window), "new");
}

#[test]
fn a_message_from_someone_not_in_the_member_list_has_their_number() {
    let mut model = create_test_model();
    let g = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    model.session.group_numbers.insert(g, chat_id);
    model.ensure_group_window(chat_id);

    tox(
        &mut model,
        ToxEvent::GroupMessage(
            g,
            GroupPeerNumber(9),
            MessageType::Normal,
            b"hi".to_vec(),
            Some(PK),
        ),
    );
    assert_eq!(last_line(&model, WindowId::Group(chat_id)).0, "Peer 9");
}

#[test]
fn a_renamed_conference_member_has_the_new_name_on_messages() {
    let mut model = create_test_model();
    let c = ConferenceNumber(0);
    let conf_id = ConferenceId([6u8; 32]);
    model.session.conference_numbers.insert(c, conf_id);
    model.ensure_conference_window(conf_id);
    let window = WindowId::Conference(conf_id);
    let p = ConferencePeerNumber(1);

    tox(
        &mut model,
        ToxEvent::ConferencePeerJoin(c, p, "old".to_owned(), PK),
    );
    tox(
        &mut model,
        ToxEvent::ConferencePeerName(c, p, "new".to_owned(), PK),
    );
    tox(
        &mut model,
        ToxEvent::ConferenceMessage(c, p, MessageType::Normal, b"hi".to_vec(), Some(PK)),
    );
    assert_eq!(last_line(&model, window).0, "new");
    assert_eq!(listed_name(&model, window), "new");
}
