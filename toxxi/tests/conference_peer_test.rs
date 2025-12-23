use toxcore::tox::{Address, ConferenceNumber, ConferencePeerNumber, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId, PeerInfo, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_conference_peer_join_leave() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    let pid = ConferencePeerNumber(0);
    let pk = PublicKey([1u8; 32]);
    let peer_name = "Alice".to_string();

    model.session.conference_numbers.insert(cid, conf_id);

    // Ensure conference window exists
    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    // Verify initial state
    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert!(conv.peers.is_empty());
    }

    // Peer Join
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            pid,
            peer_name.clone(),
            pk,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 1);
        assert_eq!(
            conv.peers[0],
            PeerInfo {
                id: PeerId(pk),
                name: peer_name,
                role: None,
                status: ToxUserStatus::TOX_USER_STATUS_NONE,
                is_ignored: false,
                seen_online: true,
            }
        );
    }

    // Peer Leave
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerLeave(cid, pid, pk)),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert!(conv.peers.is_empty());
    }
}

#[test]
fn test_multiple_conference_peers() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    let pid1 = ConferencePeerNumber(0);
    let pid2 = ConferencePeerNumber(1);
    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);
    let name1 = "Alice".to_string();
    let name2 = "Bob".to_string();

    model.session.conference_numbers.insert(cid, conf_id);
    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(cid, pid1, name1.clone(), pk1)),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(cid, pid2, name2.clone(), pk2)),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 2);
        assert!(conv.peers.contains(&PeerInfo {
            id: PeerId(pk1),
            name: name1.clone(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        }));
        assert!(conv.peers.contains(&PeerInfo {
            id: PeerId(pk2),
            name: name2,
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        }));
    }

    // Bob leaves
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerLeave(cid, pid2, pk2)),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 1);
        assert_eq!(conv.peers[0].id, PeerId(pk1));
    }
}

#[test]
fn test_conference_peer_join_non_existent_conference() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    let pid = ConferencePeerNumber(0);
    let pk = PublicKey([1u8; 32]);
    let peer_name = "Alice".to_string();

    model.session.conference_numbers.insert(cid, conf_id);

    // Do NOT call model.ensure_conference_window(conf_id)

    // Peer Join for non-existent conference
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(cid, pid, peer_name, pk)),
    );

    // Verify no conversation was created
    assert!(
        !model
            .domain
            .conversations
            .contains_key(&WindowId::Conference(conf_id))
    );
}
