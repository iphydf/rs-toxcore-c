use toxcore::tox::{Address, ConferenceNumber, ConferencePeerNumber, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_conference_peer_index_shift() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    let pk_alice = PublicKey([1u8; 32]);
    let pk_bob = PublicKey([2u8; 32]);

    // Alice joins at index 0
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(0),
            "Alice".to_string(),
            pk_alice,
        )),
    );

    // Bob joins at index 1
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(1),
            "Bob".to_string(),
            pk_bob,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 2);
        assert!(conv.peers.iter().any(|pinfo| pinfo.id == PeerId(pk_alice)));
        assert!(conv.peers.iter().any(|pinfo| pinfo.id == PeerId(pk_bob)));
    }

    // Simulate Alice leaving, which may trigger a peer index shift for other participants.
    // We emit Leave for Alice.
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerLeave(
            cid,
            ConferencePeerNumber(0),
            pk_alice,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 1);
        assert_eq!(conv.peers[0].id, PeerId(pk_bob));
        // Note: The index in conv.peers doesn't even exist anymore, but if we had it,
        // it would still be Bob.
    }
}

#[test]
fn test_conference_peer_name_change() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    let pk = PublicKey([1u8; 32]);

    // Join as "Alice"
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(0),
            "Alice".to_string(),
            pk,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers[0].name, "Alice");
    }

    // Name change to "Ally"
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerName(
            cid,
            ConferencePeerNumber(0),
            "Ally".to_string(),
            pk,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers[0].name, "Ally");
    }
}

#[test]
fn test_conference_peer_rejoin_same_pk() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    let pk = PublicKey([1u8; 32]);

    // Join
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(0),
            "Alice".to_string(),
            pk,
        )),
    );

    // Leave
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerLeave(
            cid,
            ConferencePeerNumber(0),
            pk,
        )),
    );

    // Rejoin with different index but same PK
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(5),
            "Alice".to_string(),
            pk,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.peers.len(), 1);
        assert_eq!(conv.peers[0].id, PeerId(pk));
    }
}
