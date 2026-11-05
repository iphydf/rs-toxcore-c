use toxcore::tox::{ConferenceNumber, ConferencePeerNumber};
use toxcore::types::PublicKey;
use toxxi::model::{PeerId, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;
use toxxi_testing::create_test_model;

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

    // Alice leaves, which may shift other peers' indices.
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
        // The index no longer exists in conv.peers, but it would still be Bob.
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

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            ConferencePeerNumber(0),
            "Alice".to_string(),
            pk,
        )),
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerLeave(
            cid,
            ConferencePeerNumber(0),
            pk,
        )),
    );

    // Rejoin with a different index but the same key.
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
