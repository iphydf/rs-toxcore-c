use crate::utils::Tell;
use std::collections::HashMap;
use std::sync::mpsc;

use toxcore::tox::events::{
    EventConferenceInvite, EventConferenceMessage, EventConferencePeerListChanged,
    EventConferencePeerName, EventConferenceTitle,
};
use toxcore::tox::{ConferenceNumber, Tox};
use toxcore::types::{ConferenceId, MessageType, PublicKey};

use super::{Session, find_friend, log_error, send_failure};
use crate::model::{InternalMessageId, WindowId};
use crate::msg::{LogContext, Msg, SendFailure, ToxEvent};
use crate::sync::event::ChatId;

fn find_conference(tox: &Tox, id: &ConferenceId) -> Option<ConferenceNumber> {
    tox.conference_by_id(id).ok().map(|c| c.number())
}

/// Sends toxxi the titles of the conferences in the profile.
pub(super) fn announce(tox: &Tox, tx: &mpsc::Sender<Msg>) {
    for conf in tox.conference_chatlist() {
        let cnum = conf.number();
        if let Ok(title_bytes) = conf.title() {
            let title = String::from_utf8_lossy(&title_bytes).into_owned();
            tx.tell(Msg::Tox(ToxEvent::ConferenceTitle(cnum, title, None)));
        }
    }
}

impl Session<'_> {
    fn conference_created(&self, cnum: ConferenceNumber, cid: ConferenceId) {
        self.tx
            .tell(Msg::Tox(ToxEvent::ConferenceCreated(cnum, cid)));
    }

    pub(super) fn send_conference_message(
        &mut self,
        conference_id: ConferenceId,
        message_type: MessageType,
        msg: Vec<u8>,
        internal_id: InternalMessageId,
    ) {
        let sent = find_conference(self.tox, &conference_id)
            .ok_or(SendFailure::Never)
            .and_then(|conference| {
                self.tox
                    .conference(conference)
                    .send_message(message_type, &msg)
                    .map(|_| conference)
                    .map_err(|e| send_failure(self.tx, LogContext::Global, &e))
            });
        self.tx.tell(Msg::Tox(match sent {
            Ok(conference) => ToxEvent::ConferenceMessageSent(conference, internal_id),
            Err(failure) => ToxEvent::MessageSendFailed(
                WindowId::Conference(conference_id),
                internal_id,
                failure,
            ),
        }));
    }

    pub(super) fn create_conference(&mut self) {
        if let Ok(conf) = self.tox.conference_new() {
            if let Some(cid) = conf.id() {
                self.conference_created(conf.number(), cid);
            } else {
                log_error(
                    self.tx,
                    LogContext::Global,
                    "Failed to get conference ID for created conference",
                );
            }
        }
    }

    pub(super) fn make_conference(&mut self, name: &str) -> Option<ChatId> {
        let conf = self.tox.conference_new().ok()?;
        let titled = conf.set_title(name.as_bytes());
        self.check(LogContext::Global, "setting the conference title", titled);
        let cid = conf.id()?;
        self.conference_created(conf.number(), cid);
        Some(ChatId::Conference(cid))
    }

    pub(super) fn delete_conference(&mut self, conference_id: ConferenceId) {
        if let Some(conference_number) = find_conference(self.tox, &conference_id) {
            let deleted = self.tox.conference(conference_number).delete();
            self.check(LogContext::Global, "deleting the conference", deleted);
        }
    }

    pub(super) fn join_conference(&mut self, friend: PublicKey, cookie: Vec<u8>) -> Option<ChatId> {
        let friend_number = find_friend(self.tox, &friend)?;
        match self
            .tox
            .conference_join(&self.tox.friend(friend_number), &cookie)
        {
            Ok(conf) => {
                let cid = conf.id()?;
                self.conference_created(conf.number(), cid);
                Some(ChatId::Conference(cid))
            }
            Err(e) => {
                log_error(
                    self.tx,
                    LogContext::Global,
                    format!("Failed to join conference: {e:?}"),
                );
                None
            }
        }
    }

    pub(super) fn invite_friend_to_conference(
        &mut self,
        conference_id: ConferenceId,
        pk: PublicKey,
    ) {
        if let Some(conference_number) = find_conference(self.tox, &conference_id)
            && let Some(friend_number) = find_friend(self.tox, &pk)
        {
            let invited = self
                .tox
                .conference(conference_number)
                .invite(&self.tox.friend(friend_number));
            self.check(
                LogContext::Friend(pk),
                "inviting to the conference",
                invited,
            );
        }
    }

    pub(super) fn set_conference_topic(&mut self, conference_id: ConferenceId, topic: String) {
        let Some(conference_number) = find_conference(self.tox, &conference_id) else {
            log_error(
                self.tx,
                LogContext::Global,
                format!("SetConferenceTopic: Conference not found for ID {conference_id:?}"),
            );
            return;
        };
        if let Err(e) = self
            .tox
            .conference(conference_number)
            .set_title(topic.as_bytes())
        {
            log_error(
                self.tx,
                LogContext::Global,
                format!("Error setting conference title: {e:?}"),
            );
        } else {
            // Tox tells of others' titles, not our own.
            self.tx.tell(Msg::Tox(ToxEvent::ConferenceTitle(
                conference_number,
                topic,
                Some(self.tox.public_key()),
            )));
        }
    }

    pub(super) fn conference_message(&mut self, e: &EventConferenceMessage) {
        let conf = self.tox.conference(e.conference_number());
        if !conf.peer_number_is_ours(e.peer_number()).unwrap_or(false) {
            let pk = conf.peer_public_key(e.peer_number()).ok();
            self.tx.tell(Msg::Tox(ToxEvent::ConferenceMessage(
                e.conference_number(),
                e.peer_number(),
                e.message_type(),
                e.message().to_vec(),
                pk,
            )));
        }
    }

    pub(super) fn conference_invite(&mut self, e: &EventConferenceInvite) {
        self.friend_event(e.friend_number(), |friend| ToxEvent::ConferenceInvite {
            friend,
            kind: e.conference_type(),
            cookie: e.cookie().to_vec(),
        });
    }

    pub(super) fn conference_title(&mut self, e: &EventConferenceTitle) {
        let title = String::from_utf8_lossy(e.title()).into_owned();
        let setter = self
            .tox
            .conference(e.conference_number())
            .peer_public_key(e.peer_number())
            .ok();
        self.tx.tell(Msg::Tox(ToxEvent::ConferenceTitle(
            e.conference_number(),
            title,
            setter,
        )));
    }

    /// Tox only says that the list changed, so we compare it with the last one
    /// and tell toxxi who joined, left or changed their name.
    pub(super) fn conference_peer_list_changed(&mut self, e: &EventConferencePeerListChanged) {
        let cnum = e.conference_number();
        let conf = self.tox.conference(cnum);
        if let Ok(title_bytes) = conf.title() {
            let title = String::from_utf8_lossy(&title_bytes).into_owned();
            self.tx
                .tell(Msg::Tox(ToxEvent::ConferenceTitle(cnum, title, None)));
        }
        let Ok(peers) = conf.peer_list() else {
            return;
        };
        let mut current_peers = HashMap::new();
        for peer_idx in peers {
            if let Ok(true) = conf.peer_number_is_ours(peer_idx) {
                continue;
            }
            if let Ok(pk) = conf.peer_public_key(peer_idx) {
                let name = conf
                    .peer_name(peer_idx)
                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                    .unwrap_or_else(|_| format!("Peer {}", peer_idx.0));
                current_peers.insert(pk, (peer_idx, name));
            }
        }

        let old_peers = self.conference_peers.entry(cnum).or_default();
        for (pk, (idx, name)) in &current_peers {
            match old_peers.get(pk) {
                None => {
                    self.tx.tell(Msg::Tox(ToxEvent::ConferencePeerJoin(
                        cnum,
                        *idx,
                        name.clone(),
                        *pk,
                    )));
                }
                // The peer number may have changed too, but toxxi doesn't use it.
                Some((_, old_name)) if old_name != name => {
                    self.tx.tell(Msg::Tox(ToxEvent::ConferencePeerName(
                        cnum,
                        *idx,
                        name.clone(),
                        *pk,
                    )));
                }
                Some(_) => {}
            }
        }
        for (pk, (idx, _)) in old_peers.iter() {
            if !current_peers.contains_key(pk) {
                self.tx
                    .tell(Msg::Tox(ToxEvent::ConferencePeerLeave(cnum, *idx, *pk)));
            }
        }
        *old_peers = current_peers;
    }

    pub(super) fn conference_peer_name(&mut self, e: &EventConferencePeerName) {
        let conf = self.tox.conference(e.conference_number());
        if let Ok(pk) = conf.peer_public_key(e.peer_number()) {
            let name = String::from_utf8_lossy(e.name()).into_owned();
            if let Some(peers) = self.conference_peers.get_mut(&e.conference_number())
                && let Some(peer_info) = peers.get_mut(&pk)
            {
                peer_info.1 = name.clone();
            }
            self.tx.tell(Msg::Tox(ToxEvent::ConferencePeerName(
                e.conference_number(),
                e.peer_number(),
                name,
                pk,
            )));
        }
    }
}
