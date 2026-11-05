//! toxxis on one network without Tox: what one sends a friend arrives as the
//! friend's event straight away, so tests of what they say to each other
//! (account sync, pairing) run in milliseconds and the same way every time.

use std::collections::{HashSet, VecDeque};

use toxcore::tox::{Address, Connection, UserStatus};
use toxcore::types::PublicKey;

use toxxi::app::effects;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::msg::{Cmd, IOAction, Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::update::{handle_enter, update};

/// More messages than any settled exchange takes.
const MAX_STEPS: usize = 100_000;

pub struct Peer {
    pub key: PublicKey,
    pub model: Model,
    pub name: String,
    pub done: Vec<Cmd>,
}

#[derive(Default)]
pub struct Network {
    pub peers: Vec<Peer>,
    /// Pairs of peers whose Tox are friends and online.
    links: HashSet<(usize, usize)>,
    queue: VecDeque<(usize, Msg)>,
}

/// A model of its own account, named `name`, with the Tox key `key`.
pub fn model(name: &str, key: PublicKey) -> Model {
    let domain = DomainState::new(
        Address::from_public_key(key, 0),
        name.to_owned(),
        String::new(),
        UserStatus::None,
    );
    Model::new(domain, Config::default(), Config::default())
}

impl Network {
    /// Adds a peer and returns its index. Its Tox key is its account's.
    pub fn add(&mut self, model: Model) -> usize {
        self.peers.push(Peer {
            key: model.domain.self_public_key(),
            name: model.domain.self_name.clone(),
            model,
            done: Vec::new(),
        });
        self.peers.len() - 1
    }

    fn index_of(&self, key: &PublicKey) -> Option<usize> {
        self.peers.iter().position(|peer| peer.key == *key)
    }

    fn linked(&self, a: usize, b: usize) -> bool {
        self.links.contains(&(a.min(b), a.max(b)))
    }

    /// Makes two peers online friends.
    pub fn connect(&mut self, a: usize, b: usize) {
        if self.links.insert((a.min(b), a.max(b))) {
            self.status(a, b, Connection::Tcp);
        }
    }

    pub fn disconnect(&mut self, a: usize, b: usize) {
        if self.links.remove(&(a.min(b), a.max(b))) {
            self.status(a, b, Connection::None);
        }
    }

    fn status(&mut self, a: usize, b: usize, connection: Connection) {
        for (to, from) in [(a, b), (b, a)] {
            let key = self.peers[from].key;
            self.queue
                .push_back((to, Msg::Tox(ToxEvent::FriendStatus(key, connection))));
            if connection != Connection::None {
                let name = self.peers[from].name.clone();
                self.queue
                    .push_back((to, Msg::Tox(ToxEvent::FriendName(key, name))));
            }
        }
    }

    /// Types `line` into a peer, as Enter does.
    pub fn enter(&mut self, peer: usize, line: &str) {
        let cmds = handle_enter(&mut self.peers[peer].model, line);
        self.route(peer, cmds);
        self.settle();
    }

    /// Gives a peer a message, and everything that follows from it.
    pub fn send(&mut self, peer: usize, msg: Msg) {
        self.queue.push_back((peer, msg));
        self.settle();
    }

    /// A tick for every peer: what they record on ticks gets recorded.
    pub fn tick(&mut self) {
        for peer in 0..self.peers.len() {
            self.queue.push_back((peer, Msg::System(SystemEvent::Tick)));
        }
        self.settle();
    }

    /// Delivers messages until nobody has anything more to say.
    pub fn settle(&mut self) {
        for _ in 0..MAX_STEPS {
            let Some((peer, msg)) = self.queue.pop_front() else {
                return;
            };
            let cmds = update(&mut self.peers[peer].model, msg);
            self.route(peer, cmds);
        }
        panic!("the network never settled");
    }

    fn route(&mut self, from: usize, cmds: Vec<Cmd>) {
        let cmds = effects(&mut self.peers[from].model, cmds);
        for cmd in cmds {
            match cmd {
                Cmd::Tox(ToxAction::SyncSend(to, bytes)) => self.deliver(from, &to, bytes),
                Cmd::IO(IOAction::AppendEvents(_, pushes)) => {
                    for (to, bytes) in pushes {
                        self.deliver(from, &to, bytes);
                    }
                }
                Cmd::Tox(ToxAction::AddFriend(address, message)) => {
                    match self.index_of(&address.public_key()) {
                        Some(to) => {
                            let key = self.peers[from].key;
                            self.queue
                                .push_back((to, Msg::Tox(ToxEvent::FriendRequest(key, message))));
                        }
                        None => self.peers[from]
                            .done
                            .push(Cmd::Tox(ToxAction::AddFriend(address, message))),
                    }
                }
                // Its online friends learn its new name.
                Cmd::Tox(ToxAction::SetName(name) | ToxAction::SetDeviceName(name)) => {
                    self.peers[from].name = name.clone();
                    let key = self.peers[from].key;
                    for to in 0..self.peers.len() {
                        if self.linked(from, to) {
                            let event = ToxEvent::FriendName(key, name.clone());
                            self.queue.push_back((to, Msg::Tox(event)));
                        }
                    }
                }
                Cmd::Tox(ToxAction::AcceptFriend(key)) => match self.index_of(&key) {
                    Some(to) => self.connect(from, to),
                    None => self.peers[from]
                        .done
                        .push(Cmd::Tox(ToxAction::AcceptFriend(key))),
                },
                cmd @ (Cmd::Tox(_) | Cmd::IO(_) | Cmd::App(_)) => self.peers[from].done.push(cmd),
            }
        }
    }

    fn deliver(&mut self, from: usize, to: &PublicKey, bytes: Vec<u8>) {
        if let Some(to) = self.index_of(to)
            && self.linked(from, to)
        {
            let key = self.peers[from].key;
            self.queue
                .push_back((to, Msg::Tox(ToxEvent::SyncMessage(key, bytes))));
        }
    }
}
