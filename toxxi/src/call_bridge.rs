//! The account's calls, in the Tox thread: toxxi has no audio or video of its
//! own, so it connects each call with a friend to a call with one of the
//! account's devices, and passes their frames between the two.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use toxcore::tox::Tox;
use toxcore::toxav::ToxAV;
use toxcore::toxav::bit_rate::{AUDIO_BIT_RATE, VIDEO_BIT_RATE, VideoBitRates};
use toxcore::toxav::events::{AvEvent, AvEvents};
use toxcore::types::{FriendNumber, Result, ToxavCallControl, ToxavFriendCallState};

/// What the model hears of friends' calls; devices' calls aren't its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEvent {
    Ringing {
        friend: FriendNumber,
        video: bool,
    },
    /// Connected to a device.
    Connected {
        friend: FriendNumber,
    },
    Ended {
        friend: FriendNumber,
    },
}

impl CallEvent {
    pub fn friend(&self) -> FriendNumber {
        match self {
            Self::Ringing { friend, .. } | Self::Connected { friend } | Self::Ended { friend } => {
                *friend
            }
        }
    }
}

pub struct CallBridge<'a> {
    av: ToxAV<'a, AvEvents>,
    // Friends' calls ringing here.
    ringing: HashSet<FriendNumber>,
    // Calls placed for a device, by the friend: the device, with video or
    // not, to call once the friend answers.
    placed: HashMap<FriendNumber, (FriendNumber, bool)>,
    // Each call's other end: the friend's for a device's, and the other way.
    peers: HashMap<FriendNumber, FriendNumber>,
    // The friends' ends of `peers`.
    friends: HashSet<FriendNumber>,
    video_bit_rates: VideoBitRates,
}

fn has(state: u32, flag: ToxavFriendCallState) -> bool {
    flag.is_in(state)
}

impl<'a> CallBridge<'a> {
    pub fn new(tox: &'a Tox) -> Result<Self> {
        Ok(Self {
            av: ToxAV::new(tox, AvEvents::default())?,
            ringing: HashSet::new(),
            placed: HashMap::new(),
            peers: HashMap::new(),
            friends: HashSet::new(),
            video_bit_rates: VideoBitRates::default(),
        })
    }

    pub fn iteration_interval(&self) -> Duration {
        Duration::from_millis(self.av.iteration_interval().into())
    }

    pub fn iterate(&mut self) -> Vec<CallEvent> {
        self.av.iterate();
        let mut events = Vec::new();
        for event in std::mem::take(&mut self.av.handler_mut().0) {
            events.extend(self.handle(event));
        }
        // A rate it couldn't raise stays as it was.
        let _ = self.video_bit_rates.raise(&self.av);
        events
    }

    /// Answers `friend`'s call ringing here, or places one, and calls
    /// `device` once it's connected.
    pub fn connect(
        &mut self,
        friend: FriendNumber,
        device: FriendNumber,
        video: bool,
    ) -> Vec<CallEvent> {
        let bit_rate = if video { VIDEO_BIT_RATE } else { 0 };
        if self.ringing.remove(&friend) {
            if self.av.answer(friend, AUDIO_BIT_RATE, bit_rate).is_err() {
                return vec![CallEvent::Ended { friend }];
            }
            self.video_bit_rates.started(friend, bit_rate);
            return self.call_device(friend, device, video);
        }
        if self.peers.contains_key(&friend) || self.placed.contains_key(&friend) {
            return Vec::new();
        }
        if self.av.call(friend, AUDIO_BIT_RATE, bit_rate).is_err() {
            return vec![CallEvent::Ended { friend }];
        }
        self.video_bit_rates.started(friend, bit_rate);
        self.placed.insert(friend, (device, video));
        Vec::new()
    }

    /// Ends `friend`'s call, and its device's.
    pub fn hang_up(&mut self, friend: FriendNumber) {
        let _ = self
            .av
            .call_control(friend, ToxavCallControl::TOXAV_CALL_CONTROL_CANCEL);
        self.forget(friend);
    }

    fn call_device(
        &mut self,
        friend: FriendNumber,
        device: FriendNumber,
        video: bool,
    ) -> Vec<CallEvent> {
        let bit_rate = if video { VIDEO_BIT_RATE } else { 0 };
        if self.av.call(device, AUDIO_BIT_RATE, bit_rate).is_err() {
            self.hang_up(friend);
            return vec![CallEvent::Ended { friend }];
        }
        self.video_bit_rates.started(device, bit_rate);
        self.peers.insert(friend, device);
        self.peers.insert(device, friend);
        self.friends.insert(friend);
        vec![CallEvent::Connected { friend }]
    }

    /// Forgets the call `number` is in, at both ends, ending the other.
    fn forget(&mut self, number: FriendNumber) {
        self.ringing.remove(&number);
        self.placed.remove(&number);
        self.friends.remove(&number);
        self.video_bit_rates.forget(number);
        if let Some(peer) = self.peers.remove(&number) {
            self.peers.remove(&peer);
            self.friends.remove(&peer);
            self.video_bit_rates.forget(peer);
            let _ = self
                .av
                .call_control(peer, ToxavCallControl::TOXAV_CALL_CONTROL_CANCEL);
        }
    }

    fn handle(&mut self, event: AvEvent) -> Vec<CallEvent> {
        match event {
            AvEvent::Call { friend, video } => {
                self.ringing.insert(friend);
                vec![CallEvent::Ringing { friend, video }]
            }
            AvEvent::CallState {
                friend: number,
                state,
            } => {
                let ended = has(state, ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_ERROR)
                    || has(
                        state,
                        ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_FINISHED,
                    );
                if ended {
                    // Of a call with a device, its friend's ends too.
                    let friend = match self.peers.get(&number) {
                        Some(peer) if !self.friends.contains(&number) => *peer,
                        _ => number,
                    };
                    let known = self.ringing.contains(&friend)
                        || self.placed.contains_key(&friend)
                        || self.friends.contains(&friend);
                    self.forget(number);
                    return if known {
                        vec![CallEvent::Ended { friend }]
                    } else {
                        Vec::new()
                    };
                }
                if let Some((device, video)) = self.placed.remove(&number) {
                    // The friend answered.
                    return self.call_device(number, device, video);
                }
                // Video goes to one end while the other sends it.
                if let Some(&peer) = self.peers.get(&number) {
                    let sending = has(
                        state,
                        ToxavFriendCallState::TOXAV_FRIEND_CALL_STATE_SENDING_V,
                    );
                    if sending != self.video_bit_rates.sending(peer) {
                        let bit_rate = if sending { VIDEO_BIT_RATE } else { 0 };
                        let _ = self.video_bit_rates.set(&self.av, peer, bit_rate);
                    }
                }
                Vec::new()
            }
            AvEvent::VideoBitRate { friend, bit_rate } => {
                let _ = self.video_bit_rates.lost(&self.av, friend, bit_rate);
                Vec::new()
            }
            AvEvent::Audio {
                friend,
                pcm,
                channels,
                sampling_rate,
            } => {
                if let Some(&peer) = self.peers.get(&friend) {
                    let _ = self
                        .av
                        .audio_send_frame(peer, &pcm, channels, sampling_rate);
                }
                Vec::new()
            }
            AvEvent::Video { friend, frame } => {
                if let Some(&peer) = self.peers.get(&friend)
                    && self.video_bit_rates.sending(peer)
                {
                    let _ = self.av.video_send_frame(
                        peer,
                        frame.width,
                        frame.height,
                        &frame.y,
                        &frame.u,
                        &frame.v,
                    );
                }
                Vec::new()
            }
        }
    }
}
