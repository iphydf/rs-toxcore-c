//! What toxav's callbacks give, kept to act on once it's done iterating, as
//! the callbacks can't call toxav themselves.

use crate::toxav::ToxAVHandler;
use crate::types::FriendNumber;

/// A frame without the padding at the end of its planes' rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

impl Frame {
    #[allow(clippy::too_many_arguments)]
    pub fn packed(
        width: u16,
        height: u16,
        y: &[u8],
        u: &[u8],
        v: &[u8],
        ystride: i32,
        ustride: i32,
        vstride: i32,
    ) -> Self {
        let (width_px, height_px) = (usize::from(width), usize::from(height));
        let (chroma_width, chroma_height) = (width_px.div_ceil(2), height_px.div_ceil(2));
        let pack = |plane: &[u8], stride: i32, width: usize, height: usize| {
            let stride = stride.unsigned_abs() as usize;
            (0..height)
                .flat_map(|row| &plane[row * stride..row * stride + width])
                .copied()
                .collect()
        };
        Self {
            width,
            height,
            y: pack(y, ystride, width_px, height_px),
            u: pack(u, ustride, chroma_width, chroma_height),
            v: pack(v, vstride, chroma_width, chroma_height),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvEvent {
    Call {
        friend: FriendNumber,
        video: bool,
    },
    CallState {
        friend: FriendNumber,
        state: u32,
    },
    VideoBitRate {
        friend: FriendNumber,
        bit_rate: u32,
    },
    Audio {
        friend: FriendNumber,
        pcm: Vec<i16>,
        channels: u8,
        sampling_rate: u32,
    },
    Video {
        friend: FriendNumber,
        frame: Frame,
    },
}

/// A handler that keeps each callback's event, for `ToxAV::handler_mut`.
#[derive(Debug, Default)]
pub struct AvEvents(pub Vec<AvEvent>);

impl ToxAVHandler for AvEvents {
    fn on_call(&mut self, friend: FriendNumber, _audio: bool, video: bool) {
        self.0.push(AvEvent::Call { friend, video });
    }

    fn on_call_state(&mut self, friend: FriendNumber, state: u32) {
        self.0.push(AvEvent::CallState { friend, state });
    }

    fn on_video_bit_rate(&mut self, friend: FriendNumber, bit_rate: u32) {
        self.0.push(AvEvent::VideoBitRate { friend, bit_rate });
    }

    fn on_audio_receive_frame(
        &mut self,
        friend: FriendNumber,
        pcm: &[i16],
        channels: u8,
        sampling_rate: u32,
    ) {
        self.0.push(AvEvent::Audio {
            friend,
            pcm: pcm.to_vec(),
            channels,
            sampling_rate,
        });
    }

    fn on_video_receive_frame(
        &mut self,
        friend: FriendNumber,
        width: u16,
        height: u16,
        y: &[u8],
        u: &[u8],
        v: &[u8],
        ystride: i32,
        ustride: i32,
        vstride: i32,
    ) {
        let frame = Frame::packed(width, height, y, u, v, ystride, ustride, vstride);
        self.0.push(AvEvent::Video { friend, frame });
    }
}
