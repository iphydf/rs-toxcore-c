//! Calls' bit rates, as bTox uses them: video starts high, toxav's loss
//! reports take it down, and it goes back up while there are none.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::toxav::{ToxAv, ToxAvHandler};
use crate::types::{AvBitRate, FriendNumber, Result};

/// Opus kbit/s.
pub const AUDIO_BIT_RATE: AvBitRate = AvBitRate(48);

/// VP8 kbit/s: where video starts, the most it goes up to, and the least
/// toxav's loss reports take it down to.
pub const VIDEO_BIT_RATE: AvBitRate = AvBitRate(1000);
pub const MAX_VIDEO_BIT_RATE: AvBitRate = AvBitRate(1500);
pub const MIN_VIDEO_BIT_RATE: AvBitRate = AvBitRate(150);

/// Without loss reports for this long, the video bit rate goes up a tenth.
pub const VIDEO_BIT_RATE_STEP: Duration = Duration::from_secs(5);

/// What video goes to each friend we send it to at, and since when.
#[derive(Debug, Default)]
pub struct VideoBitRates(HashMap<FriendNumber, (AvBitRate, Instant)>);

impl VideoBitRates {
    pub fn sending(&self, friend: FriendNumber) -> bool {
        self.0.contains_key(&friend)
    }

    /// Takes the rate a call was placed or answered with.
    pub fn started(&mut self, friend: FriendNumber, bit_rate: AvBitRate) {
        if bit_rate != AvBitRate(0) {
            self.0.insert(friend, (bit_rate, Instant::now()));
        }
    }

    /// Starts sending `friend` video, or stops with 0.
    pub fn set<H: ToxAvHandler>(
        &mut self,
        av: &ToxAv<'_, H>,
        friend: FriendNumber,
        bit_rate: AvBitRate,
    ) -> Result<()> {
        av.video_set_bit_rate(friend, bit_rate)?;
        if bit_rate == AvBitRate(0) {
            self.0.remove(&friend);
        } else {
            self.0.insert(friend, (bit_rate, Instant::now()));
        }
        Ok(())
    }

    /// Takes the rate toxav's loss report on `friend` gives.
    pub fn lost<H: ToxAvHandler>(
        &mut self,
        av: &ToxAv<'_, H>,
        friend: FriendNumber,
        bit_rate: AvBitRate,
    ) -> Result<()> {
        if !self.sending(friend) {
            return Ok(());
        }
        self.set(
            av,
            friend,
            bit_rate.clamp(MIN_VIDEO_BIT_RATE, MAX_VIDEO_BIT_RATE),
        )
    }

    /// Raises the rates that went a step without loss.
    pub fn raise<H: ToxAvHandler>(&mut self, av: &ToxAv<'_, H>) -> Result<()> {
        let raised: Vec<_> = self
            .0
            .iter()
            .filter(|(_, (rate, since))| {
                *rate < MAX_VIDEO_BIT_RATE && since.elapsed() >= VIDEO_BIT_RATE_STEP
            })
            .map(|(friend, (rate, _))| {
                (*friend, MAX_VIDEO_BIT_RATE.min(AvBitRate(rate.0 * 11 / 10)))
            })
            .collect();
        for (friend, rate) in raised {
            self.set(av, friend, rate)?;
        }
        Ok(())
    }

    /// The call with `friend` ended.
    pub fn forget(&mut self, friend: FriendNumber) {
        self.0.remove(&friend);
    }
}
