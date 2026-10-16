//! Adding a device with one action on each side: the home device hands out a
//! link with a one-time code, and the new device's friend request carries it.

use std::time::{Duration, Instant};

use rand::RngCore;
use toxcore::types::Address;

const REQUEST_PREFIX: &str = "pair:";
pub const VALID_FOR: Duration = Duration::from_secs(10 * 60);
const CODE_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingCode([u8; CODE_SIZE]);

impl PairingCode {
    fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        let mut code = [0u8; CODE_SIZE];
        if hex.len() != 2 * code.len() || !hex.is_ascii() {
            return None;
        }
        for (byte, pair) in code.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(code))
    }

    pub fn link(&self, home: &Address) -> String {
        format!("tox:{}?pair={}", home, self.hex())
    }

    pub fn request_message(&self) -> String {
        format!("{}{}", REQUEST_PREFIX, self.hex())
    }

    pub fn from_request(message: &str) -> Option<Self> {
        Self::from_hex(message.strip_prefix(REQUEST_PREFIX)?)
    }
}

/// Codes the home device has handed out, each good for one device.
#[derive(Default)]
pub struct Pairing {
    codes: Vec<(PairingCode, Instant)>,
}

impl Pairing {
    pub fn issue(&mut self, now: Instant) -> PairingCode {
        let mut code = [0u8; CODE_SIZE];
        rand::thread_rng().fill_bytes(&mut code);
        let code = PairingCode(code);
        self.codes.push((code, now));
        code
    }

    pub fn redeem(&mut self, code: PairingCode, now: Instant) -> bool {
        self.codes
            .retain(|(_, issued)| now.duration_since(*issued) < VALID_FOR);
        let issued = self.codes.iter().position(|(c, _)| *c == code);
        issued.map(|i| self.codes.remove(i)).is_some()
    }
}
