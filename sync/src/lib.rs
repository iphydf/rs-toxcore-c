//! Account sync between a user's devices.
#![deny(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm
)]

pub mod account;
pub mod event;
pub mod fact;
pub mod frame;
pub mod pairing;
pub mod protocol;
pub mod replica;
pub mod session;
pub mod setting;
pub mod store;
