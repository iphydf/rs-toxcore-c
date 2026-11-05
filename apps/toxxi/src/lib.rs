#![deny(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm
)]

pub mod app;
pub mod bootstrap;
pub mod call_bridge;
pub mod commands;
pub mod completion;
pub mod config;
pub mod disk;
pub mod emojis;
pub mod export;
pub mod io;
pub mod model;
pub mod msg;
pub mod screenshot;
pub mod sync;
pub mod terminal;
pub mod text;
pub mod time;
pub mod ui;
pub mod update;
pub mod utils;
pub mod widgets;
pub mod worker;
