#[macro_use]
mod macros;

extern crate serde;

#[cfg(not(feature = "manual"))]
mod core {
    #[path = "generated/mod.rs"]
    mod generated;

    pub use generated::*;

    #[path = "../core/dispatch.rs"]
    pub mod dispatch;

    #[path = "../core/av_dispatch.rs"]
    pub mod av_dispatch;

    pub use dispatch::*;
    pub use av_dispatch::*;
}
#[cfg(feature = "manual")]
#[path = "core/mod.rs"]
mod core;

mod ffi;
pub mod tox;
pub mod toxav;
pub mod types;

pub use types::*;
