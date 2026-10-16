#![allow(unused_imports)]
use super::tox::Tox;
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
pub struct IterateOptions {
    pub(crate) ptr: *mut ffi::Tox_Iterate_Options,
}
