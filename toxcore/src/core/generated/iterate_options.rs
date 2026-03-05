#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
use super::tox::Tox;
pub struct IterateOptions {
    pub(crate) ptr: *mut ffi::Tox_Iterate_Options

}
