// Hand-written safe wrappers for the events iteration API. `Tox_Iterate_Options`
// lives in tox_private.h which apigen cannot parse, so its constructor and
// setters are written by hand against the bindgen-generated FFI symbols.
use super::iterate_options::IterateOptions;
use super::tox::Tox;
use super::tox::ToxEvents;
use crate::ffi;
use crate::types::*;

impl IterateOptions {
    /// Allocate a new `Tox_Iterate_Options` initialised with default values.
    pub fn new() -> std::result::Result<Self, Tox_Err_Iterate_Options_New> {
        let mut err = ffi::Tox_Err_Iterate_Options_New::TOX_ERR_ITERATE_OPTIONS_NEW_OK;
        let ptr = unsafe { ffi::tox_iterate_options_new(&mut err) };
        if err == ffi::Tox_Err_Iterate_Options_New::TOX_ERR_ITERATE_OPTIONS_NEW_OK {
            Ok(IterateOptions { ptr })
        } else {
            Err(err.into())
        }
    }

    /// Set whether iteration should fail hard on the first error.
    pub fn fail_hard(&mut self, fail_hard: bool) {
        unsafe { ffi::tox_iterate_options_set_fail_hard(self.ptr, fail_hard) };
    }
}

impl Drop for IterateOptions {
    fn drop(&mut self) {
        unsafe { ffi::tox_iterate_options_free(self.ptr) };
    }
}

impl Tox {
    /// Run a single iteration and record all events. If no options are given,
    /// default options are used.
    pub fn events_iterate(
        &self,
        options: Option<&IterateOptions>,
    ) -> std::result::Result<ToxEvents<'_>, Tox_Err_Events_Iterate> {
        match options {
            Some(opts) => ToxEvents::iterate(self, opts),
            None => {
                let opts = IterateOptions::new().map_err(|_| {
                    Tox_Err_Events_Iterate::from(
                        ffi::Tox_Err_Events_Iterate::TOX_ERR_EVENTS_ITERATE_MALLOC,
                    )
                })?;
                ToxEvents::iterate(self, &opts)
            }
        }
    }
}
