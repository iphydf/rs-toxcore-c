// The log callback, as a `ToxLogger` trait object. apigen doesn't wrap C
// callbacks or their `void *` user data.
use super::options::Options;
use crate::ffi;
use crate::types::*;

// The toxcore log callback can run on another thread.
pub trait ToxLogger: Send + Sync {
    fn log(&mut self, level: ToxLogLevel, file: &str, line: u32, func: &str, message: &str);
}

impl Options {
    pub fn set_logger<T: ToxLogger + 'static>(&mut self, logger: T) {
        let boxed = Box::new(Box::new(logger) as Box<dyn ToxLogger>);
        let ptr = Box::into_raw(boxed);
        unsafe {
            ffi::tox_options_set_log_callback(self.ptr, Some(tox_log_handler));
            ffi::tox_options_set_log_user_data(self.ptr, ptr as *mut std::ffi::c_void)
        };
    }
}

// `CStr::from_ptr` and the `user_data` deref are UB on null, and a panic must
// not unwind into C.
extern "C" fn tox_log_handler(
    _tox: *mut ffi::Tox,
    level: ffi::Tox_Log_Level,
    file: *const std::os::raw::c_char,
    line: u32,
    func: *const std::os::raw::c_char,
    message: *const std::os::raw::c_char,
    user_data: *mut std::ffi::c_void,
) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: `user_data` is the `Box<dyn ToxLogger>` installed by
    // `set_logger`; a panic in the user logger must not unwind into C.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let logger = &mut *(user_data as *mut Box<dyn ToxLogger>);
        let file = if file.is_null() {
            ""
        } else {
            std::ffi::CStr::from_ptr(file).to_str().unwrap_or("")
        };
        let func = if func.is_null() {
            ""
        } else {
            std::ffi::CStr::from_ptr(func).to_str().unwrap_or("")
        };
        let message = if message.is_null() {
            ""
        } else {
            std::ffi::CStr::from_ptr(message).to_str().unwrap_or("")
        };
        logger.log(level.into(), file, line, func, message);
    }));
}
