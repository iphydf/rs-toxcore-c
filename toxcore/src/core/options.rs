use crate::ffi;
use crate::types::ToxLogLevel;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

pub trait ToxLogger: Send + Sync {
    fn log(&mut self, level: ToxLogLevel, file: &str, line: u32, func: &str, message: &str);
}

pub struct Options {
    pub(crate) ptr: *mut ffi::Tox_Options,
    // Keep logger alive as long as Options is alive
    #[allow(dead_code)]
    logger: Option<Box<Box<dyn ToxLogger>>>,
}

unsafe impl Send for Options {}
unsafe impl Sync for Options {}

impl Drop for Options {
    fn drop(&mut self) {
        unsafe { ffi::tox_options_free(self.ptr) }
    }
}

impl Options {
    pub fn new() -> Result<Self, crate::types::Tox_Err_Options_New> {
        let ptr = ffi_call!(
            tox_options_new,
            ffi::Tox_Err_Options_New::TOX_ERR_OPTIONS_NEW_OK
        )
        .map_err(crate::types::Tox_Err_Options_New::from)?;
        Ok(Self { ptr, logger: None })
    }

    pub fn ipv6_enabled(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_ipv6_enabled(self.ptr, enabled) };
    }

    pub fn start_port(&mut self, port: u16) {
        unsafe { ffi::tox_options_set_start_port(self.ptr, port) };
    }

    pub fn end_port(&mut self, port: u16) {
        unsafe { ffi::tox_options_set_end_port(self.ptr, port) };
    }

    pub fn udp_enabled(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_udp_enabled(self.ptr, enabled) };
    }

    pub fn local_discovery_enabled(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_local_discovery_enabled(self.ptr, enabled) };
    }

    pub fn dht_announcements_enabled(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_dht_announcements_enabled(self.ptr, enabled) };
    }

    pub fn proxy_type(&mut self, proxy_type: ffi::Tox_Proxy_Type) {
        unsafe { ffi::tox_options_set_proxy_type(self.ptr, proxy_type) };
    }

    pub fn proxy_host(&mut self, host: &str) {
        let host_c = CString::new(host).unwrap();
        unsafe { ffi::tox_options_set_proxy_host(self.ptr, host_c.as_ptr()) };
    }

    pub fn proxy_port(&mut self, port: u16) {
        unsafe { ffi::tox_options_set_proxy_port(self.ptr, port) };
    }

    pub fn tcp_port(&mut self, port: u16) {
        unsafe { ffi::tox_options_set_tcp_port(self.ptr, port) };
    }

    pub fn hole_punching_enabled(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_hole_punching_enabled(self.ptr, enabled) };
    }

    pub fn savedata_type(&mut self, savedata_type: ffi::Tox_Savedata_Type) {
        unsafe { ffi::tox_options_set_savedata_type(self.ptr, savedata_type) };
    }

    pub fn savedata_data(&mut self, data: &[u8]) {
        unsafe { ffi::tox_options_set_savedata_data(self.ptr, data.as_ptr(), data.len()) };
    }

    pub fn experimental_thread_safety(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_experimental_thread_safety(self.ptr, enabled) };
    }

    pub fn experimental_groups_persistence(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_experimental_groups_persistence(self.ptr, enabled) };
    }

    pub fn experimental_disable_dns(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_experimental_disable_dns(self.ptr, enabled) };
    }

    pub fn experimental_owned_data(&mut self, enabled: bool) {
        unsafe { ffi::tox_options_set_experimental_owned_data(self.ptr, enabled) };
    }

    pub fn set_logger<L: ToxLogger + 'static>(&mut self, logger: L) {
        let inner: Box<dyn ToxLogger> = Box::new(logger);
        let mut wrapper = Box::new(inner);
        let ptr = &mut *wrapper as *mut Box<dyn ToxLogger> as *mut std::os::raw::c_void;
        unsafe {
            ffi::tox_options_set_log_callback(self.ptr, Some(dispatch_log_boxed));
            ffi::tox_options_set_log_user_data(self.ptr, ptr);
        }
        self.logger = Some(wrapper);
    }
}

unsafe extern "C" fn dispatch_log_boxed(
    _tox: *mut ffi::Tox,
    level: ffi::Tox_Log_Level,
    file: *const c_char,
    line: u32,
    func: *const c_char,
    message: *const c_char,
    user_data: *mut c_void,
) {
    if !user_data.is_null() {
        let logger = unsafe { &mut *(user_data as *mut Box<dyn ToxLogger>) };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let file = if file.is_null() {
                ""
            } else {
                unsafe { CStr::from_ptr(file).to_str().unwrap_or("") }
            };
            let func = if func.is_null() {
                ""
            } else {
                unsafe { CStr::from_ptr(func).to_str().unwrap_or("") }
            };
            let message = if message.is_null() {
                ""
            } else {
                unsafe { CStr::from_ptr(message).to_str().unwrap_or("") }
            };
            logger.log(level.into(), file, line, func, message);
        }));
    }
}
