#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
use super::tox::Tox;
pub struct Options {
    pub(crate) ptr: *mut ffi::Tox_Options

}
impl Drop for Options {
    fn drop(&mut self) {
        unsafe {
            ffi::tox_options_free(self.ptr)
        }
    }
}
impl Options {
    pub fn new() -> std::result::Result<Self, Tox_Err_Options_New> {
        ffi_call!(tox_options_new, ffi::Tox_Err_Options_New::TOX_ERR_OPTIONS_NEW_OK).map(|val| Self { ptr: val })
    }

    pub fn get_ipv6_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_ipv6_enabled, self.ptr)
    }

    pub fn ipv6_enabled(&mut self, ipv6_enabled: bool) {
        unsafe {
            ffi::tox_options_set_ipv6_enabled(self.ptr, ipv6_enabled)
        }
    }

    pub fn get_udp_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_udp_enabled, self.ptr)
    }

    pub fn udp_enabled(&mut self, udp_enabled: bool) {
        unsafe {
            ffi::tox_options_set_udp_enabled(self.ptr, udp_enabled)
        }
    }

    pub fn get_local_discovery_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_local_discovery_enabled, self.ptr)
    }

    pub fn local_discovery_enabled(&mut self, local_discovery_enabled: bool) {
        unsafe {
            ffi::tox_options_set_local_discovery_enabled(self.ptr, local_discovery_enabled)
        }
    }

    pub fn get_dht_announcements_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_dht_announcements_enabled, self.ptr)
    }

    pub fn dht_announcements_enabled(&mut self, dht_announcements_enabled: bool) {
        unsafe {
            ffi::tox_options_set_dht_announcements_enabled(self.ptr, dht_announcements_enabled)
        }
    }

    pub fn get_proxy_type(&self) -> ToxProxyType {
        unsafe {
            ffi::tox_options_get_proxy_type(self.ptr)
        }.into()
    }

    pub fn proxy_type(&mut self, proxy_type: ToxProxyType) {
        unsafe {
            ffi::tox_options_set_proxy_type(self.ptr, proxy_type.into())
        }
    }

    pub fn get_proxy_host(&self) -> &str {
        unsafe {
            let ptr = ffi::tox_options_get_proxy_host(self.ptr) as *const std::os::raw::c_char;
            std::ffi::CStr::from_ptr(ptr).to_str()
                .unwrap_or("")
        }
    }

    pub fn proxy_host(&mut self, proxy_host: &str) -> bool {
        let proxy_host_cstr = std::ffi::CString::new(proxy_host).unwrap();
        ffi_bool!(tox_options_set_proxy_host, self.ptr, proxy_host_cstr.as_ptr())
    }

    pub fn get_proxy_port(&self) -> u16 {
        unsafe {
            ffi::tox_options_get_proxy_port(self.ptr)
        }
    }

    pub fn proxy_port(&mut self, proxy_port: u16) {
        unsafe {
            ffi::tox_options_set_proxy_port(self.ptr, proxy_port)
        }
    }

    pub fn get_start_port(&self) -> u16 {
        unsafe {
            ffi::tox_options_get_start_port(self.ptr)
        }
    }

    pub fn start_port(&mut self, start_port: u16) {
        unsafe {
            ffi::tox_options_set_start_port(self.ptr, start_port)
        }
    }

    pub fn get_end_port(&self) -> u16 {
        unsafe {
            ffi::tox_options_get_end_port(self.ptr)
        }
    }

    pub fn end_port(&mut self, end_port: u16) {
        unsafe {
            ffi::tox_options_set_end_port(self.ptr, end_port)
        }
    }

    pub fn get_tcp_port(&self) -> u16 {
        unsafe {
            ffi::tox_options_get_tcp_port(self.ptr)
        }
    }

    pub fn tcp_port(&mut self, tcp_port: u16) {
        unsafe {
            ffi::tox_options_set_tcp_port(self.ptr, tcp_port)
        }
    }

    pub fn get_hole_punching_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_hole_punching_enabled, self.ptr)
    }

    pub fn hole_punching_enabled(&mut self, hole_punching_enabled: bool) {
        unsafe {
            ffi::tox_options_set_hole_punching_enabled(self.ptr, hole_punching_enabled)
        }
    }

    pub fn get_savedata_type(&self) -> ToxSavedataType {
        unsafe {
            ffi::tox_options_get_savedata_type(self.ptr)
        }.into()
    }

    pub fn savedata_type(&mut self, savedata_type: ToxSavedataType) {
        unsafe {
            ffi::tox_options_set_savedata_type(self.ptr, savedata_type.into())
        }
    }

    pub fn get_savedata_data(&self) -> Vec<u8> {
        unsafe {
            let size = ffi::tox_options_get_savedata_length(self.ptr);
            let ptr = ffi::tox_options_get_savedata_data(self.ptr);
            std::slice::from_raw_parts(ptr, size).to_vec()
        }
    }

    pub fn savedata_data(&mut self, savedata_data: &[u8]) -> bool {
        ffi_bool!(tox_options_set_savedata_data, self.ptr, savedata_data.as_ptr(), savedata_data.len())
    }

    pub fn get_savedata_length(&self) -> usize {
        unsafe {
            ffi::tox_options_get_savedata_length(self.ptr)
        }
    }

    pub fn savedata_length(&mut self, savedata_length: usize) {
        unsafe {
            ffi::tox_options_set_savedata_length(self.ptr, savedata_length)
        }
    }

    pub fn get_experimental_owned_data(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_owned_data, self.ptr)
    }

    pub fn experimental_owned_data(&mut self, experimental_owned_data: bool) {
        unsafe {
            ffi::tox_options_set_experimental_owned_data(self.ptr, experimental_owned_data)
        }
    }

    pub fn get_experimental_thread_safety(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_thread_safety, self.ptr)
    }

    pub fn experimental_thread_safety(&mut self, experimental_thread_safety: bool) {
        unsafe {
            ffi::tox_options_set_experimental_thread_safety(self.ptr, experimental_thread_safety)
        }
    }

    pub fn get_experimental_groups_persistence(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_groups_persistence, self.ptr)
    }

    pub fn experimental_groups_persistence(&mut self, experimental_groups_persistence: bool) {
        unsafe {
            ffi::tox_options_set_experimental_groups_persistence(self.ptr, experimental_groups_persistence)
        }
    }

    pub fn get_experimental_disable_dns(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_disable_dns, self.ptr)
    }

    pub fn experimental_disable_dns(&mut self, experimental_disable_dns: bool) {
        unsafe {
            ffi::tox_options_set_experimental_disable_dns(self.ptr, experimental_disable_dns)
        }
    }

    pub fn default(&mut self) {
        unsafe {
            ffi::tox_options_default(self.ptr)
        }
    }

    pub fn copy(&mut self, src: &Options) {
        unsafe {
            ffi::tox_options_copy(self.ptr, src.ptr)
        }
    }

    pub fn set_logger<T: ToxLogger + 'static>(&mut self, logger: T) {
        let boxed = Box::new(Box::new(logger) as Box<dyn ToxLogger>);
        let ptr = Box::into_raw(boxed);
        unsafe {
            ffi::tox_options_set_log_callback(self.ptr, Some(tox_log_handler));
            ffi::tox_options_set_log_user_data(self.ptr, ptr as *mut std::ffi::c_void)
        };
    }
}
pub trait ToxLogger: Send + Sync {
    fn log(&mut self, level: ToxLogLevel, file: &str, line: u32, func: &str, message: &str);
}
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

