#![allow(unused_imports)]
use crate::ffi;
#[allow(unused_imports)]
use crate::types::*;
pub struct Options {
    pub(crate) ptr: *mut ffi::Tox_Options,
}
impl Drop for Options {
    fn drop(&mut self) {
        unsafe { ffi::tox_options_free(self.ptr) }
    }
}
impl Options {
    pub fn new() -> std::result::Result<Self, Tox_Err_Options_New> {
        ffi_call!(
            tox_options_new,
            ffi::Tox_Err_Options_New::TOX_ERR_OPTIONS_NEW_OK
        )
        .map(|val| Self { ptr: val })
    }

    pub fn get_ipv6_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_ipv6_enabled, self.ptr)
    }

    pub fn ipv6_enabled(&mut self, ipv6_enabled: bool) {
        unsafe { ffi::tox_options_set_ipv6_enabled(self.ptr, ipv6_enabled) }
    }

    pub fn get_udp_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_udp_enabled, self.ptr)
    }

    pub fn udp_enabled(&mut self, udp_enabled: bool) {
        unsafe { ffi::tox_options_set_udp_enabled(self.ptr, udp_enabled) }
    }

    pub fn get_local_discovery_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_local_discovery_enabled, self.ptr)
    }

    pub fn local_discovery_enabled(&mut self, local_discovery_enabled: bool) {
        unsafe { ffi::tox_options_set_local_discovery_enabled(self.ptr, local_discovery_enabled) }
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
        unsafe { ffi::tox_options_get_proxy_type(self.ptr) }.into()
    }

    pub fn proxy_type(&mut self, proxy_type: ToxProxyType) {
        unsafe { ffi::tox_options_set_proxy_type(self.ptr, proxy_type.into()) }
    }

    pub fn get_proxy_host(&self) -> &str {
        unsafe {
            let ptr = ffi::tox_options_get_proxy_host(self.ptr) as *const std::os::raw::c_char;
            if ptr.is_null() {
                ""
            } else {
                std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("")
            }
        }
    }

    pub fn proxy_host(&mut self, proxy_host: &str) -> bool {
        let proxy_host_cstr = c_str!(proxy_host);
        ffi_bool!(
            tox_options_set_proxy_host,
            self.ptr,
            proxy_host_cstr.as_ptr()
        )
    }

    pub fn get_proxy_port(&self) -> u16 {
        unsafe { ffi::tox_options_get_proxy_port(self.ptr) }
    }

    pub fn proxy_port(&mut self, proxy_port: u16) {
        unsafe { ffi::tox_options_set_proxy_port(self.ptr, proxy_port) }
    }

    pub fn get_start_port(&self) -> u16 {
        unsafe { ffi::tox_options_get_start_port(self.ptr) }
    }

    pub fn start_port(&mut self, start_port: u16) {
        unsafe { ffi::tox_options_set_start_port(self.ptr, start_port) }
    }

    pub fn get_end_port(&self) -> u16 {
        unsafe { ffi::tox_options_get_end_port(self.ptr) }
    }

    pub fn end_port(&mut self, end_port: u16) {
        unsafe { ffi::tox_options_set_end_port(self.ptr, end_port) }
    }

    pub fn get_tcp_port(&self) -> u16 {
        unsafe { ffi::tox_options_get_tcp_port(self.ptr) }
    }

    pub fn tcp_port(&mut self, tcp_port: u16) {
        unsafe { ffi::tox_options_set_tcp_port(self.ptr, tcp_port) }
    }

    pub fn get_hole_punching_enabled(&self) -> bool {
        ffi_bool!(tox_options_get_hole_punching_enabled, self.ptr)
    }

    pub fn hole_punching_enabled(&mut self, hole_punching_enabled: bool) {
        unsafe { ffi::tox_options_set_hole_punching_enabled(self.ptr, hole_punching_enabled) }
    }

    pub fn get_savedata_type(&self) -> ToxSavedataType {
        unsafe { ffi::tox_options_get_savedata_type(self.ptr) }.into()
    }

    pub fn savedata_type(&mut self, savedata_type: ToxSavedataType) {
        unsafe { ffi::tox_options_set_savedata_type(self.ptr, savedata_type.into()) }
    }

    pub fn get_savedata_data(&self) -> Vec<u8> {
        unsafe {
            let size = ffi::tox_options_get_savedata_length(self.ptr);
            let ptr = ffi::tox_options_get_savedata_data(self.ptr);
            if ptr.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(ptr, size).to_vec()
            }
        }
    }

    pub fn savedata_data(&mut self, savedata_data: &[u8]) -> bool {
        ffi_bool!(
            tox_options_set_savedata_data,
            self.ptr,
            savedata_data.as_ptr(),
            savedata_data.len()
        )
    }

    pub fn get_savedata_length(&self) -> usize {
        unsafe { ffi::tox_options_get_savedata_length(self.ptr) }
    }

    pub fn savedata_length(&mut self, savedata_length: usize) {
        unsafe { ffi::tox_options_set_savedata_length(self.ptr, savedata_length) }
    }

    pub fn get_experimental_owned_data(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_owned_data, self.ptr)
    }

    pub fn experimental_owned_data(&mut self, experimental_owned_data: bool) {
        unsafe { ffi::tox_options_set_experimental_owned_data(self.ptr, experimental_owned_data) }
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
            ffi::tox_options_set_experimental_groups_persistence(
                self.ptr,
                experimental_groups_persistence,
            )
        }
    }

    pub fn get_experimental_disable_dns(&self) -> bool {
        ffi_bool!(tox_options_get_experimental_disable_dns, self.ptr)
    }

    pub fn experimental_disable_dns(&mut self, experimental_disable_dns: bool) {
        unsafe { ffi::tox_options_set_experimental_disable_dns(self.ptr, experimental_disable_dns) }
    }

    pub fn default(&mut self) {
        unsafe { ffi::tox_options_default(self.ptr) }
    }

    pub fn copy(&mut self, src: &Options) {
        unsafe { ffi::tox_options_copy(self.ptr, src.ptr) }
    }
}
