use super::options::Options;
use crate::ffi;
use crate::types::{
    ADDRESS_SIZE, Address, FriendNumber, HASH_LENGTH, PUBLIC_KEY_SIZE, PublicKey, SECRET_KEY_SIZE,
    Tox_Err_Bootstrap, Tox_Err_Events_Iterate, Tox_Err_Get_Port, Tox_Err_New, Tox_Err_Set_Info,
    ToxUserStatus,
};
use std::ffi::CString;

pub struct Tox {
    pub(crate) ptr: *mut ffi::Tox,
}

unsafe impl Send for Tox {}

impl Drop for Tox {
    fn drop(&mut self) {
        unsafe { ffi::tox_kill(self.ptr) };
    }
}

impl Tox {
    pub fn new(options: &Options) -> Result<Self, Tox_Err_New> {
        ffi_call!(tox_new, ffi::Tox_Err_New::TOX_ERR_NEW_OK, options.ptr)
            .map(|ptr| Self { ptr })
            .map_err(|e| e.into())
    }

    pub fn events_init(&self) {
        unsafe { ffi::tox_events_init(self.ptr) };
    }

    pub fn events_iterate(
        &self,
        fail_hard: bool,
    ) -> Result<super::events::ToxEvents<'_>, Tox_Err_Events_Iterate> {
        let ptr = ffi_call!(
            tox_events_iterate,
            ffi::Tox_Err_Events_Iterate::TOX_ERR_EVENTS_ITERATE_OK,
            self.ptr,
            fail_hard
        )
        .map_err(Tox_Err_Events_Iterate::from)?;
        Ok(super::events::ToxEvents::new(ptr))
    }

    pub fn bootstrap(
        &self,
        host: &str,
        port: u16,
        public_key: &PublicKey,
    ) -> Result<(), Tox_Err_Bootstrap> {
        let host_c = CString::new(host).unwrap();
        ffi_call_unit!(
            tox_bootstrap,
            ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK,
            self.ptr,
            host_c.as_ptr(),
            port,
            public_key.0.as_ptr()
        )
        .map_err(|e| e.into())
    }

    pub fn add_tcp_relay(
        &self,
        host: &str,
        port: u16,
        public_key: &PublicKey,
    ) -> Result<(), Tox_Err_Bootstrap> {
        let host_c = CString::new(host).unwrap();
        ffi_call_unit!(
            tox_add_tcp_relay,
            ffi::Tox_Err_Bootstrap::TOX_ERR_BOOTSTRAP_OK,
            self.ptr,
            host_c.as_ptr(),
            port,
            public_key.0.as_ptr()
        )
        .map_err(|e| e.into())
    }

    pub fn iteration_interval(&self) -> u32 {
        unsafe { ffi::tox_iteration_interval(self.ptr) }
    }

    pub fn self_get_address(&self) -> Address {
        let mut addr = [0u8; ADDRESS_SIZE];
        unsafe { ffi::tox_self_get_address(self.ptr, addr.as_mut_ptr()) };
        Address(addr)
    }

    pub fn self_get_public_key(&self) -> PublicKey {
        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        unsafe { ffi::tox_self_get_public_key(self.ptr, pk.as_mut_ptr()) };
        PublicKey(pk)
    }

    pub fn self_get_dht_id(&self) -> PublicKey {
        let mut dht_id = [0u8; PUBLIC_KEY_SIZE];
        unsafe { ffi::tox_self_get_dht_id(self.ptr, dht_id.as_mut_ptr()) };
        PublicKey(dht_id)
    }

    pub fn self_get_udp_port(&self) -> Result<u16, Tox_Err_Get_Port> {
        ffi_call!(
            tox_self_get_udp_port,
            ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK,
            self.ptr
        )
        .map_err(|e| e.into())
    }

    pub fn self_get_tcp_port(&self) -> Result<u16, Tox_Err_Get_Port> {
        ffi_call!(
            tox_self_get_tcp_port,
            ffi::Tox_Err_Get_Port::TOX_ERR_GET_PORT_OK,
            self.ptr
        )
        .map_err(|e| e.into())
    }

    pub fn self_set_name(&self, name: &[u8]) -> Result<(), Tox_Err_Set_Info> {
        ffi_call_unit!(
            tox_self_set_name,
            ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK,
            self.ptr,
            name.as_ptr(),
            name.len()
        )
        .map_err(|e| e.into())
    }

    pub fn self_get_name(&self) -> Vec<u8> {
        ffi_get_vec_simple!(tox_self_get_name, tox_self_get_name_size, u8, self.ptr)
    }

    pub fn self_set_status_message(&self, status_message: &[u8]) -> Result<(), Tox_Err_Set_Info> {
        ffi_call_unit!(
            tox_self_set_status_message,
            ffi::Tox_Err_Set_Info::TOX_ERR_SET_INFO_OK,
            self.ptr,
            status_message.as_ptr(),
            status_message.len()
        )
        .map_err(|e| e.into())
    }

    pub fn self_get_status_message(&self) -> Vec<u8> {
        ffi_get_vec_simple!(
            tox_self_get_status_message,
            tox_self_get_status_message_size,
            u8,
            self.ptr
        )
    }

    pub fn self_set_status(&self, status: ToxUserStatus) {
        unsafe { ffi::tox_self_set_status(self.ptr, status.into()) };
    }

    pub fn self_get_status(&self) -> ToxUserStatus {
        unsafe { ffi::tox_self_get_status(self.ptr).into() }
    }

    pub fn self_get_secret_key(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut sk = [0u8; SECRET_KEY_SIZE];
        unsafe { ffi::tox_self_get_secret_key(self.ptr, sk.as_mut_ptr()) };
        sk
    }

    pub fn self_set_nospam(&self, nospam: u32) {
        unsafe { ffi::tox_self_set_nospam(self.ptr, nospam) };
    }

    pub fn self_get_nospam(&self) -> u32 {
        unsafe { ffi::tox_self_get_nospam(self.ptr) }
    }

    pub fn get_savedata_size(&self) -> usize {
        unsafe { ffi::tox_get_savedata_size(self.ptr) }
    }

    pub fn get_savedata(&self) -> Vec<u8> {
        let size = unsafe { ffi::tox_get_savedata_size(self.ptr) };
        let mut buf = vec![0u8; size];
        unsafe { ffi::tox_get_savedata(self.ptr, buf.as_mut_ptr()) };
        buf
    }

    pub fn self_get_friend_list_size(&self) -> usize {
        unsafe { ffi::tox_self_get_friend_list_size(self.ptr) }
    }

    pub fn self_get_friend_list(&self) -> Vec<FriendNumber> {
        ffi_get_vec_simple!(
            tox_self_get_friend_list,
            tox_self_get_friend_list_size,
            u32,
            self.ptr
        )
        .into_iter()
        .map(FriendNumber)
        .collect()
    }

    pub fn hash(data: &[u8]) -> [u8; HASH_LENGTH] {
        let mut hash = [0u8; HASH_LENGTH];
        unsafe { ffi::tox_hash(hash.as_mut_ptr(), data.as_ptr(), data.len()) };
        hash
    }

    pub fn version_major() -> u32 {
        unsafe { ffi::tox_version_major() }
    }
    pub fn version_minor() -> u32 {
        unsafe { ffi::tox_version_minor() }
    }
    pub fn version_patch() -> u32 {
        unsafe { ffi::tox_version_patch() }
    }

    pub fn version_is_compatible(major: u32, minor: u32, patch: u32) -> bool {
        ffi_bool!(tox_version_is_compatible, major, minor, patch)
    }
}
