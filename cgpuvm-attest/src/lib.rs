use libc::{c_int, size_t};
use libc::c_char;
use std::ffi::CString;

#[link(name = "azguestattestation")]
extern {
    fn get_attestation_token(app_data: *const u8, pcr_sel: u32, jwt: *mut u8,  jwt_len: *mut size_t, endpoint_url: *const c_char) -> c_int;
}

pub fn attest(data: &[u8], pcrs: u32, endpoint_url: &str) -> Option<Vec<u8>> {
    let endpoint_url_cstring = CString::new(endpoint_url).expect("CString::new failed");
    unsafe {
        let url_ptr = endpoint_url_cstring.as_ptr();
        let mut dstlen = 32*1024;
        let mut dst = Vec::with_capacity(dstlen);
        let pdst = dst.as_mut_ptr();
        let res = get_attestation_token(data.as_ptr(), pcrs, pdst, &mut dstlen, url_ptr);
        dst.set_len(dstlen);
        (res == 0).then_some(dst)
    }
}