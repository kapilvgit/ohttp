use libc::{c_char, c_int, size_t};
use std::ffi::CString;

#[link(name = "azguestattestation")]
extern "C" {
    fn get_attestation_token(
        app_data: *const u8,
        pcr_sel: u32,
        jwt: *mut u8,
        jwt_len: *mut size_t,
        endpoint_url: *const c_char,
    ) -> c_int;
}

pub fn attest(data: &[u8], pcrs: u32, endpoint_url: &str) -> Result<Vec<u8>, String> {
    match CString::new(endpoint_url) {
        Ok(endpoint_url_cstring) => unsafe {
            let url_ptr = endpoint_url_cstring.as_ptr();
            let mut dstlen = 32 * 1024;
            let mut dst = Vec::with_capacity(dstlen);
            let pdst = dst.as_mut_ptr();
            if get_attestation_token(data.as_ptr(), pcrs, pdst, &mut dstlen, url_ptr) == 0 {
                dst.set_len(dstlen);
                Ok(dst)
            } else {
                Err("CVM guest attestation library returned a non-0 code.".to_owned())
            }
        },
        _e => Err("Failed to convert endpoint URL to CString.".to_owned()),
    }
}
