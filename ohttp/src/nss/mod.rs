// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::pedantic)]
// Bindgen auto generated code
// won't adhere to the clippy rules below
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::unseparated_literal_suffix)]
#![allow(clippy::used_underscore_binding)]

// pub mod aead;
mod err;
#[macro_use]
mod p11;
pub mod hkdf;
pub mod hpke;

pub use self::p11::{generate_key_pair, random, SymKey};
pub use err::secstatus_to_res;
use lazy_static::lazy_static;
use std::ptr::null;

#[allow(clippy::pedantic, non_upper_case_globals)]
mod nss_init {
    include!(concat!(env!("OUT_DIR"), "/nss_init.rs"));
}

pub use nss_init::SECStatus;
#[allow(non_upper_case_globals)]
pub const SECSuccess: SECStatus = nss_init::_SECStatus_SECSuccess;
#[allow(non_upper_case_globals)]
pub const SECFailure: SECStatus = nss_init::_SECStatus_SECFailure;

#[derive(PartialEq, Eq)]
enum NssLoaded {
    External,
    NoDb,
}

impl Drop for NssLoaded {
    fn drop(&mut self) {
        if *self == Self::NoDb {
            unsafe { secstatus_to_res(nss_init::NSS_Shutdown()).expect("NSS Shutdown failed") }
        }
    }
}

lazy_static! {
    static ref INITIALIZED: NssLoaded = {
        if already_initialized() {
            return NssLoaded::External;
        }

        secstatus_to_res(unsafe { nss_init::NSS_NoDB_Init(null()) }).expect("NSS_NoDB_Init failed");
        secstatus_to_res(unsafe { nss_init::NSS_SetDomesticPolicy() })
            .expect("NSS_SetDomesticPolicy failed");

        NssLoaded::NoDb
    };
}

fn already_initialized() -> bool {
    unsafe { nss_init::NSS_IsInitialized() != 0 }
}

/// Initialize NSS.  This only executes the initialization routines once.
pub fn init() {
    lazy_static::initialize(&INITIALIZED);
}

/// Panic if NSS isn't initialized.
pub fn assert_initialized() {
    assert!(already_initialized());
}