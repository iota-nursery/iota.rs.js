use std::ffi::CString;
use std::ffi::CStr;
use std::os::raw::c_char;

use trytes::*;
use curl::*;
use curl::simple::*;
use sign::iss;

#[link_args = "-s EXPORTED_FUNCTIONS=['_subseed','_key','_digest_key','_address','_signature','_digest_bundle_signature']"]
extern "C" {}

#[no_mangle]
pub fn subseed(c_seed: *const c_char, index: usize) -> *mut c_char {
    let c_seed_str = unsafe { CStr::from_ptr(c_seed) };
    let seed_str = c_seed_str.to_str().unwrap();
    let seed: Trinary = seed_str.chars().collect();

    let subseed = iss::subseed(seed, index);

    CString::new(subseed.to_string().as_bytes())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub fn key(c_subseed: *const c_char) -> *mut c_char {
    let c_subseed_str = unsafe { CStr::from_ptr(c_subseed) };
    let subseed_str = c_subseed_str.to_str().unwrap();
    let subseed: Trinary = subseed_str.chars().collect();

    let key = iss::key(subseed);

    CString::new(key.to_string().as_bytes()).unwrap().into_raw()
}

#[no_mangle]
pub fn digest_key(c_key: *const c_char) -> *mut c_char {
    let c_key_str = unsafe { CStr::from_ptr(c_key) };
    let key_str = c_key_str.to_str().unwrap();
    let key: Trinary = key_str.chars().collect();

    let digest = iss::digest_key(key);

    CString::new(digest.to_string().as_bytes())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub fn address(c_digest: *const c_char) -> *mut c_char {
    let c_digest_str = unsafe { CStr::from_ptr(c_digest) };
    let digest_str = c_digest_str.to_str().unwrap();
    let digest: Trinary = digest_str.chars().collect();

    let address = iss::address(digest);

    CString::new(address.to_string().as_bytes())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub fn signature(c_bundle: *const c_char, c_key: *const c_char) -> *mut c_char {
    let c_key_str = unsafe { CStr::from_ptr(c_key) };
    let key_str = c_key_str.to_str().unwrap();
    let key: Trinary = key_str.chars().collect();

    let c_bundle_str = unsafe { CStr::from_ptr(c_bundle) };
    let bundle_str = c_bundle_str.to_str().unwrap();
    let bundle: Trinary = bundle_str.chars().collect();

    let signature = iss::signature(bundle, key);

    CString::new(signature.to_string().as_bytes())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub fn digest_bundle_signature(c_bundle: *const c_char, c_signature: *const c_char) -> *mut c_char {
    let c_signature_str = unsafe { CStr::from_ptr(c_signature) };
    let signature_str = c_signature_str.to_str().unwrap();
    let signature: Trinary = signature_str.chars().collect();

    let c_bundle_str = unsafe { CStr::from_ptr(c_bundle) };
    let bundle_str = c_bundle_str.to_str().unwrap();
    let bundle: Trinary = bundle_str.chars().collect();

    let digest = iss::digest_bundle_signature(bundle, signature);

    CString::new(digest.to_string().as_bytes())
        .unwrap()
        .into_raw()
}
