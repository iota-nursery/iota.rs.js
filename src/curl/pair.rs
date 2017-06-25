use iota_trytes::*;
use iota_curl::*;
use cty::*;
use alloc::Vec;
use alloc::string::ToString;
use core::mem;
use alloc::boxed::Box;

use util::c_str_to_static_slice;

#[no_mangle]
pub fn curl_pair_new() -> *mut c_void {
    let curl = Box::new(Curl::<BCTrit>::default());
    Box::into_raw(curl) as *mut c_void
}

#[no_mangle]
pub fn curl_pair_delete(c_curl: *mut c_void) {
    unsafe { mem::drop(Box::from_raw(c_curl)) }
}

#[no_mangle]
pub fn curl_pair_absorb(c_curl: *mut c_void, trinary: *const c_char) {
    let trinary_str = unsafe { c_str_to_static_slice(trinary) };
    let trinary: Trinary = trinary_str.chars().collect();

    let curl: &mut Curl<BCTrit>= unsafe { &mut *(c_curl as *mut Curl<BCTrit>) };
    let trits: Vec<BCTrit> = trinary.trits();
    curl.absorb(trits.as_slice());
}

#[no_mangle]
pub fn curl_pair_reset(c_curl: *mut c_void) {
    let mut curl: Box<Curl<BCTrit>> = unsafe { Box::from_raw(c_curl as *mut Curl<BCTrit>) };
    curl.reset();
}

#[no_mangle]
pub fn curl_pair_squeeze(c_curl: *mut c_void, trit_count: isize) -> *const c_char {
    let mut curl: Box<Curl<BCTrit>> = unsafe { Box::from_raw(c_curl as *mut Curl<BCTrit>) };
    let trits = curl.squeeze(trit_count as usize);

    let trinary: Trinary = trits.into_iter().collect();
    let trinary_str = Box::new(trinary.to_string() + "\0");

    &trinary_str.as_bytes()[0] as *const c_char
}
