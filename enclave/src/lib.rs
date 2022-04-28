// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "cess_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_rand;
extern crate sgx_types;
extern crate sgx_tcrypto;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub use self::bncurve::*;
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::ptr;

mod bncurve;
mod pbc;

#[no_mangle]
pub extern "C" fn get_rng(length: usize, value: *mut u8) -> sgx_status_t {
    let mut random_vec = vec![0u8; length];
    let random_slice = &mut random_vec[..];

    let mut rng = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    rng.fill_bytes(random_slice);

    unsafe {
        ptr::copy_nonoverlapping(random_slice.as_ptr(), value, length);
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn process_data() -> sgx_status_t {
    println!("Initializing Pairings");
    pbc::init_pairings();

    // -------------------------------------
    // on Secure pairings
    // test PRNG
    println!("rand Zr = {}", bncurve::Zr::random().to_str());

    // Test Hash
    let h = Hash::from_vector(b"");
    println!("hash(\"\") = {}", h.to_str());
    assert_eq!(
        h.to_str(),
        "H(a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a)"
    );
    println!("");

    // test keying...
    let (skey, pkey, sig) = pbc::key_gen();
    println!("-------RANDOM KEY-------");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(check_keying(&pkey, &sig));
    sgx_status_t::SGX_SUCCESS
}
