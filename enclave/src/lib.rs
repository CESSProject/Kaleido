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
#![feature(core_intrinsics)]

extern crate cess_bncurve;
extern crate sgx_rand;
extern crate sgx_tcrypto;
extern crate sgx_types;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate alloc;

use alloc::vec::Vec;
use cess_bncurve::*;

use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::{env, ptr, slice};

mod pbc;

struct Signatures(Vec<G1>, PublicKey);

static mut SIGNATURES: Signatures = Signatures(Vec::new(), PublicKey::new(G2::zero()));

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

/// Arguments:
/// `seed` is used to compute keys
/// `seed_len` is the number of **elements**, not the number of bytes.
/// `data` is the data that needs to be processed. It should not exceed SGX max memory size
/// `data_len` argument is the number of **elements**, not the number of bytes.
/// `block_size` is the size of the chunks that the data will be sliced to, in bytes.
/// `sig_len` is the number of signatures generated. This should be used to allocate
/// memory to call `get_signatures`
#[no_mangle]
pub extern "C" fn process_data(
    seed: *const u8,
    seed_len: usize,
    data: *mut u8,
    data_len: usize,
    block_size: usize,
    sig_len: &mut usize,
) -> sgx_status_t {
    let d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };
    let s = unsafe { slice::from_raw_parts(seed, seed_len) };

    pbc::init_pairings();
    let (skey, pkey, _sig) = pbc::key_gen_deterministic(s);

    let mut signatures: Vec<G1> = Vec::new();
    d.chunks(block_size).for_each(|chunk| {
        signatures.push(cess_bncurve::sign_message(&chunk.to_vec(), &skey));
    });

    *sig_len = signatures.len();
    
    unsafe {
        SIGNATURES = Signatures(signatures, pkey);
    }

    sgx_status_t::SGX_SUCCESS
}

/// For public key Enclave EDL requires the length of array to be passed along
/// Make sure to pass the correct length of publickey being retrieved
///
#[no_mangle]
pub extern "C" fn get_signature(index: usize, sig_len: usize, sig: *mut u8) {
    unsafe {
        let signature = &SIGNATURES.0[index];
        ptr::copy_nonoverlapping(signature.base_vector().as_ptr(), sig, sig_len);
    }
}

/// For public key Enclave EDL requires the length of array to be passed along
/// Make sure to pass the correct length of publickey being retrieved
///
#[no_mangle]
pub extern "C" fn get_public_key(pkey_len: usize, pkey: *mut u8) {
    unsafe {
        let public_key = SIGNATURES.1;
        ptr::copy_nonoverlapping(public_key.base_vector().as_ptr(), pkey, pkey_len);
    }
}
