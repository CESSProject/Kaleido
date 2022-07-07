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
extern crate libc;
extern crate merkletree;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;
extern crate sgx_tcrypto;
extern crate sgx_types;

#[cfg(not(target_env = "sgx"))]
extern crate crypto;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate alloc;

mod merkletree_generator;
mod ocall_def;
mod param;
mod pbc;
mod podr2_proof_commit;

use crate::podr2_proof_commit::podr2_proof_commit;
use alloc::string::ToString;
use alloc::vec::Vec;
use cess_bncurve::*;
use core::intrinsics::forget;
use core::ops::{Index, IndexMut};
use merkletree::merkle::MerkleTree;
use ocall_def::ocall_post_podr2_commit_data;
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::ffi::CString;
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::untrusted::time::SystemTimeEx;
use std::{
    ffi::CStr,
    ptr, slice,
    sync::{Arc, SgxMutex},
    thread, time,
};

struct Keys {
    skey: SecretKey,
    pkey: PublicKey,
    sig: G1,
    generated: bool,
}

impl Keys {
    pub const fn new() -> Keys {
        Keys {
            skey: SecretKey::zero(),
            pkey: PublicKey::zero(),
            sig: G1::zero(),
            generated: false,
        }
    }

    pub fn gen_keys(self: &mut Self, seed: &[u8]) {
        if !self.generated {
            let (skey, pkey, sig) = pbc::key_gen_deterministic(seed);
            self.skey = skey;
            self.pkey = pkey;
            self.sig = sig;
            self.generated = true;
        }
    }

    pub fn get_keys(self: &Self) -> (SecretKey, PublicKey, G1) {
        (self.skey, self.pkey, self.sig)
    }
}

static mut KEYS: Keys = Keys::new();

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
pub extern "C" fn gen_keys(seed: *const u8, seed_len: usize) -> sgx_status_t {
    let s = unsafe { slice::from_raw_parts(seed, seed_len) };

    pbc::init_pairings();
    unsafe {
        KEYS.gen_keys(s);
    }
    sgx_status_t::SGX_SUCCESS
}

/// Arguments:
/// `data` is the data that needs to be processed. It should not exceed SGX max memory size
/// `data_len` argument is the number of **elements**, not the number of bytes.
/// `block_size` is the size of the chunks that the data will be sliced to, in bytes.
/// `sig_len` is the number of signatures generated. This should be used to allocate
/// memory to call `get_signatures`
/// `muilti_thread` if set to true the enclave will use multi thread to compute signatures.
#[no_mangle]
pub extern "C" fn process_data(
    data: *mut u8,
    data_len: usize,
    block_size: usize,
    segment_size: usize,
    callback_url: *const c_char,
) -> sgx_status_t {
    let d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };
    let (skey, pkey, _sig) = unsafe { KEYS.get_keys() };

    let mut podr2_data = podr2_proof_commit::podr2_proof_commit(
        skey.clone(),
        pkey.clone(),
        d.clone(),
        block_size,
        segment_size,
    );

    let c_str = unsafe { CStr::from_ptr(callback_url) };
    podr2_data.callback_url = c_str.to_str().unwrap().to_string();

    // for s in &result.sigmas {
    //     println!("s: {}", u8v_to_hexstr(&s));
    // }
    // for u in &result.t.t0.u {
    //     println!("u: {}", u8v_to_hexstr(&u));
    // }
    // println!("name: {}", u8v_to_hexstr(&result.t.t0.name));
    // println!("t.signature:{:?}", u8v_to_hexstr(&result.t.signature));
    // println!("pkey:{:?}", pkey.to_str());
    
    let json_data = serde_json::to_string(&podr2_data).unwrap();
    let c_json_data = CString::new(json_data.as_bytes().to_vec()).unwrap();
    unsafe {
        ocall_post_podr2_commit_data(c_json_data.as_ptr());
    }
    
    sgx_status_t::SGX_SUCCESS
}
