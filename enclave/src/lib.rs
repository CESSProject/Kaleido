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

use alloc::string::ToString;
use alloc::vec::Vec;
use cess_bncurve::*;

use core::ops::{Index, IndexMut};
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::untrusted::time::SystemTimeEx;
use std::{
    ptr, slice,
    sync::{Arc, SgxMutex},
    thread, time,
};

mod pbc;

struct SignatureWithIndex(usize, G1);

struct Signatures(Vec<G1>, PublicKey);

static mut SIGNATURES: Signatures = Signatures(vec![], PublicKey::new(G2::zero()));

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
            unsafe {
                SIGNATURES.1 = pkey;
            }
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
#[no_mangle]
pub extern "C" fn process_data(
    data: *mut u8,
    data_len: usize,
    sig_len: usize,
    sig: *mut u8,
) -> sgx_status_t {
    let d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };

    let (skey, pkey, _sig) = unsafe { KEYS.get_keys() };

    let signature = cess_bncurve::sign_message(&d, &skey);
    unsafe {
        ptr::copy_nonoverlapping(signature.base_vector().as_ptr(), sig, sig_len);
    }

    // let mut chunks: Vec<Vec<u8>> = Vec::new();
    // d.chunks(block_size).for_each(|chunk| {
    //     chunks.push(chunk.to_vec());
    // });

    // let now = time::SystemTime::now();
    // let mut handles = vec![];
    // let mut signatures = &mut vec![G1::zero(); chunks.len()];
    // if multi_thread {
    //     println!("Multi-thread");

    //     for i in 0..chunks.len() {
    //         let chunk = chunks[i].to_vec().clone();
    //         let skey = skey.clone();
    //         let mut signatures = signatures.clone();
    //         let handle = thread::spawn(move || {
    //             let sig = cess_bncurve::sign_message(&chunk, &skey);
    //             signatures[i] = sig;
    //         });
    //         handles.push(handle);
    //     }

    //     for handle in handles {
    //         handle.join().unwrap();
    //     }
    // } else {
    //     println!("Single-thread");

    //     for i in 0..chunks.len() {
    //         let chunk = chunks[i].to_vec().clone();
    //         let sig = cess_bncurve::sign_message(&chunk, &skey);
    //         signatures[i] = sig;
    //     }
    // }
    // let escaped = now.elapsed().unwrap();
    // println!("Sig took {:.2?}", escaped);

    // *sig_len = chunks.len();

    // unsafe {
    //     SIGNATURES = Signatures(signatures.to_vec(), pkey);
    // }

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
