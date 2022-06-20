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

use alloc::vec::Vec;
use cess_bncurve::*;
use merkletree::merkle::MerkleTree;

use core::ops::{Index, IndexMut};
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::untrusted::time::SystemTimeEx;
use std::{
    ptr, slice,
    sync::{Arc, SgxMutex},
    thread, time,
};

use crate::podr2_proof_commit::podr2_proof_commit;

mod merkletree_generator;
mod param;
mod pbc;
mod podr2_proof_commit;

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
    let (skey, pkey, _sig) = unsafe { KEYS.get_keys() };
    println!("{}", skey);
    println!("{}", pkey);
    println!("{}", _sig);
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
    sig_len: &mut usize,
    multi_thread: bool,
) -> sgx_status_t {
    let now = Instant::now();
    let d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };
    let elapsed = now.elapsed();
    println!("Data copied to Enclave in {:.2?}!", elapsed);

    let (skey, pkey, _sig) = unsafe { KEYS.get_keys() };
    //get skey byte
    println!("skey:{:?}",skey.base_vector().to_vec());
    //get pkey byte
    println!("pkey:{:?}",pkey.base_vector().to_vec());
    //get zr by byte
    // let mut byte1 =vec![0u8; 32];
    // byte1[0]=100;
    // byte1[1]=100;
    // byte1[2]=100;

    let zr = pbc::get_zr_from_byte(&vec![
        100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
        100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    ]);
    println!("{}", zr.to_str());
    //get G1 from random
    let g1_rand = pbc::get_random_g1();
    println!("g1_rand {}", g1_rand.to_str());
    let g1_rand_clone = g1_rand.clone();
    println!("g1_rand_clone: {}", g1_rand_clone.to_str());

    //get G1 from hash
    let g1_hash = pbc::get_g1_from_hash(&hash(&vec![100, 100, 100]));
    println!("g1_hash {}", g1_hash.to_str());

    // test g1_byte pow zr
    pbc::g1_pow_zn(&g1_rand, &zr);
    println!("g1_rand POW zr:{:?}", g1_rand.to_str());

    //test g1_zero mul zr
    let result = G1::zero();
    pbc::g1_mul_g1(&result, &g1_rand_clone);
    println!("G1 zero MUL g1_byte:{:?}", result.to_str());


    // let result =
    // podr2_proof_commit::podr2_proof_commit(skey.clone(), pkey.clone(), d.clone(), block_size);
    // println!("sigmas:{:?}", result.sigmas);
    // println!("");
    // println!("t.t0.name:{:?}", result.t.t0.name);
    // println!("");
    // println!("t.t0.u:{:?}",result.t.t0.u);
    // println!("");
    // println!("t.t0.n:{:?}",result.t.t0.n);
    // println!("");
    // println!("t.signature:{:?}",result.t.signature);
    // println!("");
    // println!("pkey:{:?}",pkey.base_vector());


    // let n_sig = (d.len() as f32 / block_size as f32).ceil() as usize;
    // let signatures = Arc::new(SgxMutex::new(vec![G1::zero(); n_sig]));
    // if multi_thread {
    //     let mut handles = vec![];
    //     let now = Instant::now();
    //     d.chunks(block_size).enumerate().for_each(|(i, chunk)| {
    //         let chunk = chunk.to_vec().clone();
    //         let skey = skey.clone();
    //         let signatures = Arc::clone(&signatures);
    //         let handle = thread::spawn(move || {
    //             let sig = cess_bncurve::sign_message(&chunk, &skey);
    //             let mut signature = signatures.lock().unwrap();
    //             *signature.index_mut(i) = sig;
    //         });
    //         handles.push(handle);
    //     });
    //     for handle in handles {
    //         handle.join().unwrap();
    //     }
    //     let elapsed = now.elapsed();
    //     println!("Signatures computed in {:.2?}!", elapsed);
    // } else {
    //     d.chunks(block_size).enumerate().for_each(|(i, chunk)| {
    //         let chunk = chunk.to_vec().clone();
    //         let sig = cess_bncurve::sign_message(&chunk, &skey);
    //         signatures.lock().unwrap()[i] = sig;
    //     });
    // }
    //
    // *sig_len = n_sig;
    //
    // unsafe { SIGNATURES = Signatures(signatures.lock().unwrap().to_vec(), pkey) }

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

/// Arguments:
/// `data` is the data that needs to be processed. It should not exceed SGX max memory size
/// `data_len` argument is the number of **elements**, not the number of bytes.
/// `block_size` is the size of the chunks that the data will be sliced to, in bytes.
/// `sig_len` is the number of signatures generated. This should be used to allocate
/// memory to call `get_signatures`
#[no_mangle]
pub extern "C" fn sign_message(
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

    sgx_status_t::SGX_SUCCESS
}
