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
#![allow(unused_variables)]

extern crate cess_bncurve;
extern crate http_req;
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
use http_req::response::{self, Headers};
use http_req::tls::Conn;
use http_req::{
    request::{Method, RequestBuilder},
    response::Response,
    tls,
    uri::Uri,
};
use merkletree::merkle::MerkleTree;
// use ocall_def::ocall_post_podr2_commit_data;
use param::{podr2_commit_data::PoDR2CommitData, podr2_commit_response::PoDR2CommitResponse};
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::{
    ffi::CStr,
    ffi::CString,
    net::TcpStream,
    ptr, slice,
    string::String,
    sync::{Arc, SgxMutex},
    thread, time,
    time::{Duration, Instant},
    untrusted::time::InstantEx,
    untrusted::time::SystemTimeEx,
};
extern crate sgx_trts;
extern crate sgx_tdh;
extern crate sgx_tkey_exchange;
use sgx_tcrypto::*;
use sgx_tkey_exchange::*;
use sgx_trts::memeq::ConsttimeMemEq;

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

    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(e) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    thread::Builder::new()
        .name("process_data".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();
            let mut podr2_data = podr2_proof_commit::podr2_proof_commit(
                skey.clone(),
                pkey.clone(),
                d.clone(),
                block_size,
                segment_size,
            );

            // Print PoDR2CommitData
            // for s in &podr2_data.sigmas {
            //     println!("s: {}", u8v_to_hexstr(&s));
            // }
            // for u in &podr2_data.t.t0.u {
            //     println!("u: {}", u8v_to_hexstr(&u));
            // }
            // println!("name: {}", u8v_to_hexstr(&podr2_data.t.t0.name));
            // println!("t.signature:{:?}", u8v_to_hexstr(&podr2_data.t.signature));
            // println!("pkey:{:?}", pkey.to_str());

            // Post PoDR2CommitData to callback url.
            let _ = post_podr2_data(podr2_data, call_back_url);
        })
        .expect("Failed to launch process_data thread");

    sgx_status_t::SGX_SUCCESS
}

fn post_podr2_data(data: PoDR2CommitData, callback_url: String) -> sgx_status_t {
    let mut podr2_res = get_podr2_resp(data);

    let json_data = serde_json::to_string(&podr2_res);
    let json_data = match json_data {
        Ok(data) => data,
        Err(_) => {
            println!("Failed to seralize PoDR2CommitResponse");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let addr = callback_url.parse();
    let addr: Uri = match addr {
        Ok(add) => add,
        Err(_) => {
            println!("Failed to Parse Url");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let conn_addr = get_host_with_port(&addr);

    //Connect to remote host
    let mut stream = TcpStream::connect(&conn_addr);
    let mut stream = match stream {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to connect to {}, {}", addr, e);
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let json_bytes = json_data.as_bytes();
    let mut writer = Vec::new();
    let time_out = Some(Duration::from_millis(200));
    if addr.scheme() == "https" {
        //Open secure connection over TlsStream, because of `addr` (https)
        let mut stream = tls::Config::default().connect(addr.host().unwrap_or(""), stream);

        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                println!("Failed to connect to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };

        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                println!("Failed to send request to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

        println!("Status: {} {}", response.status_code(), response.reason());
    } else {
        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                println!("Failed to send request to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

        println!("Status: {} {}", response.status_code(), response.reason());
    }
    println!("{}", String::from_utf8_lossy(&writer));
    return sgx_status_t::SGX_SUCCESS;
}

fn get_podr2_resp(data: PoDR2CommitData) -> PoDR2CommitResponse {
    let mut podr2_res = PoDR2CommitResponse::new();
    podr2_res.pkey = base64::encode(data.pkey);

    let mut sigmas_encoded: Vec<String> = Vec::new();
    for sigma in data.sigmas {
        sigmas_encoded.push(base64::encode(sigma))
    }

    let mut u_encoded: Vec<String> = Vec::new();
    for u in data.t.t0.u {
        u_encoded.push(base64::encode(u))
    }

    podr2_res.sigmas = sigmas_encoded;
    podr2_res.t.signature = base64::encode(data.t.signature);
    podr2_res.t.t0.name = base64::encode(data.t.t0.name);
    podr2_res.t.t0.n = data.t.t0.n;
    podr2_res.t.t0.u = u_encoded;
    podr2_res
}

fn get_host_with_port(addr: &Uri) -> String {
    let port = addr.port();
    let port: u16 = if port.is_none() {
        let scheme = addr.scheme();
        if scheme == "http" {
            80
        } else {
            443
        }
    } else {
        port.unwrap()
    };
    format!("{}:{}", addr.host().unwrap(), port)
}

const G_SP_PUB_KEY: sgx_ec256_public_t = sgx_ec256_public_t {
    gx: [
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf, 0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae,
        0xad, 0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d, 0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b,
        0xeb, 0x38,
    ],
    gy: [
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b, 0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14,
        0xe2, 0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28, 0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14,
        0x5e, 0x06,
    ],
};

#[no_mangle]
pub extern "C" fn enclave_init_ra(b_pse: i32, p_context: &mut sgx_ra_context_t) -> sgx_status_t {
    match rsgx_ra_init(&G_SP_PUB_KEY, b_pse) {
        Ok(p) => {
            *p_context = p;
            sgx_status_t::SGX_SUCCESS
        }
        Err(x) => x,
    }
}

#[no_mangle]
pub extern "C" fn enclave_ra_close(context: sgx_ra_context_t) -> sgx_status_t {
    match rsgx_ra_close(context) {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(x) => x,
    }
}

#[no_mangle]
pub extern "C" fn verify_att_result_mac(
    context: sgx_ra_context_t,
    message: *const u8,
    msg_size: size_t,
    mac: *const u8,
    mac_size: size_t,
) -> sgx_status_t {
    let ret: sgx_status_t;
    let mk_key: sgx_ec_key_128bit_t;
    let mac_slice;
    let message_slice;
    let mac_result: sgx_cmac_128bit_tag_t;

    if mac_size != SGX_MAC_SIZE || msg_size > u32::max_value as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    unsafe {
        mac_slice = slice::from_raw_parts(mac, mac_size as usize);
        message_slice = slice::from_raw_parts(message, msg_size as usize);
    }

    if mac_slice.len() != SGX_MAC_SIZE as usize || message_slice.len() != msg_size as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    match rsgx_ra_get_keys(context, sgx_ra_key_type_t::SGX_RA_KEY_MK) {
        Ok(k) => mk_key = k,
        Err(x) => return x,
    }

    match rsgx_rijndael128_cmac_slice(&mk_key, message_slice) {
        Ok(tag) => mac_result = tag,
        Err(x) => return x,
    }

    if mac_slice.consttime_memeq(&mac_result) == false {
        return sgx_status_t::SGX_ERROR_MAC_MISMATCH;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_secret_data(
    context: sgx_ra_context_t,
    p_secret: *const u8,
    sec_size: u32,
    gcm_mac: &[u8; 16],
    max_vlen: u32,
    p_ret: &mut [u8; 16],
) -> sgx_status_t {
    let ret: sgx_status_t;
    let sk_key: sgx_ec_key_128bit_t;

    match rsgx_ra_get_keys(context, sgx_ra_key_type_t::SGX_RA_KEY_SK) {
        Ok(key) => sk_key = key,
        Err(x) => return x,
    }

    let secret_slice = unsafe { slice::from_raw_parts(p_secret, sec_size as usize) };

    if secret_slice.len() != sec_size as usize {
        ret = sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    let mut decrypted_vec: Vec<u8> = vec![0; sec_size as usize];
    let decrypted_slice = &mut decrypted_vec[..];
    let iv = [0; 12];
    let aad: [u8; 0] = [0; 0];

    let ret =
        rsgx_rijndael128GCM_decrypt(&sk_key, &secret_slice, &iv, &aad, gcm_mac, decrypted_slice);

    match ret {
        Ok(()) => {
            if decrypted_slice[0] == 0 && decrypted_slice[1] != 1 {
                sgx_status_t::SGX_ERROR_INVALID_SIGNATURE
            } else {
                sgx_status_t::SGX_SUCCESS
            }
        }
        Err(_) => {
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}