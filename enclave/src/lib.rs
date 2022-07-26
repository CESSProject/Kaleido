// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding c&opyright ownership.  The ASF licenses this file
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
extern crate http_req;
extern crate libc;
extern crate merkletree;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;
extern crate sgx_serialize;
extern crate sgx_tcrypto;
extern crate sgx_types;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate sgx_serialize_derive;

#[macro_use]
extern crate log;
extern crate env_logger;

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
mod secret_exchange;

use crate::podr2_proof_commit::podr2_proof_commit;
use alloc::string::ToString;
use alloc::vec::Vec;
use cess_bncurve::*;
use core::borrow::BorrowMut;
use core::convert::TryInto;
use core::fmt::{Display, Formatter, Result};
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
use log::{info, trace, warn};
use merkletree::merkle::MerkleTree;
use sgx_serialize::{DeSerializeHelper, SerializeHelper};

// use ocall_def::ocall_post_podr2_commit_data;
use param::{podr2_commit_data::PoDR2CommitData, podr2_commit_response::PoDR2CommitResponse};
use sgx_types::*;
use std::{
    ffi::CStr,
    ffi::CString,
    io::{Read, Write},
    net::TcpStream,
    ptr,
    sgxfs::SgxFile,
    slice,
    string::String,
    sync::{Arc, SgxMutex},
    thread, time,
    time::{Duration, Instant},
    untrusted::time::InstantEx,
    untrusted::time::SystemTimeEx,
};

<<<<<<< HEAD
//mra dependence
extern crate rustls;
extern crate webpki;
// extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate chrono;
extern crate webpki_roots;
extern crate sgx_trts;
extern crate sgx_tse;

=======
#[derive(Serializable, DeSerializable)]
>>>>>>> Added Serialization and DeSerialization of Keys and encrypted File Storage
struct Keys {
    skey: SecretKey,
    pkey: PublicKey,
    sig: G1,
}

impl Keys {
    pub const fn new() -> Keys {
        Keys {
            skey: SecretKey::zero(),
            pkey: PublicKey::zero(),
            sig: G1::zero(),
        }
    }

    pub fn gen_keys(self: &mut Self) {
        let (skey, pkey, sig) = pbc::key_gen();
        self.skey = skey;
        self.pkey = pkey;
        self.sig = sig;
    }

    pub fn get_keys(self: &Self) -> (SecretKey, PublicKey, G1) {
        (self.skey, self.pkey, self.sig)
    }

    pub fn get_instance(self: &mut Self) -> Keys {
        let mut keys = Keys::new();
        keys.pkey = self.pkey.clone();
        keys.skey = self.skey.clone();
        keys.sig = self.sig.clone();
        keys
    }
}

lazy_static! (
    static ref KEYS: SgxMutex<Keys> = SgxMutex::new(Keys::new());
);

#[no_mangle]
pub extern "C" fn init() -> sgx_status_t {
    pbc::init_pairings();
    env_logger::init();
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn gen_keys() -> sgx_status_t {
    let filename = "keys";
    let mut file = match SgxFile::open(filename) {
        Ok(f) => f,
        Err(fopen_err) => {
            info!(
                "{} file not found, creating new file. Error: {}",
                filename, fopen_err
            );

            // Generate Keys
            KEYS.lock().unwrap().gen_keys();

            let helper = SerializeHelper::new();
            let keys = KEYS.lock().unwrap().get_instance();
            let data = match helper.encode(&keys) {
                Some(d) => d,
                None => {
                    println!("encode data failed.");
                    return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
                }
            };

            let mut file = match SgxFile::create(filename) {
                Ok(f) => f,
                Err(e) => {
                    println!(
                        "SgxFile::create failed to create file {}. Error: {}",
                        filename, e
                    );
                    return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
                }
            };

            let write_size = match file.write(data.as_slice()) {
                Ok(len) => len,
                Err(_) => {
                    println!("SgxFile::write failed to write data to the file {}.", filename);
                    return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
                }
            };

            return sgx_status_t::SGX_SUCCESS;
        }
    };

    // While encoding 4 bits are added by the encoder
    let mut data = [0_u8; config::ZR_SIZE_FR256 + config::G2_SIZE_FR256 + config::HASH_SIZE + 4];

    let read_size = match file.read(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
        }
    };

    let helper = DeSerializeHelper::<Keys>::new(data.to_vec());
    let keys = match helper.decode() {
        Some(d) => d,
        None => {
            println!("decode data failed.");
            return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
        }
    };

    let (skey, pkey, sig) = keys.get_keys();
    let mut keys = KEYS.lock().unwrap();
    keys.pkey = pkey;
    keys.skey = skey;
    keys.sig = sig;

    info!("Signing keys generated!");
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
    let (skey, pkey, _sig) = KEYS.lock().unwrap().get_keys();

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


//ocal code
extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                                  ret_ti  : *mut sgx_target_info_t,
                                  ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_ias_socket ( ret_val : *mut sgx_status_t,
                                  ret_fd  : *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                            p_sigrl            : *const u8,
                            sigrl_len          : u32,
                            p_report           : *const sgx_report_t,
                            quote_type         : sgx_quote_sign_type_t,
                            p_spid             : *const sgx_spid_t,
                            p_nonce            : *const sgx_quote_nonce_t,
                            p_qe_report        : *mut sgx_report_t,
                            p_quote            : *mut u8,
                            maxlen             : u32,
                            p_quote_len        : *mut u32) -> sgx_status_t;
    #[allow(dead_code)]
    pub fn ocall_get_update_info (ret_val: *mut sgx_status_t,
                                  platformBlob: * const sgx_platform_info_t,
                                  enclaveTrusted: i32,
                                  update_info: * mut sgx_update_info_bit_t) -> sgx_status_t;
}