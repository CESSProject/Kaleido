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

// #[macro_use]
// extern crate itertools;

//mra dependence
extern crate base64;
extern crate bit_vec;
extern crate chrono;
extern crate httparse;
extern crate num_bigint;
extern crate rustls;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;

mod merkletree_generator;
mod ocall_def;
mod param;
mod pbc;
mod podr2_proof_commit;
mod secret_exchange;

use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;
use cess_bncurve::*;
use core::convert::TryInto;
use core::sync::atomic::AtomicUsize;
use http_req::response;
use http_req::{request::RequestBuilder, tls, uri::Uri};
use log::{info, warn};
use merkletree::merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use std::io::ErrorKind;
use std::sync::atomic::Ordering;

// use ocall_def::ocall_post_podr2_commit_data;
use param::{podr2_commit_data::PoDR2CommitData, podr2_commit_response::PoDR2CommitResponse};
use sgx_types::*;
use std::{
    env,
    ffi::CStr,
    io::{Error, Read, Write},
    net::TcpStream,
    sgxfs::SgxFile,
    slice,
    string::String,
    sync::SgxMutex,
    thread,
    time::Duration,
};

static ENCLAVE_MEM_CAP: AtomicUsize = AtomicUsize::new(0);

#[derive(Serializable, DeSerializable)]
struct Keys {
    skey: SecretKey,
    pkey: PublicKey,
    sig: G1,
}

impl Keys {
    const FILE_NAME: &'static str = "keys";

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

    pub fn save(self: &mut Self) -> bool {
        let helper = SerializeHelper::new();
        let data = match helper.encode(self.get_instance()) {
            Some(d) => d,
            None => {
                return false;
            }
        };

        let mut file = match SgxFile::create(Keys::FILE_NAME) {
            Ok(f) => f,
            Err(e) => {
                return false;
            }
        };

        let _write_size = match file.write(data.as_slice()) {
            Ok(len) => len,
            Err(_) => {
                return false;
            }
        };
        return true;
    }

    pub fn load() -> Result<Keys, std::io::Error> {
        let mut file = SgxFile::open(Keys::FILE_NAME)?;

        // While encoding 4 bits are added by the encoder
        let mut data =
            [0_u8; config::ZR_SIZE_FR256 + config::G2_SIZE_FR256 + config::HASH_SIZE + 4];

        file.read(&mut data)?;

        let helper = DeSerializeHelper::<Keys>::new(data.to_vec());

        match helper.decode() {
            Some(d) => Ok(d),
            None => {
                error!("decode data failed.");
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Failed to decode file {}", Keys::FILE_NAME),
                ));
            }
        }
    }
}

lazy_static! (
    static ref KEYS: SgxMutex<Keys> = SgxMutex::new(Keys::new());
);

#[no_mangle]
pub extern "C" fn init() -> sgx_status_t {
    env_logger::init();
    pbc::init_pairings();
    let heap_max_size = env::var("HEAP_MAX_SIZE").expect("HEAP_MAX_SIZE is not set.");
    let heap_max_size = i64::from_str_radix(heap_max_size.trim_start_matches("0x"), 16).unwrap();
    debug!("HEAP_MAX_SIZE: {} MB", heap_max_size / (1024 * 1024));
    let max_file_size = (heap_max_size as f32 * 0.65) as usize;
    ENCLAVE_MEM_CAP.fetch_add(max_file_size, Ordering::SeqCst);
    info!("Max supported File size: {} bytes", max_file_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn gen_keys() -> sgx_status_t {
    let filename = "keys";
    {
        let mut file = match SgxFile::open(filename) {
            Ok(f) => f,
            Err(_) => {
                info!("{} file not found, creating new file.", filename);

                // Generate Keys
                KEYS.lock().unwrap().gen_keys();
                let saved = KEYS.lock().unwrap().save();
                if !saved {
                    error!("Failed to save keys");
                    return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
                }

                info!("Signing keys generated!");
                return sgx_status_t::SGX_SUCCESS;
            }
        };
    }

    // While encoding 4 bits are added by the encoder
    match Keys::load() {
        Ok(keys) => {
            let mut guard = KEYS.lock().unwrap();
            guard.pkey = keys.pkey;
            guard.skey = keys.skey;
            guard.sig = keys.sig;

            info!("Signing keys loaded successfully!");
        }
        Err(_) => {
            return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// Arguments:
/// `data` is the data that needs to be processed. It should not exceed SGX max memory size
/// `data_len` argument is the number of **elements**, not the number of bytes.
/// `block_size` is the size of the chunks that the data will be sliced to, in bytes.
/// `segment_size`
/// `callback_url` PoDR2 data will be posted back to this url
#[no_mangle]
pub extern "C" fn process_data(
    data: *mut u8,
    data_len: usize,
    block_size: usize,
    segment_size: usize,
    callback_url: *const c_char,
) -> sgx_status_t {
    // Check for enough memory before proceeding
    if !has_enough_mem(data_len) {
        warn!("Enclave Busy.");
        return sgx_status_t::SGX_ERROR_BUSY;
    }

    // fetch_sub returns previous value. Therefore substract the data_len
    let mem = ENCLAVE_MEM_CAP.fetch_sub(data_len, Ordering::SeqCst);
    info!("Enclave remaining memory {}", mem - data_len);

    let d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };
    let (skey, pkey, _sig) = KEYS.lock().unwrap().get_keys();

    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    thread::Builder::new()
        .name("process_data".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();
            let podr2_data = podr2_proof_commit::podr2_proof_commit(
                skey,
                pkey,
                d,
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
            let _ = post_podr2_data(podr2_data, call_back_url, data_len);
        })
        .expect("Failed to launch process_data thread");
    sgx_status_t::SGX_SUCCESS
}

fn has_enough_mem(data_len: usize) -> bool {
    //Determine the remaining enclave memory size
    let mem = ENCLAVE_MEM_CAP.fetch_add(0, Ordering::SeqCst);
    if mem < data_len {
        return false;
    }
    true
}

fn post_podr2_data(data: PoDR2CommitData, callback_url: String, data_len: usize) -> sgx_status_t {
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
        let mut stream = tls::Config::default().connect(addr.host().unwrap_or(""), &mut stream);

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

    // Update available memory.
    ENCLAVE_MEM_CAP.fetch_add(data_len, Ordering::SeqCst);

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
