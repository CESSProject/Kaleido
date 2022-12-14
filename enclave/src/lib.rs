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

extern crate cess_curve;
extern crate http_req;
extern crate libc;
extern crate merkletree;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;
extern crate sgx_serialize;
extern crate sgx_tcrypto;
extern crate sgx_types;
extern crate secp256k1;

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

extern crate base64;
extern crate bit_vec;
extern crate chrono;
extern crate httparse;
extern crate num;
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
mod podr2_pub;
mod podr2_pri;
mod podr2_proof_commit;
mod attestation;

use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;
use cess_curve::*;
use core::convert::TryInto;
use core::sync::atomic::AtomicUsize;
use http_req::response;
use http_req::{
    request::{Method, RequestBuilder},
    tls,
    uri::Uri,
};
use log::{info, warn};
use merkletree::merkle::MerkleTree;
use param::podr2_commit_data::PoDR2Data;
use param::podr2_commit_response::PoDR2Response;
use serde::{Deserialize, Serialize};
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use std::io::ErrorKind;
use std::sync::atomic::Ordering;

// use ocall_def::ocall_post_podr2_commit_data;
use param::{
    podr2_commit_data::PoDR2CommitData,
    podr2_commit_response::{PoDR2CommitResponse, StatusInfo},
    Podr2Status,
};
use sgx_types::*;
use std::{
    env,
    ffi::CStr,
    io::Seek,
    io::{Error, Read, Write},
    net::TcpStream,
    sgxfs::SgxFile,
    slice,
    string::String,
    sync::SgxMutex,
    thread,
    time::Duration,
    time::Instant,
    untrusted::fs,
};
use podr2_pri::key_gen::{MacHash, Symmetric};

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

        let mut data = Vec::new();
        file.read_to_end(&mut data);

        let helper = DeSerializeHelper::<Keys>::new(data);

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
    static ref Payload :SgxMutex<String>=SgxMutex::new(String::new());
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
    n_blocks: usize,
    callback_url: *const c_char,
) -> sgx_status_t {
    // Check for enough memory before proceeding
    println!("The Payload value is :{:?}",Payload.lock().unwrap());
    let mut status = param::podr2_commit_response::StatusInfo::new();
    let mut podr2_data = PoDR2Data::new();
    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    if !has_enough_mem(data_len) {
        warn!("Enclave Busy.");
        status.status_msg = "Enclave Busy.".to_string();
        status.status_code = Podr2Status::PoDr2ErrorOutOfMemory as usize;
        let _ = post_podr2_data(podr2_data, status, callback_url_str.clone(), 0);
        return sgx_status_t::SGX_ERROR_BUSY;
    }

    // fetch_sub returns previous value. Therefore substract the data_len
    let mem = ENCLAVE_MEM_CAP.fetch_sub(data_len, Ordering::SeqCst);
    info!("Enclave remaining memory {}", mem - data_len);

    let mut d = unsafe { slice::from_raw_parts(data, data_len).to_vec() };
    let (skey, pkey, _sig) = KEYS.lock().unwrap().get_keys();

    if d.len() < n_blocks {
        // TODO: Return Error for Invalid n_blocks (No. of Blocks can not be greater than data length.)
        warn!(
            "Invalid n_blocks {:?} - No. of blocks can not be greater than data length {:?}",
            n_blocks,
            d.len()
        );
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    thread::Builder::new()
        .name("process_data".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();
            let podr2_data = podr2_pub::sig_gen(skey, pkey, &mut d, n_blocks);
            let podr2_data = match podr2_data {
                Ok(d) => {
                    status.status_msg = "ok".to_string();
                    d
                }
                Err(e) => {
                    status.status_msg = e.to_string();
                    status.status_code = Podr2Status::PoDr2Unexpected as usize;
                    println!("PoDR2 Error: {}", e.to_string());
                    PoDR2Data::new()
                }
            };
            println!("-------------------PoDR2 TEST Pri-------------------");
            let et = podr2_pri::key_gen::key_gen();
            let plain = b"This is not a password";
            let mut encrypt_result=et.symmetric_encrypt(plain,"enc").unwrap();
            let ct=u8v_to_hexstr(&encrypt_result);
            println!("CBC encrypt result is :{:?}",ct);
            let mut decrypt_result=et.symmetric_decrypt(&encrypt_result,"enc").unwrap();
            println!("CBC decrypt result is :{:?}",std::str::from_utf8(&decrypt_result).unwrap());

            let mac_hash_result=et.mac_encrypt(plain).unwrap();
            let mac_hex=u8v_to_hexstr(&mac_hash_result);
            println!("HMAC result is :{:?}",mac_hex);
            let mut matrix:Vec<Vec<u8>>=vec![];
            matrix.push(vec![11,22,33,44,55,66]);
            matrix.push(vec![11,22,33,44,55,66]);
            matrix.push(vec![11,22,33,44,55,66]);
            matrix.push(vec![11,22,33,44,55,66]);
            println!("matrix is {:?}",matrix);
            let sig_gen_result=podr2_pri::sig_gen::sig_gen(matrix.clone(),et.clone());
            println!("sigmas:{:?}",sig_gen_result.0);
            println!("tag.mac_t0 is :{:?},tag.t.n is {},tag.t.enc is {:?}",sig_gen_result.1.mac_t0.clone(),sig_gen_result.1.t.n.clone(),sig_gen_result.1.t.enc.clone());
            let q_slice=podr2_pri::chal_gen::chal_gen(matrix.len() as i64);
            let gen_proof_result=podr2_pri::gen_proof::gen_proof(sig_gen_result.0,q_slice.clone(),matrix.clone());
            println!("sigma is :{:?}",gen_proof_result.0);
            println!("miu is :{:?}",gen_proof_result.1);

            let ok=podr2_pri::verify_proof::verify_proof(gen_proof_result.0,q_slice.clone(),gen_proof_result.1,sig_gen_result.1,et.clone());
            println!("verify result is {}",ok);
            println!("-------------------PoDR2 TEST Pri-------------------");
            // Post PoDR2Data to callback url.
            if !call_back_url.is_empty() {
                let _ = post_podr2_data(podr2_data, status, call_back_url, data_len);
            } else {
                let mut podr2_res = get_podr2_resp(podr2_data, status);
                let json_data = serde_json::to_string(&podr2_res);
                let json_data = match json_data {
                    Ok(data) => data,
                    Err(_) => {
                        warn!("Failed to seralize PoDR2Response");
                        "".to_string()
                    }
                };
                debug!("PoDR2 Data: {}", json_data);

                warn!("Callback URL not provided.");
            }
        })
        .expect("Failed to launch process_data thread");
    sgx_status_t::SGX_SUCCESS
}

pub fn u8v_to_hexstr(x: &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0..x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

fn has_enough_mem(data_len: usize) -> bool {
    //Determine the remaining enclave memory size
    let mem = ENCLAVE_MEM_CAP.fetch_add(0, Ordering::SeqCst);
    if mem < data_len {
        return false;
    }
    true
}

fn post_podr2_data(
    data: PoDR2Data,
    status_info: StatusInfo,
    callback_url: String,
    data_len: usize,
) -> sgx_status_t {
    let mut podr2_res = get_podr2_resp(data, status_info);

    let json_data = serde_json::to_string(&podr2_res);
    let json_data = match json_data {
        Ok(data) => data,
        Err(_) => {
            warn!("Failed to seralize PoDR2CommitResponse");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let addr = callback_url.parse();
    let addr: Uri = match addr {
        Ok(add) => add,
        Err(_) => {
            warn!("Failed to Parse Url");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let conn_addr = get_host_with_port(&addr);

    //Connect to remote host
    let mut stream = TcpStream::connect(&conn_addr);
    let mut stream = match stream {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to {}, {}", addr, e);
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
                warn!("Failed to connect to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        };

        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .method(Method::POST)
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                warn!("Failed to send https request to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

        info!(
            "PoDR2 Post Data Status: {} {}",
            response.status_code(),
            response.reason()
        );
    } else {
        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .method(Method::POST)
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                warn!("Failed to send http request to {}, {}", addr, e);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };

        info!(
            "PoDR2 Post Data Status: {} {}",
            response.status_code(),
            response.reason()
        );
    }

    // Update available memory.
    let mem = ENCLAVE_MEM_CAP.fetch_add(data_len, Ordering::SeqCst);
    info!("The enclave space is released to :{} (b)", mem + data_len);

    return sgx_status_t::SGX_SUCCESS;
}

fn get_podr2_resp(data: PoDR2Data, status_info: StatusInfo) -> PoDR2Response {
    let mut podr2_res = PoDR2Response::new();

    let mut phi_encoded: Vec<String> = Vec::new();
    for sig in data.phi {
        phi_encoded.push(base64::encode(sig))
    }

    podr2_res.mht_root_sig = base64::encode(data.mht_root_sig);
    podr2_res.phi = phi_encoded;
    podr2_res.status = status_info;
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
