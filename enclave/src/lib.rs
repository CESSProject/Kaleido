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

extern crate alloc;
extern crate base64;
extern crate bit_vec;
extern crate cess_curve;
extern crate chrono;
#[cfg(not(target_env = "sgx"))]
extern crate crypto;
extern crate env_logger;
extern crate http_req;
extern crate httparse;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate merkletree;
extern crate num;
extern crate num_bigint;
extern crate rustls;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;
extern crate rsa;
extern crate rand;
extern crate sgx_serialize;
#[macro_use]
extern crate sgx_serialize_derive;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;
extern crate timer;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;
extern crate threadpool;

use alloc::string::ToString;
use alloc::vec::Vec;
use rand::rngs::OsRng;
use rsa::{PublicKey, PaddingScheme};
use core::convert::TryInto;

use cess_curve::*;
use log::{info, warn};
use secp256k1::*;
use sgx_rand::Rng;
use sgx_serialize::{DeSerializable, DeSerializeHelper, Serializable, SerializeHelper};
use sgx_types::sgx_status_t::{SGX_ERROR_UNEXPECTED, SGX_SUCCESS};
use sgx_types::*;
use statics::CHAL_DATA;
use std::ffi::CString;
use std::io::ErrorKind;
use std::sync::atomic::Ordering;
use std::{
    env,
    ffi::CStr,
    io::{Error, Read, Write},
    sgxfs::SgxFile,
    slice,
    string::String,
    sync::SgxMutex,
    thread,
};

use param::{
    podr2_commit_data::PoDR2CommitData, podr2_pub_commit_data::PoDR2PubData, Podr2Status,
    StatusInfo,
};
// use ocall_def::ocall_post_podr2_commit_data;
use param::podr2_commit_data::PoDR2SigGenData;
use param::podr2_commit_response::{PoDR2ChalResponse, PoDR2Response};
use podr2_v1_pri::chal_gen::{ChalData, PoDR2Chal};
use podr2_v1_pri::key_gen::{MacHash, Symmetric};
use podr2_v1_pri::{QElement, Tag};
use podr2_v2_pub_rsa::SigGenResponse;
use utils::bloom_filter::BloomHash;
use utils::file;
use crate::attestation::hex;
use crate::statics::*;

mod attestation;
mod keys;
mod merkletree_generator;
mod ocall_def;
mod param;
mod pbc;
mod podr2_v1_pri;
mod podr2_v1_pub_pbc;
mod podr2_v2_pub_pbc;
mod podr2_v2_pub_rsa;
mod statics;
mod utils;

#[no_mangle]
pub extern "C" fn init() -> sgx_status_t {
    env_logger::init();
    // pbc::init_pairings();
    if !init_keys() {
        return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
    }
    let heap_max_size = env::var("HEAP_MAX_SIZE").expect("HEAP_MAX_SIZE is not set.");
    let heap_max_size = i64::from_str_radix(heap_max_size.trim_start_matches("0x"), 16).unwrap();
    debug!("HEAP_MAX_SIZE: {} MB", heap_max_size / (1024 * 1024));
    let max_file_size = (heap_max_size as f32 * 0.65) as usize;
    utils::enclave_mem::ENCLAVE_MEM_CAP.fetch_add(max_file_size, Ordering::SeqCst);
    info!("Max supported File size: {} bytes", max_file_size);
    let available_cpu=thread::available_parallelism().unwrap();
    info!("The program is initialized successfully! and the number of available threads is:{}",available_cpu.get());
    sgx_status_t::SGX_SUCCESS
}

fn init_keys() -> bool {
    let mut file = match SgxFile::open(podr2_v1_pri::key_gen::EncryptionType::FILE_NAME) {
        Ok(f) => f,
        Err(_) => {
            info!(
                "{} file not found, creating new file.",
                podr2_v1_pri::key_gen::EncryptionType::FILE_NAME
            );

            let saved = ENCRYPTIONTYPE.lock().unwrap().save();
            if !saved {
                error!("Failed to save keys");
                return false;
            }

            info!("Signing keys generated!");
            return true;
        }
    };

    let mut guard = ENCRYPTIONTYPE.lock().unwrap();
    guard.load()
}

#[no_mangle]
pub extern "C" fn gen_keys() -> sgx_status_t {
    // let filename = "keys";

    // let mut file = match SgxFile::open(filename) {
    //     Ok(f) => f,
    //     Err(_) => {
    //         info!("{} file not found, creating new file.", filename);

    // Generate Keys
    // KEYS.lock().unwrap().gen_keys();
    // let saved = KEYS.lock().unwrap().save();
    // if !saved {
    //     error!("Failed to save keys");
    //     return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
    // }

    // info!("Signing keys generated!");
    // return sgx_status_t::SGX_SUCCESS;
    //     }
    // };

    // While encoding 4 bits are added by the encoder
    // match Keys::load() {
    //     Ok(keys) => {
    //         let mut guard = KEYS.lock().unwrap();
    //         guard.pkey = keys.pkey;
    //         guard.skey = keys.skey;

    //         info!("Signing keys loaded successfully!");
    //     }
    //     Err(_) => {
    //         return sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS;
    //     }
    // }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_report(callback_url: *const c_char) -> sgx_status_t {
    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let report = PAYLOAD.lock().unwrap().to_string().clone();
    utils::post::post_data(callback_url_str.clone(), &report);

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
    file_path: *const c_char,
    block_size: usize,
    callback_url: *const c_char,
) -> sgx_status_t {
    // Check for enough memory before proceeding
    let mut status = StatusInfo::new();
    let mut podr2_data = PoDR2PubData::new();
    let callback_url_str = match unsafe { CStr::from_ptr(callback_url).to_str() } {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let file_path_str = match unsafe { CStr::from_ptr(file_path).to_str() } {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let mut file_info = match utils::file::read_untrusted_file(file_path_str) {
        Ok(f) => f,
        Err(e) => {
            status.status_msg = e.to_string();
            status.status_code = Podr2Status::PoDr2ErrorNotexistFile as usize;
            podr2_data.status = status;
            utils::post::post_data(callback_url_str.clone(), &podr2_data);
            let mem = utils::enclave_mem::ENCLAVE_MEM_CAP.fetch_add(0, Ordering::SeqCst);
            info!("The enclave space is released to :{} (b)", mem);
            return sgx_status_t::SGX_ERROR_FILE_BAD_STATUS;
        }
    };

    // fetch_sub returns previous value. Therefore substract the file_size
    let mem = utils::enclave_mem::ENCLAVE_MEM_CAP.fetch_sub(file_info.0, Ordering::SeqCst);
    info!("Enclave remaining memory {}", mem - file_info.0);

    if file_info.0 < block_size {
        // TODO: Return Error for Invalid block_size (No. of Blocks can not be greater than data length.)
        warn!(
            "Invalid block_size {:?} - per blocks can not be greater than data length {:?}",
            block_size, file_info.0
        );
        status.status_msg = format!(
            "Invalid block_size {:?} - per blocks can not be greater than data length {:?}",
            block_size, file_info.0
        )
        .to_string();
        status.status_code = Podr2Status::PoDr2ErrorInvalidParameter as usize;
        podr2_data.status = status;
        utils::post::post_data(callback_url_str.clone(), &podr2_data);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    match thread::Builder::new()
        .name("process_data".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();

            info!("-------------------PoDR2 Pub RSA-------------------");
            let (n, s) = file::count_file(&mut file_info.1, block_size, 1);
            info!("Currently available threads are:{}",thread::available_parallelism().unwrap().get());
            match podr2_v2_pub_rsa::sig_gen::sig_gen(&mut file_info.1, n){
                Ok(result) =>(
                    podr2_data.result=result,
                    podr2_data.status.status_msg = "Sig gen successful!".to_string(),
                    podr2_data.status.status_code = Podr2Status::PoDr2Success as usize
                ),
                Err(e)=>(
                    podr2_data.result=SigGenResponse::new(),
                    podr2_data.status.status_msg=e.message.unwrap(),
                    podr2_data.status.status_code=Podr2Status::PoDr2Unexpected as usize
                    )
            };

            info!("-------------------PoDR2 Pub RSA-------------------");
            // Post PoDR2Data to callback url.
            if !call_back_url.is_empty() {
                utils::post::post_data(call_back_url, &podr2_data);
                let mem =
                    utils::enclave_mem::ENCLAVE_MEM_CAP.fetch_add(file_info.0, Ordering::SeqCst);
                info!(
                    "The enclave space is released to :{} (b)",
                    mem + file_info.0
                );
            } else {
                let json_data = serde_json::to_string(&podr2_data);
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
        }) {
        Ok(_) => return sgx_status_t::SGX_SUCCESS,
        Err(_) => return sgx_status_t::SGX_ERROR_OUT_OF_TCS,
    };
}

#[no_mangle]
pub extern "C" fn gen_chal(
    n_blocks: usize,
    chal_id: *mut u8,
    proof_id_len: usize,
    callback_url: *const c_char,
) -> sgx_status_t {
    let mut __chal_id = unsafe { slice::from_raw_parts(chal_id, proof_id_len).to_vec() };

    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    if callback_url_str.is_empty() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    match thread::Builder::new()
        .name(format!("chal_gen_{}", base64::encode(__chal_id.to_vec())))
        .spawn(move || {
            let proof_id = __chal_id.clone();
            let call_back_url = callback_url_str.clone();

            let mut status_code: usize;
            let mut status_msg: String;
            let podr2_chal = match podr2_v1_pri::chal_gen::chal_gen(n_blocks as i64, &proof_id) {
                Ok(chal) => {
                    status_code = Podr2Status::PoDr2Success as usize;
                    status_msg = "ok".to_string();
                    chal
                }
                Err(e) => {
                    status_code = Podr2Status::PoDr2Unexpected as usize;
                    status_msg = match e.message {
                        Some(m) => m,
                        None => "Failed to generate challenge".to_string(),
                    };
                    PoDR2Chal {
                        q_elements: Vec::new(),
                        time_out: 0,
                    }
                }
            };

            let mut chal_res = get_chal_resp(podr2_chal, proof_id);
            chal_res.status.status_code = status_code;
            chal_res.status.status_msg = status_msg;

            utils::post::post_data(call_back_url, &chal_res);
        }) {
        Ok(_) => return sgx_status_t::SGX_SUCCESS,
        Err(_) => return sgx_status_t::SGX_ERROR_OUT_OF_TCS,
    };
}

/// Arguments:
/// `verify_type` indicates the type of proof you need to verify (autonomous(1), idle(2), service(3)).
/// `proof_id` is the global challenge random number announced by the chain.
/// `proof_id_len` is the length of the global challenge nonce announced by the chain.
/// `proof_json` is evidence submitted by miners and file preprocessing results, including σ, μ, tag.
/// `callback_url` is the url of the callback result.
#[no_mangle]
pub extern "C" fn verify_proof(
    verify_type: usize,
    proof_id: *mut u8,
    proof_id_len: usize,
    proof_json: *const c_char,
) -> sgx_status_t {
    let mut pid = unsafe { slice::from_raw_parts(proof_id, proof_id_len).to_vec() };
    let mut chal_data = CHAL_DATA.lock().unwrap();
    if !chal_data.chal_id.eq(&pid) {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let proof_json_hex_str = match unsafe { CStr::from_ptr(proof_json).to_str() } {
        Ok(p) => p.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    if proof_json_hex_str.is_empty() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let (sigma, miu, tag) = podr2_v1_pri::convert_miner_proof(&proof_json_hex_str);

    let ok = podr2_v1_pri::verify_proof::verify_proof(
        sigma,
        miu,
        &tag,
        ENCRYPTIONTYPE.lock().unwrap().clone(),
    );
    debug!("podr2_result is :{}", ok);

    let hex = utils::convert::u8v_to_hexstr(&tag.t.file_hash);
    let mut hash = [0u8; 64];
    let bytes = hex.as_bytes();
    for i in 0..bytes.len() {
        hash[i] = bytes[i];
    }

    let bloom_hash = BloomHash(hash);
    let binary = match bloom_hash.binary() {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to compute bloom binary: {}", e);
            [0u8; 256]
        }
    };
    let file_hash_str = utils::convert::u8v_to_hexstr(&tag.t.file_hash.clone());
    // let file_hash_str = String::from_utf8(tag.t.file_hash.clone()).unwrap();
    match verify_type {
        1 => {
            if !ok {
                if chal_data.autonomous_failed_file_hashes.is_empty() {
                    chal_data.autonomous_failed_file_hashes += &file_hash_str;
                } else {
                    let tmp = "|".to_string() + &file_hash_str;
                    chal_data.autonomous_failed_file_hashes += &tmp
                }
            }
            chal_data.autonomous_bloom_filter.insert(binary);
        }
        2 => {
            if !ok {
                if chal_data.idle_failed_file_hashes.is_empty() {
                    chal_data.idle_failed_file_hashes += &file_hash_str;
                } else {
                    let tmp = "|".to_string() + &file_hash_str;
                    chal_data.idle_failed_file_hashes += &tmp
                }
            }
            chal_data.idle_bloom_filter.insert(binary);
        }
        3 => {
            if !ok {
                if chal_data.service_failed_file_hashes.is_empty() {
                    chal_data.service_failed_file_hashes += &file_hash_str;
                } else {
                    let tmp = "|".to_string() + &file_hash_str;
                    chal_data.service_failed_file_hashes += &tmp
                }
            }
            chal_data.service_bloom_filter.insert(binary);
        }
        _ => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn fill_random_file(file_path: *const c_char, data_len: usize) -> sgx_status_t {
    let file_path = match unsafe { CStr::from_ptr(file_path).to_str() } {
        Ok(path) => path.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let ok = utils::file::write_untrusted_file(file_path, data_len);
    println!("create random file :{}", ok);
    if !ok {
        return sgx_status_t::SGX_ERROR_DEVICE_BUSY;
    }
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn message_signature(
    msg: *const c_char,
    callback_url: *const c_char,
) -> sgx_status_t {
    let msg_string = match unsafe { CStr::from_ptr(msg).to_str() } {
        Ok(path) => path.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let mut msg_hash = match sgx_tcrypto::rsgx_sha256_slice(msg_string.as_bytes()) {
        Ok(hash) => hash,
        Err(e) => {
            return e;
        }
    };

    let keys = KEYS.lock().unwrap().aes_keys.clone();
    let ssk = &keys.skey;
    let message = Message::parse(&msg_hash);
    let (msg_sig, msg_recid) = secp256k1::sign(&message, &ssk);
    let mut msg_rec_sig = [0u8; 65];
    let mut n = 0_usize;
    for i in msg_sig.serialize() {
        msg_rec_sig[n] = i;
        n = n + 1;
    }
    if msg_recid.serialize() > 26 {
        msg_rec_sig[64] = msg_recid.serialize() + 27;
    } else {
        msg_rec_sig[64] = msg_recid.serialize();
    };
    let msg_signature_hex = u8v_to_hexstr(&msg_rec_sig);
    let callback_url_str = match unsafe { CStr::from_ptr(callback_url).to_str() } {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    if callback_url_str.is_empty() || msg_signature_hex.is_empty() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    utils::post::post_data(callback_url_str, &msg_signature_hex);

    return SGX_SUCCESS;
}

#[no_mangle]
pub extern "C" fn test_func(msg: *const c_char) -> sgx_status_t {
    let msg_string = match unsafe { CStr::from_ptr(msg).to_str() } {
        Ok(path) => path.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    // podr2_v2_pub_rsa::key_gen::key_gen(msg_string);
    let rsa_keys = KEYS.lock().unwrap().rsa_keys.clone();
    let e =utils::convert::u8v_to_hexstr(&rsa_keys.pkey.e().to_bytes_be());
    let n =utils::convert::u8v_to_hexstr(&rsa_keys.pkey.n().to_bytes_be());
    dbg!(e,n);
    println!("e is :{:?}",&rsa_keys.pkey.e().to_string());
    println!("n is :{:?}",&rsa_keys.pkey.n().to_string());

    let msg_vec=hex::decode_hex(&msg_string);

    // let enc_data = rsa_keys.pkey.encrypt(&mut rng, PaddingScheme::PKCS1v15, msg_string.as_bytes()).expect("failed to encrypt");
    let dec_data = rsa_keys.skey.decrypt(PaddingScheme::PKCS1v15, &msg_vec).expect("failed to decrypt");
    let res=String::from_utf8(dec_data).unwrap();
    dbg!(res);

    // assert_eq!(msg_string.as_bytes(), &dec_data[..]);

    return SGX_SUCCESS;
}

fn get_chal_resp(chal: PoDR2Chal, chal_id: Vec<u8>) -> PoDR2ChalResponse {
    let mut chal_res = PoDR2ChalResponse::new();
    chal_res.challenge.chal_id = chal_id;
    chal_res.challenge.time_out = chal.time_out;
    chal_res.challenge.q_elements = chal.q_elements;
    chal_res
}

// #[allow(unused)]
// fn get_podr2_resp(
//     data: PoDR2SigGenData,
//     status_info: param::podr2_commit_response::StatusInfo,
// ) -> PoDR2Response {
//     let mut podr2_res = PoDR2Response::new();
//
//     let mut phi_encoded: Vec<String> = Vec::new();
//     for sig in data.phi {
//         phi_encoded.push(base64::encode(sig))
//     }
//
//     podr2_res.mht_root_sig = base64::encode(data.mht_root_sig);
//     podr2_res.phi = phi_encoded;
//     podr2_res.status = status_info;
//     podr2_res
// }
