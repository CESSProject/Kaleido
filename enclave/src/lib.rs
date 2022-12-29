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

use alloc::string::ToString;
use alloc::vec::Vec;
use podr2_pri::chal_gen::{ChalData, PoDR2Chal};
use secp256k1::{PublicKey, SecretKey};
use sgx_rand::Rng;
use utils::bloom_filter::BloomHash;

use cess_curve::*;
use core::convert::TryInto;
use log::{info, warn};
use sgx_serialize::{DeSerializable, DeSerializeHelper, Serializable, SerializeHelper};
use sgx_types::*;
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

// use ocall_def::ocall_post_podr2_commit_data;
use param::podr2_commit_data::PoDR2SigGenData;
use param::podr2_commit_response::{PoDR2ChalResponse, PoDR2Response};
use param::{
    podr2_commit_data::PoDR2CommitData, podr2_pri_commit_data::PoDR2PriData, Podr2Status,
    StatusInfo,
};
use podr2_pri::key_gen::{MacHash, Symmetric};
use podr2_pri::{QElement, Tag};
use utils::file;

use crate::attestation::hex;
use crate::statics::*;

mod attestation;
mod merkletree_generator;
mod ocall_def;
mod param;
mod pbc;
mod podr2_pri;
mod podr2_proof_commit;
mod podr2_pub;
mod statics;
mod utils;

pub struct Keys {
    skey: secp256k1::SecretKey,
    pkey: secp256k1::PublicKey,
}

impl sgx_serialize::Serializable for Keys {
    fn encode<S: sgx_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let skey = self.skey.serialize();
        s.emit_seq(skey.len(), |s| {
            for (i, e) in skey.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        });

        let pkey = self.pkey.serialize();
        s.emit_seq(pkey.len(), |s| {
            for (i, e) in pkey.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        });
        Ok(())
    }
}

impl sgx_serialize::DeSerializable for Keys {
    fn decode<D: sgx_serialize::Decoder>(d: &mut D) -> Result<Self, D::Error> {
        d.read_seq(|d, len| {
            let skey_len = secp256k1::util::SECRET_KEY_SIZE;

            // Retrieve Secret Key
            let mut ssk = Vec::with_capacity(skey_len);

            for i in 0..skey_len {
                ssk.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }

            let skey_res = ssk.try_into();
            let skey_arr: [u8; secp256k1::util::SECRET_KEY_SIZE] = match skey_res {
                Ok(arr) => arr,
                Err(v) => {
                    error!(
                        "Expected a SecretKey of length {} but it was {}",
                        skey_len,
                        v.len()
                    );
                    return Err(d.error(
                        format!(
                            "Expected a SecretKey of length {} but it was {}",
                            skey_len,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            let skey = match SecretKey::parse(&skey_arr) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to parse SecretKey");
                    return Err(d.error("Failed to parse SecretKey"));
                }
            };

            // PublicKey can be derived from SecretKey
            let pkey = PublicKey::from_secret_key(&skey);


            Ok(Keys { skey, pkey })
        })
    }
}

impl Keys {
    const FILE_NAME: &'static str = "rakeys";

    // Try to Load from the file 1st
    // If not generate new.
    pub fn get_instance() -> Keys {
        let mut file = match SgxFile::open(Keys::FILE_NAME) {
            Ok(f) => f,
            Err(_) => {
                info!("{} file not found, creating new file.", Keys::FILE_NAME);

                // Generate Keys
                let keys = Keys::gen_keys();
                let saved = keys.save();
                if !saved {
                    error!("Failed to save keys");
                }

                info!("Signing keys generated!");
                return keys;
            }
        };

        info!("Keys Loaded!");
        Keys::load(&mut file)
    }

    pub fn gen_keys() -> Keys {
        let mut rand_slice = [0u8; 32];
        let mut os_rng = sgx_rand::SgxRng::new().unwrap().fill_bytes(&mut rand_slice);
        let mut skey = SecretKey::parse_slice(&rand_slice).unwrap();
        let mut pkey = PublicKey::from_secret_key(&skey);
        Keys { skey, pkey }
    }

    fn save(&self) -> bool {
        let helper = SerializeHelper::new();
        let data = match helper.encode(self) {
            Some(d) => d,
            None => {
                warn!("Key encoding failed");
                return false;
            }
        };

        let mut file = match SgxFile::create(Keys::FILE_NAME) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create file {}", Keys::FILE_NAME);
                return false;
            }
        };

        let _write_size = match file.write(data.as_slice()) {
            Ok(len) => len,
            Err(_) => {
                warn!("Failed to write file {}", Keys::FILE_NAME);
                return false;
            }
        };
        return true;
    }

    fn load(file: &mut SgxFile) -> Keys {
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data);

        let helper = DeSerializeHelper::<Keys>::new(data);

        match helper.decode() {
            Some(d) => d,
            None => {
                panic!("Failed to decode file {}.", Keys::FILE_NAME);
            }
        }
    }
}

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
    sgx_status_t::SGX_SUCCESS
}

fn init_keys() -> bool {
    let mut file = match SgxFile::open(podr2_pri::key_gen::EncryptionType::FILE_NAME) {
        Ok(f) => f,
        Err(_) => {
            info!(
                "{} file not found, creating new file.",
                podr2_pri::key_gen::EncryptionType::FILE_NAME
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
    let mut podr2_data = PoDR2PriData::new();
    let callback_url_str = match unsafe { CStr::from_ptr(callback_url).to_str() } {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let file_path_str = match unsafe { CStr::from_ptr(file_path).to_str() } {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let file_info = match utils::file::read_untrusted_file(file_path_str){
        Ok(f) =>f,
        Err(e) =>{
            status.status_msg = e.to_string();
            status.status_code = Podr2Status::PoDr2ErrorNotexistFile as usize;
            podr2_data.status = status;
            utils::post::post_data(callback_url_str.clone(), &podr2_data);
            let mem = utils::enclave_mem::ENCLAVE_MEM_CAP.fetch_add(0, Ordering::SeqCst);
            info!("The enclave space is released to :{} (b)", mem);
            return sgx_status_t::SGX_ERROR_BUSY;
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

    thread::Builder::new()
        .name("process_data".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();
            // let podr2_data = podr2_pub::sig_gen(skey, pkey, &mut d, block_size);
            // let podr2_data = match podr2_data {
            //     Ok(d) => {
            //         status.status_msg = "ok".to_string();
            //         d
            //     }
            //     Err(e) => {
            //         status.status_msg = e.to_string();
            //         status.status_code = Podr2Status::PoDr2Unexpected as usize;
            //         println!("PoDR2 Error: {}", e.to_string());
            //         PoDR2Data::new()
            //     }
            // };

            println!("-------------------PoDR2 TEST Pri-------------------");
            let et = ENCRYPTIONTYPE.lock().unwrap();
            // let et = podr2_pri::key_gen::key_gen();
            // let plain = b"This is not a password";
            // let mut encrypt_result = et.symmetric_encrypt(plain, "enc").unwrap();
            // let ct = utils::convert::u8v_to_hexstr(&encrypt_result);
            // println!("CBC encrypt result is :{:?}", ct);
            // let mut decrypt_result = et.symmetric_decrypt(&encrypt_result, "enc").unwrap();
            // println!("CBC decrypt result is :{:?}",std::str::from_utf8(&decrypt_result).unwrap());
            //
            // let mac_hash_result = et.mac_encrypt(plain).unwrap();
            // let mac_hex = utils::convert::u8v_to_hexstr(&mac_hash_result);
            // println!("HMAC result is :{:?}", mac_hex);

            let n = file::count_file(&file_info.1, block_size);
            // let mut matrix = file::split_file(&file_info.1, block_size);
            // println!("matrix is {:?}", matrix);
            let mut file_hash = match sgx_tcrypto::rsgx_sha256_slice(&file_info.1) {
                Ok(hash) => hash,
                Err(e) => {
                    panic!(e);
                }
            };

            let sig_gen_result =
                podr2_pri::sig_gen::sig_gen(&file_info.1,block_size,n, file_hash.to_vec(), et.clone());
            podr2_data.tag = sig_gen_result.1.clone();
            for sigma in sig_gen_result.0.clone() {
                podr2_data
                    .sigmas
                    .push(utils::convert::u8v_to_hexstr(&sigma))
            }

            podr2_data.status.status_msg = "Sig gen successful!".to_string();
            podr2_data.status.status_code = Podr2Status::PoDr2Success as usize;

            // let proof_id = vec![1, 3, 0, 255];

            // let podr2_chal = match podr2_pri::chal_gen::chal_gen(matrix.len() as i64, &proof_id) {
            //     Ok(chal) => chal,
            //     Err(e) => {
            //         error!("{}", e.to_string());
            //         podr2_data.status.status_msg = format!("{}", e.to_string());
            //         podr2_data.status.status_code = Podr2Status::PoDr2Unexpected as usize;
            //         PoDR2Chal {
            //             q_elements: Vec::new(),
            //             time_out: 0,
            //         }
            //     }
            // };

            // let gen_proof_result = podr2_pri::gen_proof::gen_proof(
            //     sig_gen_result.0,
            //     podr2_chal.q_elements.clone(),
            //     matrix.clone(),
            // );

            // let ok = podr2_pri::verify_proof::verify_proof(
            //     gen_proof_result.0,
            //     gen_proof_result.1,
            //     &sig_gen_result.1,
            //     et.clone(),
            //     &proof_id,
            // );

            // if !ok {
            //     let mut chal_data = CHAL_DATA.lock().unwrap();
            //     chal_data
            //         .failed_file_hashes
            //         .push(podr2_data.tag.t.file_hash.clone());
            //     let hex = utils::convert::u8v_to_hexstr(&podr2_data.tag.t.file_hash);
            //
            //     let mut hash = [0u8; 64];
            //     let bytes = hex.as_bytes();
            //     for i in 0..bytes.len() {
            //         hash[i] = bytes[i];
            //     }
            //
            //     let bloom_hash = BloomHash(hash);
            //     let binary = match bloom_hash.binary() {
            //         Ok(b) => b,
            //         Err(e) => {
            //             warn!("Failed to compute bloom binary: {}", e);
            //             [0u8; 256]
            //         }
            //     };
            //     chal_data.bloom_filter.insert(binary);
            // }

            // println!("verify result is {}", ok);
            println!("-------------------PoDR2 TEST Pri-------------------");
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
        })
        .expect("Failed to launch process_data thread");
    sgx_status_t::SGX_SUCCESS
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
            let podr2_chal = match podr2_pri::chal_gen::chal_gen(n_blocks as i64, &proof_id) {
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

#[no_mangle]
pub extern "C" fn verify_proof(
    proof_id: *mut u8,
    proof_id_len: usize,
    proof_json: *const c_char,
    callback_url: *const c_char,
) -> sgx_status_t {
    let mut pid = unsafe { slice::from_raw_parts(proof_id, proof_id_len).to_vec() };

    let callback_url_str = unsafe { CStr::from_ptr(callback_url).to_str() };
    let callback_url_str = match callback_url_str {
        Ok(url) => url.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let proof_json_hex_str = match unsafe { CStr::from_ptr(proof_json).to_str() } {
        Ok(p) => p.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    if callback_url_str.is_empty() || proof_json_hex_str.is_empty() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    // let proof_json_str=utils::convert::hexstr_to_u8v()

    let _ = thread::Builder::new()
        .name("verify_proof".to_string())
        .spawn(move || {
            let call_back_url = callback_url_str.clone();
            let proof_id = pid.clone();
            let (sigma, miu, tag) = podr2_pri::convert_miner_proof(&proof_json_hex_str);

            let ok = podr2_pri::verify_proof::verify_proof(
                sigma,
                miu,
                &tag,
                ENCRYPTIONTYPE.lock().unwrap().clone(),
                &proof_id,
            );
            debug!("podr2_result is :{}", ok);

            if !ok {
                let mut chal_data = CHAL_DATA.lock().unwrap();
                chal_data.failed_file_hashes.push(tag.t.file_hash.clone());

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
                chal_data.bloom_filter.insert(binary);
            }
        });

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn fill_random_file(file_path: *const c_char, data_len: usize) -> sgx_status_t {
    let file_path = match unsafe { CStr::from_ptr(file_path).to_str() } {
        Ok(path) => path.to_string(),
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    let ok = utils::file::write_untrusted_file(file_path, data_len);
    println!("create random file :{}", ok);
    return sgx_status_t::SGX_SUCCESS;
}

fn get_chal_resp(chal: PoDR2Chal, chal_id: Vec<u8>) -> PoDR2ChalResponse {
    let mut chal_res = PoDR2ChalResponse::new();
    chal_res.challenge.chal_id = chal_id;
    chal_res.challenge.time_out = chal.time_out;
    chal_res.challenge.q_elements = chal.q_elements;
    chal_res
}

#[allow(unused)]
fn get_podr2_resp(
    data: PoDR2SigGenData,
    status_info: param::podr2_commit_response::StatusInfo,
) -> PoDR2Response {
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
