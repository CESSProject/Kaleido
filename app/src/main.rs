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

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{str, fs, env, time::Instant};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn get_rng(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        length: usize,
        value: *mut u8,
    ) -> sgx_status_t;
    fn test_pbc(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn process_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        seed: *const u8,
        seed_len: usize,
        data: *mut u8,
        length: usize,
        block_size: usize,
        sig_len: &usize,
    ) -> sgx_status_t;
    fn get_public_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pkey_len: usize,
        pkey: *mut u8,
    ) -> sgx_status_t;
    fn get_signature(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        index: usize,
        sig_len: usize,
        sigs: *mut u8,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn test_rng(enclave: &SgxEnclave) {
    let length: usize = 5;
    let mut random_numbers = vec![0u8; length];
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        get_rng(
            enclave.geteid(),
            &mut retval,
            length,
            random_numbers.as_mut_ptr() as *mut u8,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed for get_rng {}!", result.as_str());
            return;
        }
    }
    println!("Generated Random Numbers: {:?}", random_numbers);
    println!("[+] get_rng success...");
}

fn test_pbc_lib(enclave: &SgxEnclave) {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { test_pbc(enclave.geteid(), &mut retval) };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed for test_pbc {}!", result.as_str());
            return;
        }
    }
    println!("[+] test_pbc success...");
}

fn test_process_data(enclave: &SgxEnclave) {
    let filename = "../app/example_file.txt";

    println!("Reading file {}", filename);
    let now = Instant::now();
    let data = fs::read(filename).expect("Failed to read file");
    let elapsed = now.elapsed();
    println!("File read completed in {:.2?}!", elapsed);
    
    
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let sig_len: usize = 0;
    let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
    let block_size: usize = 1024;

    let now = Instant::now();
    let result = unsafe {
        process_data(
            enclave.geteid(),
            &mut retval,
            seed.as_ptr() as * const u8,
            seed.len(),
            data.as_ptr() as *mut _,
            data.len(),
            block_size,
            &sig_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!(
                "[-] ECALL Enclave Failed for process_data {}!",
                result.as_str()
            );
            return;
        }
    }

    let mut pkey = vec![0u8; 65];
    let mut signatures = vec![vec![0u8; 33]; sig_len];

    let result = unsafe {
        for i in 0..signatures.len() {
            let res = get_signature(
                enclave.geteid(),
                &mut retval,
                i,
                signatures[i].len(),
                signatures[i].as_mut_ptr() as *mut u8,
            );
            match res {
                sgx_status_t::SGX_SUCCESS => {}
                _ => {
                    println!(
                        "[-] ECALL Enclave Failed to get Signature at index: {}, {}!",
                        i,
                        result.as_str()
                    );
                    return;
                }
            }
        }
        get_public_key(
            enclave.geteid(),
            &mut retval,
            pkey.len(),
            pkey.as_mut_ptr() as *mut u8,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!(
                "[-] ECALL Enclave Failed to get PublicKey {}!",
                result.as_str()
            );
            return;
        }
    }

    let elapsed = now.elapsed();
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("Number of Signatures: {}", sig_len);
    // println!("Signatures:");
    // for sig in signatures {
    //     println!("{:?}", hex::encode(sig));
    // }
    println!("PublicKey: {:?}", hex::encode(pkey));
    println!("[+] process_data success...");
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    test_rng(&enclave);
    test_pbc_lib(&enclave);
    test_process_data(&enclave);
    enclave.destroy();
}
