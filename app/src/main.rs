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
use std::ops::IndexMut;
use std::{
    env, fs, str,
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn get_rng(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        length: usize,
        value: *mut u8,
    ) -> sgx_status_t;
    fn test_pbc(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    fn gen_keys(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, seed: *const u8, seed_len: usize);
    fn process_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        data: *mut u8,
        data_len: usize,
        block_size: usize,
        segment_size:usize,
        sigmas_len:usize,
        sigmas_ptr: *mut u8,
        u_len:usize,
        u_ptr: *mut u8,
    ) -> sgx_status_t;
    fn sign_message(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        data: *mut u8,
        data_len: usize,
        sig_len: usize,
        sig: *mut u8,
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
    fn get_sigmas(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        g1_len: usize,
        sig_in: *mut u8,
        sig_out: *mut u8,
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
    println!("[+] get_rng success...\n");
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
    let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));

    unsafe {
        gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
    }
    println!("Get KeyGen success!");
    let block_size:usize=1024*1024;
    let segment_size:usize=1;
    let sig_len: usize = 0;

    let now = Instant::now();
    let mut n =data.len()/block_size;
    if data.len()%block_size!=0{
        n=n+1
    }
    let mut s: usize = block_size;
    if block_size > data.len() {
        s = data.len();
    }
    let mut u_num:usize=0;
    u_num=s/segment_size;
    if s%segment_size!=0{
        u_num=u_num+1
    }
    let sigmas_ptr_vec=vec![0u8;n];
    let u_ptr_vec=vec![0u8;u_num];

    let sigmas=vec![vec![0u8];n];
    let u=vec![vec![0u8];u_num];

    let result = unsafe {
        process_data(
            enclave.geteid(),
            &mut retval,
            data.as_ptr() as *mut u8,
            data.len(),
            block_size, // 1MB block size gives the best results interms of speed.
            segment_size,
            n,
            sigmas_ptr_vec.as_ptr() as *mut u8,
            u_num,
            u_ptr_vec.as_ptr() as *mut u8,
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
    println!("outside sigmas_ptr_vec is {:?}",sigmas_ptr_vec);
    println!("outside u_ptr_vec is {:?}",u_ptr_vec);
    let mut sigmas_i =0;
    for sigmas_ptr in sigmas_ptr_vec {
        println!("12121212222222222222222222222222222222222222222");
        let result=unsafe {
            println!("sigmas_ptr:{}",sigmas_ptr as *mut u8);
            println!("sigmas[sigmas_i]:{}",sigmas[sigmas_i].as_ptr() as *mut u8);
            get_sigmas(
                enclave.geteid(),
                &mut retval,
                33,
                sigmas_ptr as *mut u8,
                sigmas[sigmas_i].as_ptr() as *mut u8,
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
        sigmas_i=sigmas_i+1
    }
    let elapsed = now.elapsed();

    // let mut pkey = vec![0u8; 65];
    // let mut signatures = vec![vec![0u8; 33]; sig_len];
    //
    // let result = unsafe {
    //     for i in 0..signatures.len() {
    //         let res = get_signature(
    //             enclave.geteid(),
    //             &mut retval,
    //             i,
    //             signatures[i].len(),
    //             signatures[i].as_mut_ptr() as *mut u8,
    //         );
    //         match res {
    //             sgx_status_t::SGX_SUCCESS => {}
    //             _ => {
    //                 println!(
    //                     "[-] ECALL Enclave Failed to get Signature at index: {}, {}!",
    //                     i,
    //                     res.as_str()
    //                 );
    //                 return;
    //             }
    //         }
    //     }
    //     get_public_key(
    //         enclave.geteid(),
    //         &mut retval,
    //         pkey.len(),
    //         pkey.as_mut_ptr() as *mut u8,
    //     )
    // };
    // match result {
    //     sgx_status_t::SGX_SUCCESS => {}
    //     _ => {
    //         println!(
    //             "[-] ECALL Enclave Failed to get PublicKey {}!",
    //             result.as_str()
    //         );
    //         return;
    //     }
    // }

    // println!("First Signature: {:?}", hex::encode(&signatures[0]));
    // println!(
    //     "Last Signature: {:?}",
    //     hex::encode(&signatures[signatures.len() - 1])
    // );
    // println!("PublicKey: {:?}", hex::encode(pkey));
    // println!("Number of Signatures: {}", &signatures.len());
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");
}

fn test_sign_message_multi_thread(enclave: &SgxEnclave) {
    let filename = "../app/example_file.txt";

    let now = Instant::now();
    let data = fs::read(filename).expect("Failed to read file");
    let elapsed = now.elapsed();
    println!("File read completed in {:.2?}!", elapsed);

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
    let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

    let n_sig = (data.len() as f32 / block_size as f32).ceil() as usize;
    let mut signatures = Arc::new(Mutex::new(vec![vec![0u8; 33]; n_sig]));
    let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

    unsafe {
        gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
    }
    let sig_len: usize = 0;

    let now = Instant::now();
    let mut handles = vec![];
    data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
        let chunk = chunk.to_vec().clone();
        let eid = enclave.geteid().clone();
        let signatures = Arc::clone(&signatures);
        let mut retval = retval.clone();

        let handle = thread::spawn(move || {
            let mut sig = vec![0u8; 33];
            let result = unsafe {
                sign_message(
                    eid,
                    &mut retval,
                    chunk.as_ptr() as *mut _,
                    chunk.len(),
                    sig.len(),
                    sig.as_mut_ptr() as *mut u8,
                )
            };

            match result {
                sgx_status_t::SGX_SUCCESS => {
                    let mut sigs = signatures.lock().unwrap();
                    *sigs.index_mut(i) = sig;
                }
                _ => {
                    println!(
                        "[-] ECALL Enclave Failed for process_data {}!",
                        result.as_str()
                    );
                    return;
                }
            }
        });
        handles.push(handle);
    });

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = now.elapsed();

    let mut pkey = vec![0u8; 65];

    let result = unsafe {
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

    let sigs = signatures.lock().unwrap().to_vec();
    println!("First Signature: {:?}", hex::encode(&sigs[0]));
    println!("Last Signature: {:?}", hex::encode(&sigs[sigs.len() - 1]));
    println!("PublicKey: {:?}", hex::encode(pkey));
    println!(
        "Number of Signatures: {}",
        &signatures.lock().unwrap().to_vec().len()
    );
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");
}

fn test_sign_message_single_thread(enclave: &SgxEnclave) {
    let filename = "../app/example_file.txt";

    let now = Instant::now();
    let data = fs::read(filename).expect("Failed to read file");
    let elapsed = now.elapsed();
    println!("File read completed in {:.2?}!", elapsed);

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
    let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

    let mut signatures: Vec<Vec<u8>> = Vec::new();

    unsafe {
        gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
    }

    let now = Instant::now();
    data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
        let mut sig = vec![0u8; 33];
        let result = unsafe {
            sign_message(
                enclave.geteid(),
                &mut retval,
                chunk.as_ptr() as *mut _,
                chunk.len(),
                sig.len(),
                sig.as_mut_ptr() as *mut u8,
            )
        };

        match result {
            sgx_status_t::SGX_SUCCESS => {
                signatures.push(sig);
            }
            _ => {
                println!(
                    "[-] ECALL Enclave Failed for process_data {}!",
                    result.as_str()
                );
                return;
            }
        }
    });

    let elapsed = now.elapsed();

    let mut pkey = vec![0u8; 65];

    let result = unsafe {
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

    println!("First Signature: {:?}", hex::encode(&signatures[0]));
    println!("Last Signature: {:?}", hex::encode(&signatures[signatures.len() - 1]));

    println!("Signatures:");
    for sig in &signatures {
        println!("{:?}", hex::encode(sig));
    }

    println!("First Signature: {:?}", hex::encode(&signatures[0]));
    println!("Last Signature: {:?}", hex::encode(&signatures[signatures.len() - 1]));

    println!("PublicKey: {:?}", hex::encode(pkey));
    println!(
        "Number of Signatures: {}",
        &signatures.len()
    );
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");
}

fn test_sign_message(enclave: &SgxEnclave) {
    let filename = "../app/example_file.txt";

    let now = Instant::now();
    let data = fs::read(filename).expect("Failed to read file");
    let elapsed = now.elapsed();
    println!("File read completed in {:.2?}!", elapsed);

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
    let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

    let n_sig = (data.len() as f32 / block_size as f32).ceil() as usize;
    let mut signatures = Arc::new(Mutex::new(vec![vec![0u8; 33]; n_sig]));

    unsafe {
        gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
    }

    let now = Instant::now();
    let mut handles = vec![];
    data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
        let chunk = chunk.to_vec().clone();
        let eid = enclave.geteid().clone();
        let signatures = Arc::clone(&signatures);
        let mut retval = retval.clone();

        let handle = thread::spawn(move || {
            let mut sig = vec![0u8; 33];
            let result = unsafe {
                sign_message(
                    eid,
                    &mut retval,
                    chunk.as_ptr() as *mut _,
                    chunk.len(),
                    sig.len(),
                    sig.as_mut_ptr() as *mut u8,
                )
            };

            match result {
                sgx_status_t::SGX_SUCCESS => {
                    let mut sigs = signatures.lock().unwrap();
                    *sigs.index_mut(i) = sig;
                }
                _ => {
                    println!(
                        "[-] ECALL Enclave Failed for process_data {}!",
                        result.as_str()
                    );
                    return;
                }
            }
        });
        handles.push(handle);
    });

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = now.elapsed();

    let mut pkey = vec![0u8; 65];

    let result = unsafe {
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

    let sigs = signatures.lock().unwrap().to_vec();
    println!("First Signature: {:?}", hex::encode(&sigs[0]));
    println!("Last Signature: {:?}", hex::encode(&sigs[sigs.len() - 1]));
    println!("PublicKey: {:?}", hex::encode(pkey));
    println!(
        "Number of Signatures: {}",
        &signatures.lock().unwrap().to_vec().len()
    );
    println!("Signatures generated in {:.2?}!", elapsed);
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


    // println!("*************************** TEST RNG *****************************");
    // test_rng(&enclave);
    // println!("******************************************************************\n");
    // println!("*************************** TEST PBC *****************************");
    // test_pbc_lib(&enclave);
    // println!("******************************************************************\n");

    println!("*************************** TEST SIG *****************************");
    test_process_data(&enclave); // Multi-thread within enclave.
    println!("******************************************************************\n");

    // println!("************************* TEST SIG MSG ***************************");
    // test_sign_message_single_thread(&enclave);
    // println!("******************************************************************\n");

    // println!("********************** TEST MULTI SIG MSG ************************");
    // test_sign_message_multi_thread(&enclave);
    // println!("******************************************************************\n");
    enclave.destroy();
}
