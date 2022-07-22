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
#[macro_use]
extern crate log;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use log::{error, info};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{env, str};

mod enclave;
mod models;
mod routes;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let seed = env::var("ENCLAVE_KEY_SEED").unwrap_or("TEST_SEED".to_string());
    let port: u16 = env::var("KALEIDO_PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap();

    env_logger::init();
    info!("Initializing Enclave");
    let result = match init_enclave() {
        Ok(enclave) => {
            let eid = enclave.geteid();
            info!("Enclave Initialized! ID: {}!", eid);

            let mut retval = sgx_status_t::SGX_SUCCESS;
            unsafe {
                // Generate Deterministic Key using ENCLAVE_KEY_SEED
                // This will be removed later as the keys will be generated within enclave.
                enclave::ecalls::gen_keys(eid, &mut retval, seed.as_ptr(), seed.len());
            }
            if retval != sgx_status_t::SGX_SUCCESS {
                enclave.destroy();
                panic!("Failed to generate key pair");
            }

            let res = HttpServer::new(move || {
                let logger = Logger::default();
                let eid = eid.clone();
                App::new()
                    .wrap(logger)
                    .app_data(web::JsonConfig::default().limit(1024 * 1024 * 1024))
                    .app_data(web::Data::new(models::app_state::AppState { eid }))
                    .service(routes::r_process_data)
            })
            .bind(("0.0.0.0", port))?
            .run()
            .await?;
            enclave.destroy();
            info!("Enclave destroyed");
            Ok(res)
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            panic!("Failed to start enclave!");
        }
    };

    result
}

// fn test_rng(enclave: &SgxEnclave) {
//     let length: usize = 5;
//     let mut random_numbers = vec![0u8; length];
//     let mut retval = sgx_status_t::SGX_SUCCESS;

//     let result = unsafe {
//         enclave::ecalls::get_rng(
//             enclave.geteid(),
//             &mut retval,
//             length,
//             random_numbers.as_mut_ptr() as *mut u8,
//         )
//     };
//     match result {
//         sgx_status_t::SGX_SUCCESS => {}
//         _ => {
//             println!("[-] ECALL Enclave Failed for get_rng {}!", result.as_str());
//             return;
//         }
//     }
//     println!("Generated Random Numbers: {:?}", random_numbers);
//     println!("[+] get_rng success...\n");
// }

// fn test_pbc_lib(enclave: &SgxEnclave) {
//     let mut retval = sgx_status_t::SGX_SUCCESS;
//     let result = unsafe { enclave::ecalls::test_pbc(enclave.geteid(), &mut retval) };
//     match result {
//         sgx_status_t::SGX_SUCCESS => {}
//         _ => {
//             println!("[-] ECALL Enclave Failed for test_pbc {}!", result.as_str());
//             return;
//         }
//     }
//     println!("[+] test_pbc success...");
// }

// fn test_sign_message_multi_thread(enclave: &SgxEnclave) {
//     let filename = "../app/example_file.txt";

//     let now = Instant::now();
//     let data = fs::read(filename).expect("Failed to read file");
//     let elapsed = now.elapsed();
//     println!("File read completed in {:.2?}!", elapsed);

//     let mut retval = sgx_status_t::SGX_SUCCESS;
//     let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
//     let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

//     let n_sig = (data.len() as f32 / block_size as f32).ceil() as usize;
//     let mut signatures = Arc::new(Mutex::new(vec![vec![0u8; 33]; n_sig]));
//     let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

//     unsafe {
//         enclave::ecalls::gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
//     }
//     let sig_len: usize = 0;

//     let now = Instant::now();
//     let mut handles = vec![];
//     data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
//         let chunk = chunk.to_vec().clone();
//         let eid = enclave.geteid().clone();
//         let signatures = Arc::clone(&signatures);
//         let mut retval = retval.clone();

//         let handle = thread::spawn(move || {
//             let mut sig = vec![0u8; 33];
//             let result = unsafe {
//                 enclave::ecalls::sign_message(
//                     eid,
//                     &mut retval,
//                     chunk.as_ptr() as *mut _,
//                     chunk.len(),
//                     sig.len(),
//                     sig.as_mut_ptr() as *mut u8,
//                 )
//             };

//             match result {
//                 sgx_status_t::SGX_SUCCESS => {
//                     let mut sigs = signatures.lock().unwrap();
//                     *sigs.index_mut(i) = sig;
//                 }
//                 _ => {
//                     println!(
//                         "[-] ECALL Enclave Failed for process_data {}!",
//                         result.as_str()
//                     );
//                     return;
//                 }
//             }
//         });
//         handles.push(handle);
//     });

//     for handle in handles {
//         handle.join().unwrap();
//     }

//     let elapsed = now.elapsed();

//     let mut pkey = vec![0u8; 65];

//     let result = unsafe {
//         enclave::ecalls::get_public_key(
//             enclave.geteid(),
//             &mut retval,
//             pkey.len(),
//             pkey.as_mut_ptr() as *mut u8,
//         )
//     };
//     match result {
//         sgx_status_t::SGX_SUCCESS => {}
//         _ => {
//             println!(
//                 "[-] ECALL Enclave Failed to get PublicKey {}!",
//                 result.as_str()
//             );
//             return;
//         }
//     }

//     let sigs = signatures.lock().unwrap().to_vec();
//     println!("First Signature: {:?}", hex::encode(&sigs[0]));
//     println!("Last Signature: {:?}", hex::encode(&sigs[sigs.len() - 1]));
//     println!("PublicKey: {:?}", hex::encode(pkey));
//     println!(
//         "Number of Signatures: {}",
//         &signatures.lock().unwrap().to_vec().len()
//     );
//     println!("Signatures generated in {:.2?}!", elapsed);
//     println!("[+] process_data success...");
// }

// fn test_sign_message_single_thread(enclave: &SgxEnclave) {
//     let filename = "../app/example_file.txt";

//     let now = Instant::now();
//     let data = fs::read(filename).expect("Failed to read file");
//     let elapsed = now.elapsed();
//     println!("File read completed in {:.2?}!", elapsed);

//     let mut retval = sgx_status_t::SGX_SUCCESS;
//     let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
//     let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

//     let mut signatures: Vec<Vec<u8>> = Vec::new();

//     unsafe {
//         enclave::ecalls::gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
//     }

//     let now = Instant::now();
//     data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
//         let mut sig = vec![0u8; 33];
//         let result = unsafe {
//             enclave::ecalls::sign_message(
//                 enclave.geteid(),
//                 &mut retval,
//                 chunk.as_ptr() as *mut _,
//                 chunk.len(),
//                 sig.len(),
//                 sig.as_mut_ptr() as *mut u8,
//             )
//         };

//         match result {
//             sgx_status_t::SGX_SUCCESS => {
//                 signatures.push(sig);
//             }
//             _ => {
//                 println!(
//                     "[-] ECALL Enclave Failed for process_data {}!",
//                     result.as_str()
//                 );
//                 return;
//             }
//         }
//     });

//     let elapsed = now.elapsed();

//     let mut pkey = vec![0u8; 65];

//     let result = unsafe {
//         enclave::ecalls::get_public_key(
//             enclave.geteid(),
//             &mut retval,
//             pkey.len(),
//             pkey.as_mut_ptr() as *mut u8,
//         )
//     };
//     match result {
//         sgx_status_t::SGX_SUCCESS => {}
//         _ => {
//             println!(
//                 "[-] ECALL Enclave Failed to get PublicKey {}!",
//                 result.as_str()
//             );
//             return;
//         }
//     }

//     println!("First Signature: {:?}", hex::encode(&signatures[0]));
//     println!(
//         "Last Signature: {:?}",
//         hex::encode(&signatures[signatures.len() - 1])
//     );

//     println!("Signatures:");
//     for sig in &signatures {
//         println!("{:?}", hex::encode(sig));
//     }

//     println!("First Signature: {:?}", hex::encode(&signatures[0]));
//     println!(
//         "Last Signature: {:?}",
//         hex::encode(&signatures[signatures.len() - 1])
//     );

//     println!("PublicKey: {:?}", hex::encode(pkey));
//     println!("Number of Signatures: {}", &signatures.len());
//     println!("Signatures generated in {:.2?}!", elapsed);
//     println!("[+] process_data success...");
// }

// fn test_sign_message(enclave: &SgxEnclave) {
//     let filename = "../app/example_file.txt";

//     let now = Instant::now();
//     let data = fs::read(filename).expect("Failed to read file");
//     let elapsed = now.elapsed();
//     println!("File read completed in {:.2?}!", elapsed);

//     let mut retval = sgx_status_t::SGX_SUCCESS;
//     let seed = String::from(env::var("ENCLAVE_KEY_SEED").expect("$ENCLAVE_KEY_SEED not set"));
//     let block_size: usize = 1024 * 1024; // 1MB block size gives the best results interms of speed.

//     let n_sig = (data.len() as f32 / block_size as f32).ceil() as usize;
//     let mut signatures = Arc::new(Mutex::new(vec![vec![0u8; 33]; n_sig]));

//     unsafe {
//         enclave::ecalls::gen_keys(enclave.geteid(), &mut retval, seed.as_ptr(), seed.len());
//     }

//     let now = Instant::now();
//     let mut handles = vec![];
//     data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
//         let chunk = chunk.to_vec().clone();
//         let eid = enclave.geteid().clone();
//         let signatures = Arc::clone(&signatures);
//         let mut retval = retval.clone();

//         let handle = thread::spawn(move || {
//             let mut sig = vec![0u8; 33];
//             let result = unsafe {
//                 enclave::ecalls::sign_message(
//                     eid,
//                     &mut retval,
//                     chunk.as_ptr() as *mut _,
//                     chunk.len(),
//                     sig.len(),
//                     sig.as_mut_ptr() as *mut u8,
//                 )
//             };

//             match result {
//                 sgx_status_t::SGX_SUCCESS => {
//                     let mut sigs = signatures.lock().unwrap();
//                     *sigs.index_mut(i) = sig;
//                 }
//                 _ => {
//                     println!(
//                         "[-] ECALL Enclave Failed for process_data {}!",
//                         result.as_str()
//                     );
//                     return;
//                 }
//             }
//         });
//         handles.push(handle);
//     });

//     for handle in handles {
//         handle.join().unwrap();
//     }

//     let elapsed = now.elapsed();

//     let mut pkey = vec![0u8; 65];

//     let result = unsafe {
//         enclave::ecalls::get_public_key(
//             enclave.geteid(),
//             &mut retval,
//             pkey.len(),
//             pkey.as_mut_ptr() as *mut u8,
//         )
//     };
//     match result {
//         sgx_status_t::SGX_SUCCESS => {}
//         _ => {
//             println!(
//                 "[-] ECALL Enclave Failed to get PublicKey {}!",
//                 result.as_str()
//             );
//             return;
//         }
//     }

//     let sigs = signatures.lock().unwrap().to_vec();
//     println!("First Signature: {:?}", hex::encode(&sigs[0]));
//     println!("Last Signature: {:?}", hex::encode(&sigs[sigs.len() - 1]));
//     println!("PublicKey: {:?}", hex::encode(pkey));
//     println!(
//         "Number of Signatures: {}",
//         &signatures.lock().unwrap().to_vec().len()
//     );
//     println!("Signatures generated in {:.2?}!", elapsed);
//     println!("[+] process_data success...");
// }
