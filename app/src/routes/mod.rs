use actix_web::{post, web, HttpResponse, Responder};
use sgx_types::*;

use crate::app::AppState;
use crate::enclave_def;
use std::time::Instant;

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(data: web::Data<AppState>) -> impl Responder {
    let eid = data.eid;

    // TODO: Process received data from post.
    let data: Vec<u8> = vec![123, 12, 23];
    let block_size: usize = 1024 * 1024;

    let now = Instant::now();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let segment_size: usize = 1;
    let sigmas_len: usize = 0;
    let u_len: usize = 0;
    let mut name = vec![0u8; 32];
    let mut sig = vec![0u8; 33];

    let result = unsafe {
        enclave_def::process_data(
            eid,
            &mut retval,
            data.as_ptr() as *mut u8,
            data.len(),
            block_size, // 1MB block size gives the best results interms of speed.
            segment_size,
            &sigmas_len,
            &u_len,
            name.len(),
            name.as_mut_ptr() as *mut u8,
            sig.len(),
            sig.as_mut_ptr() as *mut u8,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!(
                "[-] ECALL Enclave Failed for process_data {}!",
                result.as_str()
            );
            HttpResponse::InternalServerError();
        }
    }

    let elapsed = now.elapsed();

    let pkey = get_public_key(eid);
    let sigmas = get_sigmas(eid, sigmas_len);
    let u = get_u(eid, u_len);

    println!("outside publicKey:{:?}", pkey);
    println!("outside signature:{:?}", sig);
    println!("outside name:{:?}", name);
    println!("outside sigmas:{:?}", sigmas);
    println!("outside u:{:?}", u);
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");

    HttpResponse::Ok().body("Success\n")
}

// TODO: Return Result<T, E> instead
fn get_public_key(eid: u64) -> Vec<u8> {
    let mut pkey = vec![0u8; 65];
    let mut retval = sgx_status_t::SGX_SUCCESS;

    unsafe {
        let res =
            enclave_def::get_public_key(eid, &mut retval, pkey.len(), pkey.as_mut_ptr() as *mut u8);

        match res {
            sgx_status_t::SGX_SUCCESS => {},
            _ => {
                println!(
                    "[-] ECALL Enclave Failed to get Publickey, {}!",
                    res.as_str()
                );
            }
        }
    };
    pkey
}

// TODO: Return Result<T, E> instead
fn get_sigmas(eid: u64, len: usize) -> Vec<Vec<u8>> {
    let mut sigmas = vec![vec![0u8; 33]; len];
    let mut retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        // get sigmas
        for i in 0..sigmas.len() {
            let res = enclave_def::get_sigmas(
                eid,
                &mut retval,
                i,
                sigmas[i].len(),
                sigmas[i].as_mut_ptr() as *mut u8,
            );
            match res {
                sgx_status_t::SGX_SUCCESS => {}
                _ => {
                    println!(
                        "[-] ECALL Enclave Failed to get Signature at index: {}, {}!",
                        i,
                        res.as_str()
                    );
                }
            }
        }
        sigmas
    }
}

// TODO: Return Result<T, E> instead
fn get_u(eid: u64, len: usize) -> Vec<Vec<u8>> {
    let mut u = vec![vec![0u8; 33]; len];
    let mut retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        //get u
        for i in 0..u.len() {
            let res = enclave_def::get_u(
                eid,
                &mut retval,
                i,
                u[i].len(),
                u[i].as_mut_ptr() as *mut u8,
            );
            match res {
                sgx_status_t::SGX_SUCCESS => {}
                _ => {
                    println!(
                        "[-] ECALL Enclave Failed to get Signature at index: {}, {}!",
                        i,
                        res.as_str()
                    ); 
                }
            }
        }
    };
    u
}
