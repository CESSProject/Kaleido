extern crate base64;

use actix_web::http::header::ContentType;
use actix_web::{post, web, HttpResponse, Responder};
use sgx_types::*;

use crate::app::AppState;
use crate::enclave_def;
use crate::models::podr2_commit::{PoDR2CommitResponse, PoDR2CommitRequest};
use std::time::Instant;

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(data: web::Data<AppState>, req: web::Json<PoDR2CommitRequest>) -> impl Responder {
    let eid = data.eid;

    let data: Vec<u8> = req.data.clone();
    let block_size: usize = req.block_size;
    let segment_size: usize = req.segment_size;

    let now = Instant::now();
    let mut retval = sgx_status_t::SGX_SUCCESS;
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
    let mut commit_res = PoDR2CommitResponse::new();
    commit_res.pkey = get_public_key(eid);
    commit_res.sigmas = get_sigmas(eid, sigmas_len);
    commit_res.t.signature = base64::encode(sig);
    commit_res.t.t0.name = base64::encode(name);
    commit_res.t.t0.n = sigmas_len;
    commit_res.t.t0.u = get_u(eid, u_len);

    println!("outside publicKey:{:?}", commit_res.pkey);
    println!("outside signature:{:?}", commit_res.t.signature);
    println!("outside name:{:?}", commit_res.t.t0.name);
    println!("outside sigmas:{:?}", commit_res.sigmas);
    println!("outside u:{:?}", commit_res.t.t0.u);
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(serde_json::to_string(&commit_res).unwrap())
}

// TODO: Return Result<T, E> instead
fn get_public_key(eid: u64) -> String {
    let mut pkey = vec![0u8; 65];
    let mut retval = sgx_status_t::SGX_SUCCESS;

    unsafe {
        let res =
            enclave_def::get_public_key(eid, &mut retval, pkey.len(), pkey.as_mut_ptr() as *mut u8);

        match res {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                println!(
                    "[-] ECALL Enclave Failed to get Publickey, {}!",
                    res.as_str()
                );
            }
        }
    };
    base64::encode(pkey)
}

// TODO: Return Result<T, E> instead
fn get_sigmas(eid: u64, len: usize) -> Vec<String> {
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
    }
    let mut sigmas_encoded: Vec<String> = Vec::new();
    for sigma in sigmas {
        sigmas_encoded.push(base64::encode(sigma))
    }
    sigmas_encoded
}

// TODO: Return Result<T, E> instead
fn get_u(eid: u64, len: usize) -> Vec<String> {
    let mut us = vec![vec![0u8; 33]; len];
    let mut retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        //get u
        for i in 0..us.len() {
            let res = enclave_def::get_u(
                eid,
                &mut retval,
                i,
                us[i].len(),
                us[i].as_mut_ptr() as *mut u8,
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
    let mut u_encoded: Vec<String> = Vec::new();
    for u in us {
        u_encoded.push(base64::encode(u))
    }
    u_encoded
}
