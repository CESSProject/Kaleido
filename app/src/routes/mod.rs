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
    let data: Vec<u8> = Vec::new();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let sig_len: usize = 0;

    let now = Instant::now();
    let result = unsafe {
        enclave_def::process_data(
            eid,
            &mut retval,
            data.as_ptr() as *mut u8,
            data.len(),
            1024 * 1024, // 1MB block size gives the best results interms of speed.
            &sig_len,
            true,
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

    let mut pkey = vec![0u8; 65];
    let mut signatures = vec![vec![0u8; 33]; sig_len];

    let result = unsafe {
        for i in 0..signatures.len() {
            let res = enclave_def::get_signature(
                eid,
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
                        res.as_str()
                    );
                    HttpResponse::InternalServerError();
                }
            }
        }
        enclave_def::get_public_key(eid, &mut retval, pkey.len(), pkey.as_mut_ptr() as *mut u8)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!(
                "[-] ECALL Enclave Failed to get PublicKey {}!",
                result.as_str()
            );
            HttpResponse::InternalServerError();
        }
    }

    if signatures.len() > 1 {
        println!("First Signature: {:?}", hex::encode(&signatures[0]));
        println!(
            "Last Signature: {:?}",
            hex::encode(&signatures[signatures.len() - 1])
        );
    }
    println!("PublicKey: {:?}", hex::encode(pkey));
    println!("Number of Signatures: {}", &signatures.len());
    println!("Signatures generated in {:.2?}!", elapsed);
    println!("[+] process_data success...");

    HttpResponse::Ok().body("Success")
}
