extern crate base64;

use actix_web::http::header::ContentType;
use actix_web::{error, post, web, HttpResponse, Responder};
use sgx_types::*;

use crate::app::AppState;
use crate::enclave_def;
use crate::models::podr2_commit::{PoDR2CommitError, PoDR2CommitRequest, PoDR2CommitResponse};
use std::time::Instant;

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(
    data: web::Data<AppState>,
    req: web::Json<PoDR2CommitRequest>,
) -> Result<impl Responder, PoDR2CommitError> {
    let eid = data.eid;

    let data_base64: String = req.data.clone();
    let block_size: usize = req.block_size;
    let segment_size: usize = req.segment_size;
    let file_data = base64::decode(data_base64);
    let file_data = match file_data {
        Ok(data) => data,
        Err(_) => {
            return Err(PoDR2CommitError {
                message: Some("Invalid base64 encoded data.".to_string()),
            })
        }
    };
    debug!("File data decoded");

    let now = Instant::now();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let sigmas_len: usize = 0;
    let u_len: usize = 0;
    let mut name = vec![0u8; 32];
    let mut sig = vec![0u8; 33];

    debug!("Processing file data");
    let result = unsafe {
        enclave_def::process_data(
            eid,
            &mut retval,
            file_data.as_ptr() as *mut u8,
            file_data.len(),
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
    
    debug!("Processing complete");
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            error!(
                "[-] ECALL Enclave Failed for process_data {}!",
                result.as_str()
            );
            HttpResponse::InternalServerError();
        }
    }

    let elapsed = now.elapsed();
    let mut commit_res = PoDR2CommitResponse::new();
    commit_res.pkey = get_public_key(eid)?;
    commit_res.sigmas = get_sigmas(eid, sigmas_len)?;
    commit_res.t.signature = base64::encode(sig);
    commit_res.t.t0.name = base64::encode(name);
    commit_res.t.t0.n = sigmas_len;
    commit_res.t.t0.u = get_u(eid, u_len)?;

    debug!(
        "************************ PoDR2Commit Result - BASE64 ENCODED ************************"
    );
    debug!("PKey: {:?}", commit_res.pkey);
    debug!("signature: {:?}", commit_res.t.signature);
    debug!("name: {:?}", commit_res.t.t0.name);
    debug!("sigmas: {:?}", commit_res.sigmas);
    debug!("u: {:?}", commit_res.t.t0.u);
    debug!("Signatures generated in {:.2?}!", elapsed);
    debug!("[+] process_data success...");

    Ok(HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(serde_json::to_string(&commit_res).unwrap()))
}

// TODO: Return Result<T, E> instead
fn get_public_key(eid: u64) -> Result<String, PoDR2CommitError> {
    let mut pkey = vec![0u8; 65];
    let mut retval = sgx_status_t::SGX_SUCCESS;

    unsafe {
        let res =
            enclave_def::get_public_key(eid, &mut retval, pkey.len(), pkey.as_mut_ptr() as *mut u8);

        match res {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                error!(
                    "[-] ECALL Enclave Failed to get Publickey, {}!",
                    res.as_str()
                );
                return Err(PoDR2CommitError {
                    message: Some("Failed to get PublicKey".to_string()),
                });
            }
        }
    };
    Ok(base64::encode(pkey))
}

// TODO: Return Result<T, E> instead
fn get_sigmas(eid: u64, len: usize) -> Result<Vec<String>, PoDR2CommitError> {
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
                    error!(
                        "[-] ECALL Enclave Failed to get Signature at index: {}, {}!",
                        i,
                        res.as_str()
                    );
                    return Err(PoDR2CommitError {
                        message: Some("Failed to get Signatures".to_string()),
                    });
                }
            }
        }
    }
    let mut sigmas_encoded: Vec<String> = Vec::new();
    for sigma in sigmas {
        sigmas_encoded.push(base64::encode(sigma))
    }
    Ok(sigmas_encoded)
}

// TODO: Return Result<T, E> instead
fn get_u(eid: u64, len: usize) -> Result<Vec<String>, PoDR2CommitError> {
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
                    error!(
                        "[-] ECALL Enclave Failed to get u at index: {}, {}!",
                        i,
                        res.as_str()
                    );
                    return Err(PoDR2CommitError {
                        message: Some("Failed to get u".to_string()),
                    });
                }
            }
        }
    };
    let mut u_encoded: Vec<String> = Vec::new();
    for u in us {
        u_encoded.push(base64::encode(u))
    }
    Ok(u_encoded)
}
