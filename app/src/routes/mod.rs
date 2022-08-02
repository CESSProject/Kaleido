extern crate base64;

use actix_web::http::header::ContentType;
use actix_web::{error, post, web, HttpResponse, Responder};
use sgx_types::*;

use crate::enclave;
use crate::models::app_state::AppState;
use crate::models::podr2_commit_response::{
    PoDR2CommitError, PoDR2CommitRequest, PoDR2CommitResponse,
};

use std::ffi::CString;
use std::time::Instant;
use url::{ParseError, Url};

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(
    data: web::Data<AppState>,
    req: web::Json<PoDR2CommitRequest>,
) -> Result<impl Responder, PoDR2CommitError> {
    let eid = data.eid;

    let callback_url = Url::parse(&req.callback_url);
    let callback_url = match callback_url {
        Ok(url) => url,
        Err(_) => {
            return Err(PoDR2CommitError {
                message: Some("Invalid url".to_string()),
            })
        }
    };
    let c_callback_url_str = CString::new(callback_url.as_str().as_bytes().to_vec()).unwrap();
    debug!("Callback URL: {:?}", c_callback_url_str);

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
    let mut result = sgx_status_t::SGX_SUCCESS;
    let sigmas_len: usize = 0;

    debug!("Processing file data");

    // The sgx_status_t returned from ecall is reflected in `result` and not from the returned value here
    unsafe {
        enclave::ecalls::process_data(
            eid,
            &mut result,
            file_data.as_ptr() as *mut u8,
            file_data.len(),
            block_size, // 1MB block size gives the best results interms of speed.
            segment_size,
            c_callback_url_str.as_ptr(),
        )
    };

    debug!("Processing complete. Status: {}", result.as_str());
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        sgx_status_t::SGX_ERROR_BUSY => {
            return Err(PoDR2CommitError {
                message: Some("SGX is busy, please try again later.".to_string()),
            });
        }
        _ => {
            error!(
                "[-] ECALL Enclave Failed for process_data {}!",
                result.as_str()
            );
            HttpResponse::InternalServerError();
        }
    }
    let elapsed = now.elapsed();
    debug!("Signatures generated in {:.2?}!", elapsed);

    Ok(HttpResponse::Ok())
}
