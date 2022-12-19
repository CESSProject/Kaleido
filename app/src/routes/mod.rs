extern crate base64;

use actix_web::http::header::ContentType;
use actix_web::{error, post, web, HttpRequest, HttpResponse, Responder};
use sgx_types::*;

use crate::enclave;
use crate::models::app_state::AppState;
use crate::models::req::{ReqReport,ReqFail,ReqFillRandomFile};
use crate::models::podr2_commit_response::{
    PoDR2ChalRequest, PoDR2CommitRequest, PoDR2CommitResponse, PoDR2Error,
};

use std::ffi::{CString, NulError};
use std::fmt::Debug;
use std::time::Instant;
use url::{ParseError, Url};

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(
    data: web::Data<AppState>,
    req: web::Json<PoDR2CommitRequest>,
) -> Result<impl Responder, PoDR2Error> {
    let eid = data.eid;

    let c_callback_url_str = get_c_url_str_from_string(&req.callback_url)?;
    let c_file_path_str = match CString::new(req.file_path.as_str().as_bytes().to_vec()){
        Ok(p) => {p}
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(e.to_string()),
            })
        }
    };

    // let data_base64: String = req.data.clone();
    // let n_blocks: usize = req.n_blocks;
    // let file_data = base64::decode(data_base64);
    // let file_data = match file_data {
    //     Ok(data) => data,
    //     Err(_) => {
    //         return Err(PoDR2Error {
    //             message: Some("Invalid base64 encoded data.".to_string()),
    //         })
    //     }
    // };
    // debug!("File data decoded");

    let now = Instant::now();
    
    debug!("Processing file data");
    
    // The sgx_status_t returned from ecall is reflected in `result` and not from the returned value here
    let mut result = sgx_status_t::SGX_SUCCESS;
    let res = unsafe {
        enclave::ecalls::process_data(
            eid,
            &mut result,
            c_file_path_str.as_ptr(),
            req.block_size,
            c_callback_url_str.as_ptr(),
        )
    };

    debug!("Processing complete. Status: {}", res.as_str());
    // TODO: Make error handling more sophisticated
    // if res != sgx_status_t::SGX_SUCCESS || result != sgx_status_t::SGX_SUCCESS {
    //     return Err(PoDR2Error {
    //         message: Some("SGX is busy, please try again later.".to_string()),
    //     });
    // }

    let elapsed = now.elapsed();
    debug!("Signatures generated in {:.2?}!", elapsed);

    Ok(HttpResponse::Ok())
}

#[post("/get_report")]
pub async fn r_get_report(
    data: web::Data<AppState>,
    req: web::Json<ReqReport>,
) -> Result<impl Responder, ReqFail> {
    let callback_url = match Url::parse(&req.callback_url) {
        Ok(url) => url,
        Err(e) => {
            warn!("Get callbcak url fail! error:{:?}",e.to_string());
            return Err(ReqFail {
                message: Some("Get callbcak url fail!".to_string()+ &e.to_string())
            })
        }
    };

    let mut result = sgx_status_t::SGX_SUCCESS;
    let c_callback_url_str = CString::new(callback_url.as_str().as_bytes().to_vec()).unwrap();
    let res = unsafe {
        enclave::ecalls::get_report(
            data.eid,
            &mut result,
            c_callback_url_str.as_ptr(),
        )
    };
    if res != sgx_status_t::SGX_SUCCESS || result != sgx_status_t::SGX_SUCCESS {
        return Err(ReqFail {
            message: Some("Error happened when get report from Kaleido!".to_string())
        })
    }
    Ok(HttpResponse::Ok())
}

// r_ is appended to identify routes
#[post("/get_chal")]
pub async fn r_get_chal(
    data: web::Data<AppState>,
    req: web::Json<PoDR2ChalRequest>,
) -> Result<impl Responder, PoDR2Error> {
    let eid = data.eid;

    let c_callback_url_str = get_c_url_str_from_string(&req.callback_url)?;

    let mut result = sgx_status_t::SGX_SUCCESS;
    let res = unsafe {
        enclave::ecalls::gen_chal(
            eid,
            &mut result,
            req.n_blocks,
            req.random.as_ptr() as *mut u8,
            req.random.len(),
            req.time,
            c_callback_url_str.as_ptr(),
        )
    };

    debug!("Processing complete. Status: {}", res.as_str());
    // TODO: Make error handling more sophisticated
    if res != sgx_status_t::SGX_SUCCESS || result != sgx_status_t::SGX_SUCCESS {
        return Err(PoDR2Error {
            message: Some("SGX is busy, please try again later.".to_string()),
        });
    }

    Ok(HttpResponse::Ok())
}

#[post("/fill_random_file")]
pub async fn r_fill_random_file(
    data: web::Data<AppState>,
    req: web::Json<ReqFillRandomFile>,
) -> Result<impl Responder, ReqFail> {
    let mut result = sgx_status_t::SGX_SUCCESS;
    let file_path_ptr = CString::new(req.file_path.as_str().as_bytes().to_vec()).unwrap();
    let res = unsafe {
        enclave::ecalls::fill_random_file(
            data.eid,
            &mut result,
            file_path_ptr.as_ptr(),
            req.data_len
        )
    };
    Ok(HttpResponse::Ok())
}

fn get_c_url_str_from_string(url_str: &String) -> Result<CString, PoDR2Error> {
    let callback_url = Url::parse(url_str);
    let callback_url = match callback_url {
        Ok(url) => url,
        Err(_) => {
            return Err(PoDR2Error {
                message: Some("Invalid url".to_string()),
            })
        }
    };
    Ok(CString::new(callback_url.as_str().as_bytes().to_vec()).unwrap())
}

fn get_c_file_path_from_string(url_str: &String) -> Result<CString, PoDR2Error> {
    let c_file_path_str = match CString::new(url_str.as_bytes().to_vec()){
        Ok(p) => {p}
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(e.to_string()),
            })
        }
    };
    Ok(c_file_path_str)
}