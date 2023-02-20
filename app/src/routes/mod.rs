extern crate base64;

use std::ffi::CString;

use actix_web::{post, web, Responder};
use sgx_types::*;
use url::Url;

use crate::enclave;
use crate::enclave::sgx_to_podr2_error::PoDR2SgxErrorResponder;
use crate::models::app_state::AppState;
use crate::models::podr2_commit_response::{
    PoDR2ChalRequest, PoDR2CommitRequest, PoDR2Error, PoDR2VerifyRequest,
};
use crate::models::req::{ReqFillRandomFile, ReqMessageSignature, ReqReport, ReqTestFunc};

// r_ is appended to identify routes
#[post("/process_data")]
pub async fn r_process_data(
    data: web::Data<AppState>,
    req: web::Json<PoDR2CommitRequest>,
) -> Result<impl Responder, PoDR2Error> {
    let eid = data.eid;

    let c_callback_url_str = get_c_url_str_from_string(&req.callback_url)?;
    let c_file_path_str = match CString::new(req.file_path.as_str().as_bytes().to_vec()) {
        Ok(p) => p,
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(e.to_string()),
            });
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

    debug!("Processing file data");

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let result2 = unsafe {
        enclave::ecalls::process_data(
            eid,
            &mut result1,
            c_file_path_str.as_ptr(),
            req.block_size,
            c_callback_url_str.as_ptr(),
        )
    };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

#[post("/get_report")]
pub async fn r_get_report(
    data: web::Data<AppState>,
    req: web::Json<ReqReport>,
) -> Result<impl Responder, PoDR2Error> {
    let callback_url = match Url::parse(&req.callback_url) {
        Ok(url) => url,
        Err(e) => {
            warn!("Get callbcak url fail! error:{:?}", e.to_string());
            return Err(PoDR2Error {
                message: Some("Get callbcak url fail!".to_string() + &e.to_string()),
            });
        }
    };

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let c_callback_url_str = CString::new(callback_url.as_str().as_bytes().to_vec()).unwrap();
    let result2 =
        unsafe { enclave::ecalls::get_report(data.eid, &mut result1, c_callback_url_str.as_ptr()) };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

// r_ is appended to identify routes
#[post("/get_chal")]
pub async fn r_get_chal(
    data: web::Data<AppState>,
    req: web::Json<PoDR2ChalRequest>,
) -> Result<impl Responder, PoDR2Error> {
    let eid = data.eid;

    let c_callback_url_str = get_c_url_str_from_string(&req.callback_url)?;

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let result2 = unsafe {
        enclave::ecalls::gen_chal(
            eid,
            &mut result1,
            req.n_blocks,
            req.proof_id.as_ptr() as *mut u8,
            req.proof_id.len(),
            c_callback_url_str.as_ptr(),
        )
    };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

#[post("/verify_proof")]
pub async fn r_verify_proof(
    data: web::Data<AppState>,
    req: web::Json<PoDR2VerifyRequest>,
) -> Result<impl Responder, PoDR2Error> {
    let eid = data.eid;

    let c_proof_json_str = CString::new(req.proof_json.as_str().as_bytes().to_vec());
    let c_proof_json_str = match c_proof_json_str {
        Ok(s) => s,
        Err(_) => {
            return Err(PoDR2Error {
                message: Some("Invalid c_proof_json_str".to_string()),
            });
        }
    };

    let mut result1 = sgx_status_t::SGX_SUCCESS;

    let proof_id = base64::decode(req.proof_id.clone());
    let proof_id = match proof_id {
        Ok(id) => id,
        Err(_) => {
            return Err(PoDR2Error {
                message: Some("Invalid proof_id".to_string()),
            });
        }
    };

    let result2 = unsafe {
        enclave::ecalls::verify_proof(
            eid,
            &mut result1,
            req.verify_type,
            proof_id.as_ptr() as *mut u8,
            proof_id.len(),
            c_proof_json_str.as_ptr(),
        )
    };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

#[post("/fill_random_file")]
pub async fn r_fill_random_file(
    data: web::Data<AppState>,
    req: web::Json<ReqFillRandomFile>,
) -> Result<impl Responder, PoDR2Error> {
    let file_path_ptr = CString::new(req.file_path.as_str().as_bytes().to_vec()).unwrap();

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let result2 = unsafe {
        enclave::ecalls::fill_random_file(
            data.eid,
            &mut result1,
            file_path_ptr.as_ptr(),
            req.data_len,
        )
    };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

#[post("/message_signature")]
pub async fn r_message_signature(
    data: web::Data<AppState>,
    req: web::Json<ReqMessageSignature>,
) -> Result<impl Responder, PoDR2Error> {
    let msg_ptr = CString::new(req.msg.as_str().as_bytes().to_vec()).unwrap();
    let callback_ptr = CString::new(req.callback_url.as_str().as_bytes().to_vec()).unwrap();

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let result2 = unsafe {
        enclave::ecalls::message_signature(
            data.eid,
            &mut result1,
            msg_ptr.as_ptr(),
            callback_ptr.as_ptr(),
        )
    };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

#[post("/test_func")]
pub async fn test_func(
    data: web::Data<AppState>,
    req: web::Json<ReqTestFunc>,
) -> Result<impl Responder, PoDR2Error> {
    let msg_ptr = CString::new(req.msg.as_str().as_bytes().to_vec()).unwrap();

    let mut result1 = sgx_status_t::SGX_SUCCESS;
    let result2 = unsafe { enclave::ecalls::test_func(data.eid, &mut result1, msg_ptr.as_ptr()) };

    PoDR2SgxErrorResponder::parse_error(result1, result2)
}

fn get_c_url_str_from_string(url_str: &String) -> Result<CString, PoDR2Error> {
    let callback_url = Url::parse(url_str);
    let callback_url = match callback_url {
        Ok(url) => url,
        Err(_) => {
            return Err(PoDR2Error {
                message: Some("Invalid url".to_string()),
            });
        }
    };
    Ok(CString::new(callback_url.as_str().as_bytes().to_vec()).unwrap())
}
