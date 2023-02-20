// use crate::models::{
//     podr2_commit_data::PoDR2CommitData, podr2_commit_response::PoDR2CommitResponse,
// };
// use awc::{self, Client};
// use futures::executor;
// use libc::c_char;
// use std::ffi::CStr;
// use tokio::runtime::Handle;
// use std::thread;

// #[no_mangle]
// pub extern "C" fn ocall_post_podr2_commit_data(data: *const c_char) {
//     let c_str = unsafe { CStr::from_ptr(data) };
//     let json_string = c_str.to_str().unwrap().to_owned();

//     let podr2_data: PoDR2CommitData = serde_json::from_str(&json_string).unwrap();

//     let mut podr2_res = PoDR2CommitResponse::new();
//     podr2_res.pkey = base64::encode(podr2_data.pkey);

//     let mut sigmas_encoded: Vec<String> = Vec::new();
//     for sigma in podr2_data.sigmas {
//         sigmas_encoded.push(base64::encode(sigma))
//     }

//     let mut u_encoded: Vec<String> = Vec::new();
//     for u in podr2_data.t.t0.u {
//         u_encoded.push(base64::encode(u))
//     }

//     podr2_res.sigmas = sigmas_encoded;
//     podr2_res.t.signature = base64::encode(podr2_data.t.signature);
//     podr2_res.t.t0.name = base64::encode(podr2_data.t.t0.name);
//     podr2_res.t.t0.n = podr2_data.t.t0.n;
//     podr2_res.t.t0.u = u_encoded;

//     debug!("{:?}", podr2_res);
//     debug!("{:?}", podr2_data.callback_url);

//     //TODO: Post Data to callback url
// }

// async fn post_data(data: PoDR2CommitResponse, url: String) {
//     let res = Client::default()
//         .post(url)
//         .send_body(serde_json::to_string(&data).unwrap())
//         .await;
//     debug!("Response: {:?}", res);
// }

#![allow(dead_code)]
#![allow(unused_assignments)]

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::str;

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    debug!("Entering ocall_sgx_init_quote");
    unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

    unsafe {
        *ret_fd = sock.into_raw_fd();
    }

    sgx_status_t::SGX_SUCCESS
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

#[no_mangle]
pub extern "C" fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_spid: *const sgx_spid_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32,
) -> sgx_status_t {
    debug!("Entering ocall_get_quote");

    let mut real_quote_len: u32 = 0;

    let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

    if ret != sgx_status_t::SGX_SUCCESS {
        warn!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    unsafe {
        *p_quote_len = real_quote_len;
    }

    let ret = unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_sigrl,
            sigrl_len,
            p_qe_report,
            p_quote as *mut sgx_quote_t,
            real_quote_len,
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        warn!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    ret
}

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
    unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) }
}
