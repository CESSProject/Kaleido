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

#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[macro_use]
pub mod cert;
pub mod hex;

use crate::{Keys, KEYS};
use libc::rand;
use ocall_def::*;
use secp256k1::*;
use sgx_rand::*;
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};
use std::env;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::untrusted::fs;
use std::vec::Vec;
use utils::convert::u8v_to_hexstr;
// use itertools::Itertools;

pub const IAS_HOSTNAME: &'static str = env!("IAS_HOSTNAME");
pub const IAS_SIGRL_SUFFIX: &'static str = env!("IAS_SIGRL_SUFFIX");
pub const IAS_REPORT_SUFFIX: &'static str = env!("IAS_REPORT_SUFFIX");
pub const CERTEXPIRYDAYS: i64 = 90i64;

fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
    println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. "
        }
        _ => {
            println!("DBG:{}", respp.code.unwrap());
            msg = "Unknown error occured"
        }
    }

    println!("{}", msg);
    let mut len_num: u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name {
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => {
                cert = str::from_utf8(h.value).unwrap().to_string()
            }
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        debug!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    debug!("Parse SIGRL result {:?}", result);
    debug!("Parse SIGRL response{:?}", respp);

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. "
        }
        _ => msg = "Unknown error occured",
    }

    info!("SIGRL: {}", msg);
    let mut len_num: u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> Vec<u8> {
    debug!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();
    let ias_key = get_ias_api_key();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                      IAS_SIGRL_SUFFIX,
                      gid,
                      IAS_HOSTNAME,
                      ias_key);
    debug!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }

    let resp_string = String::from_utf8(plaintext.clone()).unwrap();
    debug!("SIGRL Response: {}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> (String, String, String) {
    println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let ias_key = get_ias_api_key();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                      IAS_REPORT_SUFFIX,
                      IAS_HOSTNAME,
                      ias_key,
                      encoded_json.len(),
                      encoded_json);
    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(
    pub_k: &PublicKey,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    debug!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = 0;

    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();

    report_data.d[..33].clone_from_slice(&pub_k.serialize_compressed());

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            debug!("Report creation => success");
            Some(r)
        }
        Err(e) => {
            warn!("Report creation => failed {:?}", e);
            None
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);

    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };
    let p_report = (&rep.unwrap()) as *const sgx_report_t;
    let quote_type = sign_type;

    let spid: sgx_spid_t = get_spid();
    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_qe_report,
            p_quote,
            maxlen,
            p_quote_len,
        )
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        warn!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => debug!("rsgx_verify_report passed!"),
        Err(x) => {
            warn!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        warn!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }
    // println!("sgx quote mr_enclave = {:02x}", ti.mr_enclave.m.iter().format(""));
    debug!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        warn!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec);
    Ok((attn_report, sig, cert))
}

fn get_spid() -> sgx_spid_t {
    const IAS_API_KEY_STR: &str = env!("IAS_SPID");
    hex::decode_spid(IAS_API_KEY_STR)
}

fn get_ias_api_key() -> String {
    const IAS_API_KEY_STR: &str = env!("IAS_API_KEY");
    IAS_API_KEY_STR.to_string()
}

struct ClientAuth {
    outdated_ok: bool,
}

impl ClientAuth {
    fn new(outdated_ok: bool) -> ClientAuth {
        ClientAuth {
            outdated_ok: outdated_ok,
        }
    }
}

impl rustls::ClientCertVerifier for ClientAuth {
    fn client_auth_root_subjects(
        &self,
        _sni: Option<&webpki::DNSName>,
    ) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        _certs: &[rustls::Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        println!("client cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ClientCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ClientCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(
                        webpki::Error::ExtensionValueInvalid,
                    ));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(
                    webpki::Error::ExtensionValueInvalid,
                ));
            }
        }
    }
}

struct ServerAuth {
    outdated_ok: bool,
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth {
            outdated_ok: outdated_ok,
        }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        debug!("server cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                return Ok(rustls::ServerCertVerified::assertion());
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    warn!("outdated_ok is set, overriding outdated error");
                    return Ok(rustls::ServerCertVerified::assertion());
                } else {
                    return Err(rustls::TLSError::WebPKIError(
                        webpki::Error::ExtensionValueInvalid,
                    ));
                }
            }
            Err(_) => {
                return Err(rustls::TLSError::WebPKIError(
                    webpki::Error::ExtensionValueInvalid,
                ));
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn run_server(sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
    let keys = KEYS.lock().unwrap();
    let ssk = &keys.skey;
    let spk = &keys.pkey;

    let message_arr = [5u8; 32];
    let ctx_message = Message::parse(&message_arr);
    let (sig, recid) = secp256k1::sign(&ctx_message, &ssk);
    let mut make_rec_sig = [0u8; 65];
    let mut index = 0_usize;
    for i in sig.serialize() {
        make_rec_sig[index] = i;
        index = index + 1;
    }
    if recid.serialize() > 26 {
        make_rec_sig[64] = recid.serialize() + 27;
    } else {
        make_rec_sig[64] = recid.serialize();
    }
    let ok = secp256k1::verify(&ctx_message, &sig, &spk);
    println!("Verify secp256k1 result is {}", ok);
    println!("recid is {:?}", u8v_to_hexstr(&make_rec_sig));

    let (attn_report, sig, cert) = match create_attestation_report(&spk, sign_type) {
        Ok(r) => r,
        Err(e) => {
            warn!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    let mut payload = attn_report.clone() + "|" + &sig.clone() + "|" + &cert.clone();
    let s = attn_report.clone() + &sig.clone() + &cert.clone();
    let mut payload_hash = match sgx_tcrypto::rsgx_sha256_slice(s.as_bytes()) {
        Ok(hash) => hash,
        Err(e) => return e,
    };
    let payload_message = Message::parse(&payload_hash);
    let (payload_sig, payload_recid) = secp256k1::sign(&payload_message, &ssk);
    let mut payload_rec_sig = [0u8; 65];
    let mut n = 0_usize;
    for i in payload_sig.serialize() {
        payload_rec_sig[n] = i;
        n = n + 1;
    }
    if payload_recid.serialize() > 26 {
        payload_rec_sig[64] = payload_recid.serialize() + 27;
    } else {
        payload_rec_sig[64] = payload_recid.serialize();
    }
    let payload_signature_hex = u8v_to_hexstr(&payload_rec_sig);

    payload = payload + "|" + &payload_signature_hex;

    let mut res = crate::PAYLOAD.lock().unwrap();
    res.clone_from(&payload);
    // let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
    //     Ok(r) => r,
    //     Err(e) => {
    //         warn!("Error in gen_ecc_cert: {:?}", e);
    //         return e;
    //     }
    // };
    // let _result = ecc_handle.close();
    //
    // let root_ca_bin = include_bytes!("../../../bin/ca.crt");
    // let mut ca_reader = BufReader::new(&root_ca_bin[..]);
    // let mut rc_store = rustls::RootCertStore::empty();
    // // Build a root ca storage
    // rc_store.add_pem_file(&mut ca_reader).unwrap();
    // // Build a default authenticator which allow every authenticated client

    // let authenticator = rustls::AllowAnyAuthenticatedClient::new(rc_store);
    // let mut cfg = rustls::ServerConfig::new(authenticator);
    // let mut certs = Vec::new();
    // certs.push(rustls::Certificate(cert_der));
    // let privkey = rustls::PrivateKey(key_der);
    //
    // cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
    //     .unwrap();
    //
    // let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    // let mut conn = TcpStream::new(socket_fd).unwrap();
    //
    // let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    // let mut plaintext = [0u8;1024]; //Vec::new();
    // match tls.read(&mut plaintext) {
    //     Ok(_) => println!("Client said: {}", str::from_utf8(&plaintext).unwrap()),
    //     Err(e) => {
    //         println!("Error in read_to_end: {:?}", e);
    //         panic!("");
    //     }
    // };
    //
    // tls.write("hello back".as_bytes()).unwrap();

    sgx_status_t::SGX_SUCCESS
}
