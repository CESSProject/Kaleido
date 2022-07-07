use crate::models::{
    podr2_commit_data::PoDR2CommitData, podr2_commit_response::PoDR2CommitResponse,
};
use awc::{self, Client};
use libc::c_char;
use std::ffi::CStr;
use futures::executor;

#[no_mangle]
pub extern "C" fn ocall_post_podr2_commit_data(data: *const c_char) {
    let c_str = unsafe { CStr::from_ptr(data) };
    let json_string = c_str.to_str().unwrap().to_owned();

    let podr2_data: PoDR2CommitData = serde_json::from_str(&json_string).unwrap();

    let mut podr2_res = PoDR2CommitResponse::new();
    podr2_res.pkey = base64::encode(podr2_data.pkey);

    let mut sigmas_encoded: Vec<String> = Vec::new();
    for sigma in podr2_data.sigmas {
        sigmas_encoded.push(base64::encode(sigma))
    }

    let mut u_encoded: Vec<String> = Vec::new();
    for u in podr2_data.t.t0.u {
        u_encoded.push(base64::encode(u))
    }

    podr2_res.sigmas = sigmas_encoded;
    podr2_res.t.signature = base64::encode(podr2_data.t.signature);
    podr2_res.t.t0.name = base64::encode(podr2_data.t.t0.name);
    podr2_res.t.t0.n = podr2_data.t.t0.n;
    podr2_res.t.t0.u = u_encoded;

    debug!("{:?}", podr2_res);
    debug!("{:?}", podr2_data.callback_url);

    //TODO: Post Data to callback url

    // let _ = executor::block_on(async move {
    //     let _ = Client::default()
    //     .post(&podr2_data.callback_url)
    //     .send_body(serde_json::to_string(&podr2_res).unwrap())
    //     .await;
    // });
    
}
