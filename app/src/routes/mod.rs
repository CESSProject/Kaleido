use actix_web::{post, web, HttpResponse, Responder};
use sgx_types::*;

use crate::app::AppState;

extern "C" {
    fn get_rng(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        length: usize,
        value: *mut u8,
    ) -> sgx_status_t;
}

#[post("/get_rng")]
pub async fn r_get_rng(data: web::Data<AppState>) -> impl Responder {
    let length: usize = 5;
    let mut random_numbers = vec![0u8; length];
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        get_rng(
            data.eid,
            &mut retval,
            length,
            random_numbers.as_mut_ptr() as *mut u8,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed for get_rng {}!", result.as_str());
        }
    }
    println!("Generated Random Numbers: {:?}", random_numbers);

    HttpResponse::Ok().body(format!("RNG: {:?}\n", random_numbers))
}

