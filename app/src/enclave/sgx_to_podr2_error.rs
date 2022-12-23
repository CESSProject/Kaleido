use actix_web::{HttpResponse, Responder};
use sgx_types::sgx_status_t;

use crate::models::podr2_commit_response::PoDR2Error;

pub struct PoDR2SgxErrorResponder {}

impl PoDR2SgxErrorResponder {
    #[inline]
    pub fn parse_error(
        result1: sgx_status_t,
        result2: sgx_status_t,
    ) -> Result<impl Responder, PoDR2Error> {
        if result1 != sgx_status_t::SGX_SUCCESS  {
            return Err(PoDR2Error {
                message: Some(result1.__description().to_string()),
            });
        }

        if result2 != sgx_status_t::SGX_SUCCESS {
            return Err(PoDR2Error {
                message: Some(result2.__description().to_string()),
            });
        }

        Ok(HttpResponse::Ok())
    }
}
