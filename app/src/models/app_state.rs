use serde::{Deserialize, Serialize};
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use alloc::string::String;
use alloc::vec::Vec;
use std::fmt;
// This struct represents state
pub struct AppState {
    // Enclave Id
    pub eid: u64,
}
