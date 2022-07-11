extern crate alloc;

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct T0 {
    pub name: String,
    pub n: usize,
    pub u: Vec<String>,
}

//filetag struct
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct FileTagT {
    pub t0: T0,
    pub signature: String,
}

impl FileTagT {
    pub fn new() -> FileTagT {
        FileTagT {
            t0: T0 {
                name: String::new(),
                n: 0,
                u: Vec::new(),
            },
            signature: String::new(),
        }
    }
}

//PoDR2CommitResponse structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct PoDR2CommitResponse {
    pub t: FileTagT,
    pub sigmas: Vec<String>,
    pub pkey: String,
}

impl PoDR2CommitResponse {
    pub fn new() -> PoDR2CommitResponse {
        PoDR2CommitResponse {
            t: FileTagT::new(),
            sigmas: Vec::new(),
            pkey: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitRequest {
    pub data: String,
    pub block_size: usize,
    pub segment_size: usize,
    pub callback_url: String,
}

#[derive(Debug)]
pub struct PoDR2CommitError {
    pub message: Option<String>,
}

impl PoDR2CommitError {
    fn message(&self) -> String {
        match &*self {
            PoDR2CommitError {
                message: Some(message),
            } => message.clone(),
            PoDR2CommitError { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for PoDR2CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitErrorResponse {
    pub error: String,
}

impl ResponseError for PoDR2CommitError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        HttpResponse::build(self.status_code()).json(PoDR2CommitErrorResponse {
            error: self.message(),
        })
    }
}
