use std::fmt;
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ReqReport {
    pub callback_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ReqFillRandomFile {
    pub file_path: String,
    pub data_len: usize,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ReqMessageSignature {
    pub msg: String,
    pub callback_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ReqTestFunc {
    pub msg: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitErrorResponse {
    pub error: String,
}