use std::fmt;
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ReqReport {
    pub callback_url: String,
}


#[derive(Debug)]
pub struct ReqFail {
    pub message: Option<String>,
}

impl ReqFail {
    fn message(&self) -> String {
        match &*self {
            ReqFail {
                message: Some(message),
            } => message.clone(),
            ReqFail { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for ReqFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitErrorResponse {
    pub error: String,
}

impl ResponseError for ReqFail {
    fn status_code(&self) -> actix_web::http::StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        HttpResponse::build(self.status_code()).json(PoDR2CommitErrorResponse {
            error: self.message(),
        })
    }
}