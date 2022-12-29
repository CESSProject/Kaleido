use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

pub mod podr2_commit_response;
pub mod podr2_commit_data;
pub mod podr2_pri_commit_data;

pub enum Podr2Status {
    PoDr2Success                        =       100000,
    PoDr2Unexpected                     =       100001,
    PoDr2ErrorInvalidParameter          =       100002,
    PoDr2ErrorOutOfMemory               =       100003,
    PoDr2ErrorNotexistFile              =       100004,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct StatusInfo {
    pub status_code: usize,
    pub status_msg: String,
}

impl StatusInfo {
    pub fn new() -> StatusInfo {
        StatusInfo {
            status_code: 0,
            status_msg: "".to_string()
        }
    }
}