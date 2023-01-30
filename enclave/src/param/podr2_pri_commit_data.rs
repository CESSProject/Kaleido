use alloc::string::{String, ToString};
use alloc::vec::Vec;
use podr2_v1_pri::{Tag, Tag0};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct PoDR2PriData{
    pub sigmas:Vec<String>,
    pub tag:Tag,
    pub status:super::StatusInfo
}


impl PoDR2PriData {
    pub fn new() -> PoDR2PriData {
        PoDR2PriData {
            sigmas: vec![],
            tag: Tag { t: Tag0 { n: 0, enc: vec![], file_hash: vec![] }, mac_t0: vec![] },
            status: super::StatusInfo { status_code: 0, status_msg: "".to_string() }
        }
    }
}