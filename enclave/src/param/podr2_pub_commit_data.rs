use alloc::string::String;
use alloc::vec::Vec;
use podr2_v2_pub_rsa::SigGenResponse;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct PoDR2PubData{
    pub result:SigGenResponse,
    pub status:super::StatusInfo
}


impl PoDR2PubData {
    pub fn new() -> PoDR2PubData {
        PoDR2PubData {
            result: SigGenResponse::new(),
            status: super::StatusInfo::new()
        }
    }
}