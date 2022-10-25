extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use std::fmt;
use param::podr2_status;

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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct StatusInfo{
    pub status_code:usize,
    pub status_msg:String
}

impl StatusInfo {
    pub fn new() ->StatusInfo{
        StatusInfo{
            status_code:podr2_status::PoDR2_SUCCESS as usize,
            status_msg:String::new()
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
    pub status:StatusInfo
}

impl PoDR2CommitResponse {
    pub fn new() -> PoDR2CommitResponse {
        PoDR2CommitResponse {
            t: FileTagT::new(),
            sigmas: Vec::new(),
            pkey: String::new(),
            status:StatusInfo::new(),
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

//PoDR2Response structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct PoDR2Response {
    pub phi: Vec<String>,
    pub mht_root_sig: String,
    pub status:StatusInfo
}

impl PoDR2Response {
    pub fn new() -> PoDR2Response {
        PoDR2Response {
            phi: Vec::new(),
            mht_root_sig: String::new(),
            status:StatusInfo::new(),
        }
    }
}