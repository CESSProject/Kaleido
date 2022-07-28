extern crate alloc;

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
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[repr(C)]
pub struct EnclaveMemoryCounter{
    pub data_len:usize
}
impl EnclaveMemoryCounter {
    pub fn new() -> EnclaveMemoryCounter {
        EnclaveMemoryCounter {
            data_len:0
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
