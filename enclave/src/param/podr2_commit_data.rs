use core::fmt;
use std::string::ToString;

use alloc::string::String;
use alloc::vec::Vec;
use cess_curve::G1;
use serde::{Deserialize, Serialize};

//filetag struct
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct FileTagT {
    pub t0: T0,
    pub(crate) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct T0 {
    pub(crate) name: Vec<u8>,
    pub(crate) n: usize,
    pub(crate) u: Vec<Vec<u8>>,
}

impl FileTagT {
    pub fn new() -> FileTagT {
        FileTagT {
            t0: T0 {
                name: Vec::new(),
                n: 0,
                u: Vec::new(),
            },
            signature: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitData {
    pub(crate) t: FileTagT,
    pub(crate) sigmas: Vec<Vec<u8>>,
    pub pkey: Vec<u8>,
    pub callback_url: String,
}

impl PoDR2CommitData {
    pub fn new() -> PoDR2CommitData {
        PoDR2CommitData {
            t: FileTagT::new(),
            sigmas: Vec::new(),
            pkey: Vec::new(),
            callback_url: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct PoDR2Error {
    pub message: Option<String>,
}

impl PoDR2Error {
    fn message(&self) -> String {
        match &*self {
            PoDR2Error {
                message: Some(message),
            } => message.clone(),
            PoDR2Error { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for PoDR2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2Data {
    pub(crate) phi: Vec<Vec<u8>>,
    pub mht_root_sig: Vec<u8>,
}

impl PoDR2Data {
    pub fn new() -> PoDR2Data {
        PoDR2Data {
            phi: Vec::new(),
            mht_root_sig: Vec::new(),
        }
    }
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2Chal {
    pub i: Vec<usize>,
    pub vi: Vec<Vec<u8>>,
}

impl PoDR2Chal {
    pub fn new() -> PoDR2Chal {
        PoDR2Chal {
            i: Vec::new(),
            vi: Vec::new(),
        }
    }
}