use alloc::string::String;
use alloc::vec::Vec;
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
