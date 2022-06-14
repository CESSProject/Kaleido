use alloc::string::String;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

//filetag struct
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
pub struct FileTagT {
    pub t0: T0,
    pub(crate) signature: Vec<u8>,
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
pub struct T0 {
    pub(crate) name: Vec<u8>,
    pub(crate) n:    usize,
    pub(crate) u:    Vec<Vec<u8>>,
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


//PoDR2CommitResponse structure
pub struct PoDR2CommitResponse {
    pub(crate) t:FileTagT,
    pub(crate) sigmas:Vec<Vec<u8>>,
    statue_msg:PoDR2StatueMsg,
}

pub struct PoDR2StatueMsg {
    pub(crate) status_code:i8,
    pub(crate) msg:String,
}

impl PoDR2CommitResponse {
    pub fn new() -> PoDR2CommitResponse {
        PoDR2CommitResponse {
            t:FileTagT::new(),
            sigmas:Vec::new(),
            statue_msg:PoDR2StatueMsg{
                status_code:0,
                msg:String::new(),
            },
        }
    }
}