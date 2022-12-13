use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

pub mod key_gen;
pub mod sig_gen;
pub mod chal_gen;
pub mod gen_proof;
pub mod verify_proof;

#[derive(Clone)]
pub struct Tag {
    pub t: Tag0,
    pub mac_t0: Vec<u8>,
}

impl Tag {
    pub fn new() -> Tag {
        Tag {
            t: Tag0 { n: 0, enc: vec![] },
            mac_t0: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[derive(Clone)]
pub struct Tag0 {
    pub n: i64,
    pub enc: Vec<u8>,
}

impl Tag0 {
    pub fn new() -> Tag0 {
        Tag0 {
            n: 0,
            enc: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct EncEncrypt {
    pub prf: Vec<u8>,
    pub alpha: Vec<i128>,
}

impl EncEncrypt {
    pub fn new() -> EncEncrypt {
        EncEncrypt {
            prf: vec![],
            alpha: vec![]
        }
    }
}
#[derive(Clone)]
pub struct QElement {
    pub i: i64,
    pub v: i64
}