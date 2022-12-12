use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod key_gen;
pub mod sig_gen;

struct Tag {
    t: Tag0,
    mac_t0: Vec<u8>,
}

impl Tag {
    pub fn new() -> Tag {
        Tag {
            t: Tag0 { n: 0, enc: vec![] },
            mac_t0: vec![],
        }
    }
}

struct Tag0 {
    n: i64,
    enc: Vec<u8>,
}

impl Tag0 {
    pub fn new() -> Tag0 {
        Tag0 {
            n: 0,
            enc: vec![],
        }
    }
}

struct EncEncrypt {
    prf: String,
    alpha: Vec<i128>,
}

impl EncEncrypt {
    pub fn new() -> EncEncrypt {
        EncEncrypt {
            prf: "".to_string(),
            alpha: vec![]
        }
    }
}