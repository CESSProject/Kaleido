use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub mod key_gen;
pub mod sig_gen;
pub mod chal_gen;
pub mod gen_proof;
pub mod verify_proof;


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct RSAKeyPair {
    pub prf: String,
    pub alpha: Vec<i64>,
}

impl RSAKeyPair {
    pub fn new() -> RSAKeyPair {
        RSAKeyPair {
            prf: "".to_string(),
            alpha: vec![],
        }
    }
}