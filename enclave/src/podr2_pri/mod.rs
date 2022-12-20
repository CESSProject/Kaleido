use std::sync::SgxMutex;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub mod chal_gen;
pub mod gen_proof;
pub mod key_gen;
pub mod sig_gen;
pub mod verify_proof;

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofIdentifier {
    /// Unique random value sent by CESS Chain
    pub id: Vec<u8>,
    /// Epoch Time sent by CESS Chain in seconds
    pub time_out: u64,
}

impl PartialEq for ProofIdentifier {
    fn eq(&self, other: &Self) -> bool {
        // Match only id
        self.id == other.id // && self.time == other.time
    }
}

#[derive(Serialize, Deserialize)]
struct ProofIdentifierList {
    identifiers: Vec<ProofIdentifier>,
}

impl ProofIdentifierList {
    pub const fn new() -> ProofIdentifierList {
        ProofIdentifierList {
            identifiers: Vec::new(),
        }
    }
}

lazy_static! (
    static ref PROOF_TIMER_LIST: SgxMutex<ProofIdentifierList> = SgxMutex::new(ProofIdentifierList::new());
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct Tag {
    pub t: Tag0,
    pub mac_t0: Vec<u8>,
}

impl Tag {
    pub fn new() -> Tag {
        use std::time::SystemTime;
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
        Tag0 { n: 0, enc: vec![] }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct EncEncrypt {
    pub prf: String,
    pub alpha: Vec<i64>,
}

impl EncEncrypt {
    pub fn new() -> EncEncrypt {
        EncEncrypt {
            prf: "".to_string(),
            alpha: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QElement {
    pub i: i64,
    pub v: i64,
}
