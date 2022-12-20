use std::sync::SgxMutex;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use utils;

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
    pub q_elements: Vec<QElement>
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[derive(Clone)]
pub struct MinerProof {
    pub sigma: String,
    pub miu: Vec<String>,
    pub tag: MinerTag,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[derive(Clone)]
pub struct MinerTag {
    pub t: MinerTag0,
    pub mac_t0: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[derive(Clone)]
pub struct MinerTag0 {
    pub n: i64,
    pub enc: String,
}

pub fn convert_miner_proof(proof:&String) ->(Vec<u8>,Vec<Vec<u8>>,Tag) {
    let miner_proof: MinerProof = serde_json::from_str(proof).unwrap();

    //convert sigma
    let mut sigma=Vec::new();
    utils::convert::hexstr_to_u8v(miner_proof.sigma.as_str(), &mut sigma);

    //convert miu
    let mut miu=Vec::new();
    for item in miner_proof.miu{
        let mut i =Vec::new();
        utils::convert::hexstr_to_u8v(item.as_str(),&mut i);
        miu.push(i);
    }
    //convert tag
    let mut tag = Tag::new();
    tag.t.n=miner_proof.tag.t.n;
    utils::convert::hexstr_to_u8v(miner_proof.tag.t.enc.as_str(),&mut tag.t.enc);
    utils::convert::hexstr_to_u8v(miner_proof.tag.mac_t0.as_str(),&mut tag.mac_t0);

    (sigma,miu,tag)

}