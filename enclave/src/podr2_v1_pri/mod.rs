use std::sync::SgxMutex;

use self::chal_gen::{ChalData, Challenge};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use utils;

pub mod chal_gen;
pub mod gen_proof;
pub mod key_gen;
pub mod sig_gen;
pub mod verify_proof;

lazy_static! (
    static ref CHALLENGE: SgxMutex<Challenge> = SgxMutex::new(Challenge::new());
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
            t: Tag0 {
                n: 0,
                enc: vec![],
                file_hash: vec![],
            },
            mac_t0: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct Tag0 {
    pub n: i64,
    pub enc: Vec<u8>,
    pub file_hash: Vec<u8>,
}

impl Tag0 {
    pub fn new() -> Tag0 {
        Tag0 {
            n: 0,
            enc: vec![],
            file_hash: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
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

impl QElement {
    #[inline]
    pub fn get_elements(n: i64) -> Vec<QElement> {
        let mut q_elements: Vec<QElement> = vec![];

        let mut rng = thread_rng();

        let range = (n as f64 * 4.6) / 100_f64;

        let mut low = range.floor();
        let mut high = range.ceil();

        if low < 1_f64 {
            low = 1_f64;
        }
        if high < 1_f64 {
            high = 1_f64;
        }

        let between = Range::new(low, high + 1_f64);
        let n_samples = between.ind_sample(&mut rng) as usize;

        // Choose random blocks
        let mut n_blocks = sgx_rand::sample(&mut rng, 0..n, n_samples);
        n_blocks.sort();

        for i in 0..n_samples {
            let mut rng = thread_rng();
            let v_between = Range::new(0_i64, i64::MAX);
            let v = v_between.ind_sample(&mut rng);
            q_elements.push(QElement { i: n_blocks[i], v });
        }
        q_elements
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct MinerProof {
    pub sigma: String,
    pub miu: Vec<String>,
    pub tag: DMinerTag,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct DMinerTag {
    pub t: MinerTag0,
    pub mac_t0: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct MinerTag0 {
    pub n: i64,
    pub enc: String,
    pub file_hash: String,
}

pub fn convert_miner_proof(proof: &String) -> (Vec<u8>, Vec<Vec<u8>>, Tag) {
    let proof_byte = base64::decode(proof.clone()).unwrap();
    let miner_proof: MinerProof = serde_json::from_slice(&proof_byte).unwrap();

    //convert sigma
    let mut sigma = base64::decode(miner_proof.sigma.as_str()).unwrap();

    //convert miu
    let mut miu = Vec::new();
    for item in miner_proof.miu {
        let mut i = base64::decode(item.as_str()).unwrap();
        miu.push(i);
    }
    //convert tag
    let mut tag = Tag::new();
    tag.t.n = miner_proof.tag.t.n;
    tag.t.enc = base64::decode(miner_proof.tag.t.enc.as_str()).unwrap();
    tag.t.file_hash = base64::decode(miner_proof.tag.t.file_hash.as_str()).unwrap();
    tag.mac_t0 = base64::decode(miner_proof.tag.mac_t0.as_str()).unwrap();

    (sigma, miu, tag)
}
