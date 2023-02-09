use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize}; 

pub mod key_gen;
pub mod sig_gen;
pub mod chal_gen;
pub mod gen_proof;
pub mod verify_proof;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct T {
    pub tag: Tag,
    pub sig_above: String,
}
impl T {
    pub fn new() -> T {
        T {
            tag: Tag::new(),
            sig_above: "".to_string()
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct Tag {
    pub name: String,
    pub n: i64,
    pub u: String,
}

impl Tag {
    pub fn new() -> Tag {
        Tag {
            name: "".to_string(),
            n: 0,
            u: "".to_string()
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct Spk{
    pub E :String,
    pub N :String
}

impl Spk {
    pub fn new() -> Spk {
        Spk {
            E: "".to_string(),
            N: "".to_string()
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone)]
pub struct SigGenResponse {
    pub t:T,
    pub phi:Vec<String>,
    pub sig_root_hash:String,
    pub spk:Spk
}

impl SigGenResponse {
    pub fn new() -> SigGenResponse {
        SigGenResponse {
            t: T::new(),
            phi: vec![],
            sig_root_hash: "".to_string(),
            spk: Spk::new()
        }
    }
}