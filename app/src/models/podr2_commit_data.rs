use std::vec::Vec;
use serde::{Serialize, Deserialize};

//filetag struct
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="PascalCase")]
pub struct FileTagT {
    pub t0: T0,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="PascalCase")]
pub struct T0 {
    pub name: Vec<u8>,
    pub n:    usize,
    pub u:    Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2CommitData {
    pub t:FileTagT,
    pub sigmas:Vec<Vec<u8>>,
    pub pkey: Vec<u8>,
    pub callback_url: String,
}