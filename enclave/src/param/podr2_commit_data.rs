use core::fmt;
use std::string::ToString;

use alloc::string::String;
use alloc::vec::Vec;
use cess_curve::G1;
use serde::{Deserialize, Serialize};

use crate::pbc;

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

#[derive(Debug)]
pub struct PoDR2Error {
    pub message: Option<String>,
}

impl PoDR2Error {
    fn message(&self) -> String {
        match &*self {
            PoDR2Error {
                message: Some(message),
            } => message.clone(),
            PoDR2Error { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for PoDR2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2Data {
    pub(crate) phi: Vec<Vec<u8>>, // phi Φ = {σi}, 1 < i < n
    pub mht_root_sig: Vec<u8>,    // Merkle tree root signature
    pub u: Vec<u8>,               // Random eleent u <-- G
    pub pkey: Vec<u8>,            // Public Key
}

impl PoDR2Data {
    pub fn new() -> PoDR2Data {
        PoDR2Data {
            phi: Vec::new(),
            mht_root_sig: Vec::new(),
            u: Vec::new(),
            pkey: Vec::new(),
        }
    }

    pub fn print(&self) {
        for i in 0..self.phi.len() {
            println!("Sig {}, {:?}", i, base64::encode(&self.phi[i]));
        }
        println!("MHT Root Sig: {:?}", base64::encode(&self.mht_root_sig));
        println!("u: {:?}", base64::encode(&self.u));
        println!("pkey: {:?}", base64::encode(&self.pkey));

    }
    
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2Chal {
    pub i: Vec<usize>,
    pub vi: Vec<Vec<u8>>,
}

impl PoDR2Chal {
    pub fn new() -> PoDR2Chal {
        PoDR2Chal {
            i: Vec::new(),
            vi: Vec::new(),
        }
    }

    pub fn print(&self) {
        println!("Chal i: {:?}", self.i);
        for i in 0..self.vi.len() {
            println!("v{}: {:?}", i, base64::encode(&self.vi[i]));
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PoDR2Proof {
    pub mu: Vec<u8>,    // μ = ν0.m0 + ν1.m1 ... νi.mi, where s1 <= i <= sc, belongs to Zp
    pub sigma: Vec<u8>, // σ = σ0^ν0 . σ1^ν1 ... σi^νi where s1 <= i <= sc, belongs to G
    pub mi_hashs: Vec<Vec<u8>>, // H(mi) for each given challenged blocks
    pub pmt: Vec<Vec<u8>>, // Partial Merkle Tree for each hash in mi_hashes
    pub mht_root_sig: Vec<u8>, // Signed Merkle tree root
}

impl PoDR2Proof {
    pub fn new() -> PoDR2Proof {
        PoDR2Proof {
            mu: Vec::new(),
            sigma: Vec::new(),
            mi_hashs: Vec::new(),
            pmt: Vec::new(),
            mht_root_sig: Vec::new(),
        }
    }

    pub fn print(&self) {
        println!("mu: {}", base64::encode(&self.mu));
        println!("sigma: {}", base64::encode(&self.sigma));

        for hash in &self.mi_hashs {
            println!("mi_hash: {}", base64::encode(&hash));
        }

        println!("MHT Root Signature: {}", base64::encode(&self.mht_root_sig));
        for node in &self.pmt {
            println!("node: {}", base64::encode(&node));
        }
    }

    // Verifies e(σ, g) ?= e(H(m0)^v0.u^μ + H(m1)^v1.u^μ + ... + H(mi)^vi.u^μ, v)
    pub fn validate(&self, chal: &PoDR2Chal, u: &Vec<u8>, pkey: &Vec<u8>) -> bool {
        // H(m0)^v0 * H(m1)^v1 ... H(mi)^vi
        let mut hmi_pow_vi_prod = G1::zero();

        for n in 0..chal.i.len() {
            let i = chal.i[n];

            let mi_hash = self.mi_hashs[n].clone();
            // H(mi)
            let hmi = pbc::get_g1_from_byte(&mi_hash);

            // H(mi)^vi
            pbc::g1_pow_zn(&hmi, &pbc::get_zr_from_byte(&chal.vi[n]));

            if n == 0 {
                hmi_pow_vi_prod = hmi;
            } else {
                pbc::g1_mul_g1(&hmi_pow_vi_prod, &hmi);
            }
        }

        // u^mu
        let u_pow_mu = pbc::get_g1_from_byte(u);
        pbc::g1_pow_zn(&u_pow_mu, &pbc::get_zr_from_byte(&self.mu));

        //  (H(m0)^v0 * H(m1)^v1 ... H(mi)^vi) * u^mu
        let product = hmi_pow_vi_prod.clone();
        pbc::g1_mul_g1(&product, &u_pow_mu);
        
        pbc::validate_bilinearity(
            pbc::get_g1_from_byte(&self.sigma),
            pbc::get_g1(),
            product,
            pbc::get_G2_from_bytes(pkey),
        )
    }
}
