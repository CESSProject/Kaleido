use core::{
    array::TryFromSliceError,
    convert::TryInto,
    fmt::{self, Error},
};
use std::string::ToString;

use alloc::string::String;
use alloc::vec::Vec;
use cess_curve::{hash, Hash, PublicKey, G1};
use merkletree::proof::Proof;
use serde::{Deserialize, Serialize};

use crate::{merkletree_generator::Sha256Algorithm, pbc};

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
    /// phi Φ = {σi}, 1 < i < n
    /// Where σi <- (H(mi).u^mi)^sk
    pub(crate) phi: Vec<Vec<u8>>,

    /// Merkle tree root signature G1
    pub mht_root_sig: Vec<u8>,

    /// Random eleent u <-- G
    pub u: Vec<u8>,

    // Public Key G2
    pub pkey: Vec<u8>,
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
    /// Rnadom c-elements subset I = {s1, ...., sc} of set [1, n]
    /// Where s1 <= ... <= sc.
    pub i: Vec<usize>,

    /// For each i belongs to I choose a Random Element vi <- Zp
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
    /// μ = ν0.m0 + ν1.m1 ... νi.mi, where s1 <= i <= sc, belongs to Zp
    pub mu: Vec<u8>,

    /// σ = σ0^ν0 . σ1^ν1 ... σi^νi where s1 <= i <= sc, belongs to G
    pub sigma: Vec<u8>,

    /// H(mi) for each given challenged blocks
    pub mi_hashs: Vec<Vec<u8>>,

    /// Partial Merkle Tree {Ωi}s1<=i<=sc,
    /// Which are the node siblings on the path from the leaves {h(H(mi))}s1<=i<=sc
    /// to the root R of the MHT.
    pub omega: Vec<MHTProof>,

    // Signed Merkle tree root G1
    pub mht_root_sig: Vec<u8>,
}

impl PoDR2Proof {
    pub fn new() -> PoDR2Proof {
        PoDR2Proof {
            mu: Vec::new(),
            sigma: Vec::new(),
            mi_hashs: Vec::new(),
            omega: Vec::new(),
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
        for mht_proof in &self.omega {
            println!("Lemma:");
            for node in &mht_proof.lemma {
                println!("{}", base64::encode(&node));
            }
            println!("Path: {:?}", mht_proof.path);
        }
    }

    pub fn get_root(&self) -> Option<&Vec<u8>> {
        let proof = self.omega.first();
        match proof {
            None => return None,
            Some(p) => return p.lemma.last(),
        }
    }

    // Verifies e(σ, g) ?= e(H(m0)^v0.u^μ + H(m1)^v1.u^μ + ... + H(mi)^vi.u^μ, v)
    pub fn validate(&self, chal: &PoDR2Chal, u: &Vec<u8>, pkey: &Vec<u8>) -> bool {
        // H(m0)^v0 * H(m1)^v1 ... H(mi)^vi
        let mut hmi_pow_vi_prod = G1::zero();

        for n in 0..chal.i.len() {
            let i = chal.i[n];

            // Convert Vec<u8> to [u8; 32]
            let mi_hash: Result<[u8; 32], TryFromSliceError> =
                self.mi_hashs[n].as_slice().try_into();
            let mi_hash = match mi_hash {
                Ok(hash) => hash,
                Err(err) => {
                    warn!("Failed to convert mi_hash Vec<u8> to [u8; 32]");
                    return false;
                }
            };

            // H(mi)
            let hmi = pbc::get_g1_from_hash(&Hash::new(&mi_hash));

            // H(mi)^vi
            let hmi_pow_vi = hmi;
            pbc::g1_pow_zn(&hmi_pow_vi, &pbc::get_zr_from_bytes(&chal.vi[n]));

            // H(m0)^v0 * H(m1)^v1 ... H(mi)^vi
            pbc::g1_mul_g1(&hmi_pow_vi_prod, &hmi_pow_vi);
        }
        
        // u^μ
        let u_pow_mu = pbc::get_g1_from_bytes(u);
        pbc::g1_pow_zn(&u_pow_mu, &pbc::get_zr_from_bytes(&self.mu));

        //  (H(m0)^v0 * H(m1)^v1 ... H(mi)^vi) * u^mu
        let product = hmi_pow_vi_prod;
        pbc::g1_mul_g1(&product, &u_pow_mu);

        let res = cess_curve::check_message(
            &product.base_vector(),
            &PublicKey::new(pbc::get_G2_from_bytes(pkey)),
            &pbc::get_g1_from_bytes(&self.sigma),
        );
        println!("check_message {}", res);

        pbc::validate_bilinearity(
            pbc::get_g1_from_bytes(&self.sigma),
            pbc::get_g1(),
            product,
            pbc::get_G2_from_bytes(pkey),
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MHTProof {
    pub lemma: Vec<Vec<u8>>,
    pub path: Vec<bool>,
}

impl MHTProof {
    pub fn new() -> MHTProof {
        MHTProof {
            lemma: Vec::new(),
            path: Vec::new(),
        }
    }
}
