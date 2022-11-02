pub mod proof;

use core::convert::TryInto;
use std::io::{Error, Read};
use std::string::ToString;

use alloc::vec::Vec;
use cess_curve::{hash, sign_hash, Hash, Zr, G1};
use merkletree::merkle::MerkleTree;
use num::traits::Pow;
use num_bigint::{BigInt, BigUint};
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_trts::c_str::CString;

use crate::merkletree_generator::Sha256Algorithm;
use crate::param::podr2_commit_data::{PoDR2Chal, PoDR2Data};
use crate::secret_exchange::hex::hex_to_bigint;
use crate::{
    param::podr2_commit_data::{PoDR2CommitData, PoDR2Error},
    pbc,
    secret_exchange::hex,
};

pub fn sig_gen(
    skey: cess_curve::SecretKey,
    pkey: cess_curve::PublicKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<PoDR2Data, PoDR2Error> {
    let mut podr2_data = PoDR2Data::new();

    let (phi, u) = gen_phi(skey, pkey, data, n_blocks)?;
    podr2_data.phi = phi;
    podr2_data.u = u;
    podr2_data.pkey = pkey.base_vector().to_vec();
    podr2_data.mht_root_sig = get_mht_root_sig(skey, pkey, data, n_blocks)?;

    println!("-------------------PoDR2 Data-------------------");
    podr2_data.print();
    println!("-------------------PoDR2 Data-------------------");

    println!("-------------------PoDR2 Challenge-------------------");
    let chal = proof::gen_chal(podr2_data.phi.len());
    chal.print();
    println!("-------------------PoDR2 Challenge-------------------");

    println!("-------------------PoDR2 Gen Proof-------------------");
    let proof = proof::gen_proof(&chal, &podr2_data, data)?;
    proof.print();
    println!("-------------------PoDR2 Gen Proof-------------------");

    println!("-------------------PoDR2 Validate Proof-------------------");
    println!("Valid Proof: {}", proof::verify(&proof, &podr2_data, &chal));
    println!("-------------------PoDR2 Validate Proof-------------------");

    Ok(podr2_data)
}

fn get_mht_root_sig(
    skey: cess_curve::SecretKey,
    pkey: cess_curve::PublicKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<Vec<u8>, PoDR2Error> {
    // Generate MHT
    let tree: MerkleTree<[u8; 32], Sha256Algorithm> = get_mht(data, n_blocks)?;
    
    // hash the root hash again before signing otherwise cess_curve::check_message returns false
    let root_hash = hash(&tree.root().as_slice());

    // (H(R))^sk
    let sig = cess_curve::sign_hash(&root_hash, &skey);

    // let verify = cess_curve::check_message(&tree.root().as_slice(), &pkey, &sig);
    // println!("ROOT SIG VALID: {}", verify);

    Ok(sig.base_vector().to_vec())
}

// Generate MHT
pub fn get_mht(
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<MerkleTree<[u8; 32], Sha256Algorithm>, PoDR2Error> {
    let leaves_hashes = get_mht_leaves_hashes(data, n_blocks)?;
    Ok(MerkleTree::from_data(leaves_hashes))
}

fn get_mht_leaves_hashes(data: &mut Vec<u8>, n_blocks: usize) -> Result<Vec<Vec<u8>>, PoDR2Error> {
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;
    let mut leaves_hashes = vec![vec![0u8; 32]; n_blocks];

    for i in 0..n_blocks {
        let mi: Vec<u8> = if i == n_blocks - 1 {
            data[i * block_size..].to_vec()
        } else {
            data[i * block_size..(i + 1) * block_size].to_vec()
        };

        let hash = rsgx_sha256_slice(&mi);
        let hash = match hash {
            Ok(h) => h,
            Err(e) => {
                return Err(PoDR2Error {
                    message: Some("Sha256 hash failed while generating MTH leaves".to_string()),
                })
            }
        };
        leaves_hashes.push(hash.to_vec());
    }
    Ok(leaves_hashes)
}

// Generates phi Φ = {σi}, 1 < i < n and u <-- G
fn gen_phi(
    skey: cess_curve::SecretKey,
    pkey: cess_curve::PublicKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), PoDR2Error> {
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;

    debug!("Data: {:?}", data);
    debug!(
        "NBlocks: {}, Block Size: {:?}, Total Data Size: {:?}",
        n_blocks,
        block_size,
        data.len()
    );

    // Choose a random element u <- G
    let u: cess_curve::G1 = pbc::get_random_g1();

    let mut sigmas = Vec::new();

    //For each block mi compute signature sig_i
    // sig_i = (H(mi).u^mi)^skey
    for i in 0..n_blocks {
        let mi: Vec<u8> = if i == n_blocks - 1 {
            data[i * block_size..].to_vec()
        } else {
            data[i * block_size..(i + 1) * block_size].to_vec()
        };

        let bmi = hex_to_bigint(&mi);
        let bmi = match bmi {
            Some(d) => d,
            None => {
                return Err(PoDR2Error {
                    message: Some("Converting mi to BigInteger Failed".to_string()),
                })
            }
        };
        // debug!("Block(mi)-{:?}: {}", i, bmi.to_string());

        // u^mi
        let u_pow_mi = pbc::g1_pow_mpz(&u, bmi.to_string());
        // debug!("u_pow_mi: {}", u_pow_mi);

        // H(mi)
        let mi_hash = hash(mi.as_slice());
        let bhash = hex_to_bigint(mi_hash.base_vector());
        let bhash = match bhash {
            Some(d) => d,
            None => {
                return Err(PoDR2Error {
                    message: Some("Converting hash to BigInteger Failed".to_string()),
                })
            }
        };
        // debug!("hash: {}", bhash);

        // H(mi).u^mi
        let h_u_pow_mi = pbc::g1_mul_mpz(&u, bhash.to_string());
        // debug!("h_u_pow_mi: {}", h_u_pow_mi);

        // secret key
        let bskey = hex_to_bigint(skey.base_vector());
        let bskey = match bskey {
            Some(d) => d,
            None => {
                return Err(PoDR2Error {
                    message: Some("Converting skey to BigInteger Failed".to_string()),
                })
            }
        };

        // (H(mi).u^mi)^sk
        // let sig_i = pbc::g1_pow_mpz(&h_u_pow_mi, bskey.to_string());

        let h = hash(&h_u_pow_mi.base_vector());
        let sig_i = cess_curve::sign_hash(&h, &skey);
  
        // debug!("sig: {}", sig_i);
        sigmas.push(sig_i.base_vector().to_vec());
    }
    Ok((sigmas, u.base_vector().to_vec()))
}
