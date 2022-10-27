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

    podr2_data.phi = gen_phi(skey, pkey, data, n_blocks)?;
    podr2_data.mht_root_sig = get_mht_root_sig(skey, data, n_blocks)?;

    println!("-------------------PoDR2 Data-------------------");
    for i in 0..podr2_data.phi.len() {
        println!("Sig {}, {:?}", i, base64::encode(&podr2_data.phi[i]));
    }
    println!(
        "MHT Root Sig: {:?}",
        base64::encode(&podr2_data.mht_root_sig)
    );
    println!("-------------------PoDR2 Data-------------------");

    // println!("-------------------PoDR2 Challenge-------------------");
    // let chal = proof::gen_chal(podr2_data.phi.len());
    // println!("Chal i: {:?}", chal.i);
    // println!("Chal V - {}", chal.vi.len());
    // for i in 0..chal.vi.len() {
    //     println!("{}: {:?}", i, base64::encode(&chal.vi[i]));
    // }
    // println!("-------------------PoDR2 Challenge-------------------");

    // println!("-------------------PoDR2 Gen Proof-------------------");
    // // proof::gen_proof(chal, data, podr2_data.phi.len());
    // println!("-------------------PoDR2 Gen Proof-------------------");

    Ok(podr2_data)
}

fn get_mht_root_sig(
    skey: cess_curve::SecretKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<Vec<u8>, PoDR2Error> {
    // Stores MHT leaves.
    let leaves_hashes = get_mht_leaves_hashes(data, n_blocks)?;

    // Generate MHT
    let tree: MerkleTree<[u8; 32], Sha256Algorithm> = MerkleTree::from_data(leaves_hashes);
    let root_hash = Hash::new(&tree.root());

    // (H(R))^sk
    Ok(cess_curve::sign_hash(&root_hash, &skey)
        .base_vector()
        .to_vec())
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

// Generates phi Φ = {σi}, 1 < i < n.
fn gen_phi(
    skey: cess_curve::SecretKey,
    pkey: cess_curve::PublicKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<Vec<Vec<u8>>, PoDR2Error> {
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;

    debug!("Data: {:?}", data);
    debug!(
        "NBlocks: {}, Block Size: {:?}, Total Data Size: {:?}",
        n_blocks,
        block_size,
        data.len()
    );

    // Choose a random element u <- G
    let g1: cess_curve::G1 = pbc::get_random_g1();

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
        let u_pow_mi = pbc::g1_pow_mpz(&g1, bmi.to_string());
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
        let h_u_pow_mi = pbc::g1_mul_mpz(&g1, bhash.to_string());
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
    Ok(sigmas)
}
