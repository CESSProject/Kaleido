pub mod proof;

use core::convert::TryInto;
use std::io::{Error, Read};
use std::string::ToString;

use alloc::vec::Vec;
use cess_curve::{hash, sign_hash, Hash, Zr, G1};
use merkletree::merkle::MerkleTree;
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_trts::c_str::CString;
use crate::merkletree_generator::Sha256Algorithm;
use crate::param::podr2_commit_data::{PoDR2Chal, PoDR2SigGenData};
use crate::{
    param::podr2_commit_data::{PoDR2CommitData, PoDR2Error},
    pbc,
    attestation::hex,
};

pub fn sig_gen(
    skey: cess_curve::SecretKey,
    pkey: cess_curve::PublicKey,
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<PoDR2SigGenData, PoDR2Error> {
    let mut podr2_data = PoDR2SigGenData::new();

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
        leaves_hashes[i] = hash.to_vec();
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

        // H(mi)
        let hmi = pbc::get_g1_from_hash(&hash(mi.as_slice()));

        // u^mi
        let u_pow_mi = u;
        pbc::g1_pow_zn(&u_pow_mi, &pbc::get_zr_from_bytes(&mi));

        // H(mi).u^mi
        let hmi_mul_u_pow_mi = hmi;
        pbc::g1_mul_g1(&hmi_mul_u_pow_mi, &u_pow_mi);

        // (H(mi).u^mi)^sk
        // Below two lines are equivalent to cess_curve::sign_hash(...)
        // let sig_i = pbc::get_g1_from_hash(&hash(hmi_mul_u_pow_mi.base_vector()));
        // pbc::g1_pow_zn(&sig_i, &pbc::get_zr_from_byte(&skey.base_vector().to_vec()));

        let sig_i = cess_curve::sign_hash(&hash(hmi_mul_u_pow_mi.base_vector()), &skey);

        // let verify = cess_curve::check_message(&hmi_mul_u_pow_mi.base_vector(), &pkey, &sig_i);
        // println!("SIG_{} VALID: {}", i, verify);

        sigmas.push(sig_i.base_vector().to_vec());
    }
    Ok((sigmas, u.base_vector().to_vec()))
}
