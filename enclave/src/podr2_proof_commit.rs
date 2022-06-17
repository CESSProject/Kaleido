use alloc::vec::Vec;
use cess_bncurve::*;
use core::convert::TryInto;
use crypto::digest::Digest;
use merkletree::merkle::MerkleTree;
use param::*;
use pbc;
use serde::{Deserialize, Serialize};
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::uint64_t;
use std::iter::FromIterator;
use std::slice;

use crate::merkletree_generator::Sha256Algorithm;

pub fn podr2_proof_commit(
    skey: cess_bncurve::SecretKey,
    pkey: cess_bncurve::PublicKey,
    data: Vec<u8>,
    block_size: usize,
) -> PoDR2CommitResponse {
    let mut result = PoDR2CommitResponse::new();

    let mut t = FileTagT::new();
    let mut matrix: Vec<Vec<u8>> = Vec::new();
    data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
        matrix.push(chunk.to_vec());
        t.t0.n = i+1;
    });

    //'Choose a random file name name from some sufficiently large domain (e.g., Zp).'
    let zr = cess_bncurve::Zr::random();
    t.t0.name = zr.to_str().into_bytes();

    let mut u_num: usize = block_size;
    if block_size > data.len() {
        u_num = data.len();
    }

    //'Choose s random elements u1,...,us<——R——G'
    for i in 0..u_num as i64 {
        let g1 = pbc::get_random_g1();
        let g1byte = g1.to_str().into_bytes();
        t.t0.u.push(g1byte);
    }

    //the file tag t is t0 together with a signature
    let t_serialized = serde_json::to_string(&t.t0).unwrap();
    let t_serialized_bytes = t_serialized.clone().into_bytes();

    println!("serialized = {:?}", t_serialized_bytes);

    // let mut leaves_hashes = vec![vec![0u8; 32]; matrix.len()];
    let cpy_size = matrix.len();
    for i in 0..cpy_size {
        result
            .sigmas
            .push(generate_authenticator(i, &mut t.t0, &matrix[i], &skey));

        // leaves_hashes.push(rsgx_sha256_slice(&matrix[i]).unwrap().to_vec());
    }

    // // Generate MHT
    // let tree: MerkleTree<[u8; 32], Sha256Algorithm> = MerkleTree::from_data(
    //     leaves_hashes,
    // );
    // let root_hash = Hash::new(&tree.root());
    // let mth_root_sig = cess_bncurve::sign_hash(&root_hash, &skey);
    
    // println!("MHT Root: {:?}", tree.root());
    // println!("MHT Root Sig: {:?}", mth_root_sig.to_str());
    
    let t_signature = hash(&t_serialized_bytes);
    println!("t_signature:{:?}",t_signature.base_vector());
    let sigG1 =cess_bncurve::sign_hash(&t_signature, &skey);
    t.signature = sigG1.clone()
        .to_str()
        .into_bytes();

    let verify=cess_bncurve::check_message(&t_serialized_bytes,&pkey,&sigG1);
    println!("verify signature:{}",verify);
    result.t = t;

    result
}

pub fn generate_authenticator(
    i: usize,
    t0: &mut T0,
    piece: &Vec<u8>,
    alpha: &cess_bncurve::SecretKey,
) -> Vec<u8> {
    //H(name||i)
    let mut name = t0.clone().name;
    let hash_name_i = hash_name_i(&mut name, i);
    println!("hash_name_i = {:?}", hash_name_i.to_str().into_bytes());

    let productory = G1::zero();
    let s = t0.u.len();
    for j in 0..s {
        if j == s - 1 {
            //mij
            let piece_sigle = pbc::get_zr_from_byte(&vec![piece[j..][0]]);
            let g1 = pbc::get_g1_from_byte(&t0.u[j]);
            //uj^mij
            pbc::g1_pow_zn(&g1, &piece_sigle);
            pbc::g1_mul_g1(&productory, &g1);
            continue;
        }
        //mij
        let piece_sigle = pbc::get_zr_from_byte(&vec![piece[j..][0]]);
        let g1 = pbc::get_g1_from_byte(&t0.u[j]);
        //uj^mij
        pbc::g1_pow_zn(&g1, &piece_sigle);
        pbc::g1_mul_g1(&productory, &g1);
    }
    //H(name||i) · uj^mij
    pbc::g1_mul_g1(&productory, &hash_name_i);
    pbc::g1_pow_zn(
        &productory,
        &pbc::get_zr_from_byte(&alpha.to_str().into_bytes()),
    );
    let res = productory.to_str().into_bytes();
    res
}

pub fn hash_name_i(name: &mut Vec<u8>, i: usize) -> G1 {
    name.push(i as u8);
    let hash_array = hash(name.as_slice());
    pbc::get_g1_from_hash(&hash_array)
}
