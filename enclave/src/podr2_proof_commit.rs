use crate::param::*;
use crate::pbc;


use alloc::vec::Vec;
use cess_bncurve::*;
use core::convert::TryInto;
use crypto::digest::Digest;
use merkletree::merkle::MerkleTree;
// use param::*;
use serde::{Deserialize, Serialize};
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::uint64_t;
use std::iter::FromIterator;
use std::slice;

use crate::merkletree_generator::Sha256Algorithm;
use crate::param::podr2_commit_data::*;

pub fn podr2_proof_commit(
    skey: cess_bncurve::SecretKey,
    pkey: cess_bncurve::PublicKey,
    data: &mut Vec<u8>,
    block_size: usize,
    segment_size: usize,
) -> PoDR2CommitData {
    let mut result = PoDR2CommitData::new();

    let mut t = FileTagT::new();
    // let mut matrix: Vec<Vec<u8>> = Vec::new();
    //Add zeros after the excess file
    let mut extra_len =data.len() as isize %block_size as isize;
    if extra_len>0{
        let zero_pad_len=block_size as isize - extra_len;
        info!("zero_pad_len:{},data length {}",zero_pad_len,data.len());
        let append_data =&mut vec![0u8; zero_pad_len as usize];
        info!("append data length {}",append_data.len());
        data[data.len()-2..].append(append_data);
        info!("data length after append1:{}",data.len());
    }
    // data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
    //     matrix.push(chunk.to_vec());
    // });
    t.t0.n = data.len()/block_size;

    //'Choose a random file name name from some sufficiently large domain (e.g., Zp).'
    let zr = cess_bncurve::Zr::random();
    t.t0.name = zr.base_vector().to_vec();
    let mut s: usize = block_size;
    if block_size > data.len() {
        s = data.len();
    }
    let mut u_num: usize = 0;
    u_num = s / segment_size;
    if s % segment_size != 0 {
        u_num = u_num + 1
    }
    let g1 = pbc::get_random_g1();
    //'Choose s random elements u1,...,us<——R——G'
    for i in 0..u_num as i64 {
        let zr_rand = Zr::random();
        pbc::g1_pow_zn(&g1, &zr_rand);
        let g1byte = g1.base_vector().to_vec();
        t.t0.u.push(g1byte);
    }
    //the file tag t is t0 together with a signature
    let t_serialized = serde_json::to_string(&t.t0).unwrap();
    let t_serialized_bytes = t_serialized.clone().into_bytes();

    // Stores MHT leaves.
    // let mut leaves_hashes = vec![vec![0u8; 32]; t.t0.n];
    for i in 0..t.t0.n {
        result.sigmas.push(generate_authenticator(
            i,
            u_num,
            &mut t.t0,
            &data[i*block_size..(i+1)*block_size].to_vec(),
            &skey,
            segment_size,
        ));

        // leaves_hashes.push(rsgx_sha256_slice(&matrix[i]).unwrap().to_vec());
    }

    // Generate MHT
    // let tree: MerkleTree<[u8; 32], Sha256Algorithm> = MerkleTree::from_data(
    //     leaves_hashes,
    // );
    // let root_hash = Hash::new(&tree.root());
    // let mth_root_sig = cess_bncurve::sign_hash(&root_hash, &skey);

    // println!("MHT Root: {:?}", tree.root());
    // println!("MHT Root Sig: {:?}", mth_root_sig.to_str());

    let t_signature = hash(&t_serialized_bytes);
    let sig_g1 = cess_bncurve::sign_hash(&t_signature, &skey);
    t.signature = sig_g1.clone().base_vector().to_vec();

    let verify = cess_bncurve::check_message(&t_serialized_bytes, &pkey, &sig_g1);
    result.t = t;
    result.pkey = pkey.base_vector().to_vec();
    result
}

pub fn generate_authenticator(
    i: usize,
    u_num: usize,
    t0: &mut T0,
    piece: &Vec<u8>,
    alpha: &cess_bncurve::SecretKey,
    segment_size: usize,
) -> Vec<u8> {
    //H(name||i)
    let mut name = t0.clone().name;
    let hash_name_i = hash_name_i(&mut name, i + 1);
    let productory = G1::zero();
    // let mut u_num: usize = 0;
    // u_num = s / segment_size;
    // if s % segment_size != 0 {
    //     u_num = u_num + 1
    // }
    for j in 0..u_num {
        if j == u_num - 1 {
            //mij
            let piece_sigle = pbc::get_zr_from_hash(&piece[j * segment_size..piece.len()].to_vec());
            let g1 = pbc::get_g1_from_byte(&t0.u[j]);
            //uj^mij
            pbc::g1_pow_zn(&g1, &piece_sigle);
            pbc::g1_mul_g1(&productory, &g1);
            continue;
        }
        //mij
        let piece_sigle =
            pbc::get_zr_from_hash(&piece[j * segment_size..(j + 1) * segment_size].to_vec());
        // println!("index:{},piece_sigle:{:?},piece:{:?}",j,piece_sigle.base_vector().to_vec(),vec![piece[j]]);
        let g1 = pbc::get_g1_from_byte(&t0.u[j]);
        // println!("index:{},get_g1_from_byte:{:?}",j,g1.clone().base_vector().to_vec());
        //uj^mij
        pbc::g1_pow_zn(&g1, &piece_sigle);
        // println!("index:{},g1_pow_zn:{:?}",j,g1.clone().base_vector().to_vec());
        pbc::g1_mul_g1(&productory, &g1);
        // println!("index:{},g1_mul_g1:{:?}",j,productory.clone().base_vector().to_vec());
    }
    //H(name||i) · uj^mij
    // println!("productory value1:{:?}",productory.base_vector().to_vec());
    pbc::g1_mul_g1(&productory, &hash_name_i);
    // println!("productory value2:{:?}",productory.base_vector().to_vec());
    pbc::g1_pow_zn(
        &productory,
        &pbc::get_zr_from_byte(&alpha.base_vector().to_vec()),
    );
    let res = productory.base_vector().to_vec();
    res
}

// Append i to the name and compute hash
pub fn hash_name_i(name: &mut Vec<u8>, i: usize) -> G1 {
    name.push(i as u8);
    let hash_array = hash(name.as_slice());
    pbc::get_g1_from_hash(&hash_array)
}
