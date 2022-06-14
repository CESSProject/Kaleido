use alloc::vec::Vec;
use cess_bncurve::*;
use param::*;
use pbc;
use serde::{Deserialize, Serialize};
use std::slice;

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
        t.t0.n = i;
    });

    //'Choose a random file name from some sufficiently large domain (e.g., Zp).'
    let zr = cess_bncurve::Zr::random();
    t.t0.name = zr.to_str().into_bytes();

    //'Choose s random elements u1,...,us<——R——G'
    for i in 0..block_size as i64 {
        let g1: G1 = pbc::get_random_g1();
        t.t0.u.push(g1.to_str().into_bytes());
    }

    //the file tag t is t0 together with a signature
    let t_serialized = serde_json::to_string(&t).unwrap();
    let t_serialized_bytes = t_serialized.into_bytes();
    
    println!("serialized = {:?}", t_serialized_bytes);
    
    let ref_size: &usize = &t.t0.n;
    let cpy_size = *ref_size;
    for i in 0..cpy_size {
        result
            .sigmas
            .push(generate_authenticator(i, &(&t.t0), &matrix[i]));
    }
    
    let t_signature = hash(&t_serialized_bytes);
    t.signature = cess_bncurve::sign_hash(&t_signature, &skey)
        .to_str()
        .into_bytes();
    result.t = t;

    result
}

pub fn generate_authenticator(i: usize, t0: &T0, piece: &Vec<u8>) -> Vec<u8> {
    //H(name||i)

    Vec::new()
}

pub fn hash_name_i() -> G1 {
    G1::zero()
}
