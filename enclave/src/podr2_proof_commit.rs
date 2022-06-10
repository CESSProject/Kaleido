use alloc::vec::Vec;
use param::*;
use std::{slice};
use pbc;
use cess_bncurve::*;
use serde::{Serialize, Deserialize};

pub fn podr2_proof_commit(
    skey:cess_bncurve::SecretKey,
    pkey:cess_bncurve::PublicKey,
    data: Vec<u8>,
    block_size: usize,
) -> PoDR2CommitResponse {
    let mut result =PoDR2CommitResponse::new();

    let mut T =FileTagT::new();
    let mut matrix:Vec<Vec<u8>> = Vec::new();
    data.chunks(block_size).enumerate().for_each(|(i, chunk)| {
        matrix.push(chunk.to_vec());
        &T:T0.n=i as i64;
    });
    //'Choose a random file name name from some sufficiently large domain (e.g., Zp).'
    pbc::init_zr();
    let Zr=pbc::get_zr();
    &T:T0.name=Zr.to_str().into_bytes();
    //'Choose s random elements u1,...,us<——R——G'
    for i in 0..block_size as i64 {
        pbc::init_pairings();
        let G1=pbc::get_g1();
        &T:T0.u.push(G1.to_str().into_bytes());
    }
    //Choose a random file name name from some sufficiently large domain (e.g., Zp).
    pbc::init_zr();
    let Zr=pbc::get_zr();
    &T:T0.name=Zr.to_str().into_bytes();

    //the file tag t is t0 together with a signature
    let t_serialized = serde_json::to_string(&T).unwrap();
    let t_serialized_bytes = t_serialized.into_bytes();
    println!("serialized = {:?}", t_serialized_bytes);
    let t_signature = hash(&t_serialized_bytes);
    &T.signature= &cess_bncurve::sign_hash(&t_signature, &skey).to_str().into_bytes();
    result.t=T;
    for i in 0..&T:T0.n  {
        result.sigmas.push(generate_authenticator(i, &(&T: T0),&matrix[i]));
    }

    result
}

pub fn generate_authenticator(i:i64,
                              t0:&T0,
                              piece:&Vec<u8>) -> Vec<u8> {
    //H(name||i)


    Vec::new()
}

pub fn hash_name_i()->G1{
    G1::zero()
}