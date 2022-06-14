use alloc::vec::Vec;
use cess_bncurve::*;
use param::*;
use pbc;
use serde::{Deserialize, Serialize};
use sgx_types::uint64_t;
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

    //'Choose a random file name name from some sufficiently large domain (e.g., Zp).'
    let zr = cess_bncurve::Zr::random();
    t.t0.name = zr.to_str().into_bytes();
    println!("t0.name is {:?}", t.t0.name);

    let mut u_num: usize = 0;
    if block_size > data.len() {
        u_num = data.len();
    } else {
        u_num = block_size;
    }

    println!("n G1 {}", u_num);
    //'Choose s random elements u1,...,us<——R——G'
    for i in 0..u_num as i64 {
        let g1 = pbc::get_random_g1();
        let g1byte = g1.to_str().into_bytes();
        println!("{} {}", i, g1.to_str());
        t.t0.u.push(g1byte);
    }
    println!("end create G1");

    //the file tag t is t0 together with a signature
    let t_serialized = serde_json::to_string(&t).unwrap();
    let t_serialized_bytes = t_serialized.into_bytes();

    println!("serialized = {:?}", t_serialized_bytes);

    let ref_size: &usize = &t.t0.n;
    let cpy_size = *ref_size;
    println!("start to generate_authenticator");
    println!("cpy_size = {}", cpy_size);
    for i in 0..cpy_size {
        result
            .sigmas
            .push(generate_authenticator(i, &mut t.t0, &matrix[i], &skey));
    }

    let t_signature = hash(&t_serialized_bytes);
    t.signature = cess_bncurve::sign_hash(&t_signature, &skey)
        .to_str()
        .into_bytes();
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
    println!("start hash_name_i");
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
        println!("piece_sigle = {:?}", piece_sigle.to_str().into_bytes());
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
    println!("authenticator = {:?}", res);
    res
}

pub fn hash_name_i(name: &mut Vec<u8>, i: usize) -> G1 {
    name.push(i as u8);
    let hash_array = hash(name.as_slice());
    pbc::get_g1_from_hash(&hash_array)
}
