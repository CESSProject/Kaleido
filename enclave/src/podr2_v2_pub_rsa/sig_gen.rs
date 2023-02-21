use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::ops::{Deref, Mul};
use hex;
use num::{One, Signed, Zero};
use num_bigint::{BigUint, Sign, ToBigInt, ToBigUint};
use podr2_v2_pub_rsa::{SigGenResponse, T};
use rand;
use rand::rngs::OsRng;
use rsa::hash::Hashes;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use sgx_rand::Rng;
use std::sync::mpsc::channel;
use std::sync::SgxMutex;
use std::thread;
use utils;

use super::Tag;
use crate::utils::thread_controller::MAX_THREAD;
use crate::{keys::Keys, param::podr2_commit_data::PoDR2Error};

pub fn sig_gen(data: &mut Vec<u8>, n_blocks: usize) -> Result<SigGenResponse, PoDR2Error> {
    let mut t = T::new();
    let mut tag = Tag::new();
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;
    debug!(
        "NBlocks: {}, Block Size: {:?}, Total Data Size: {:?}",
        n_blocks,
        block_size,
        data.len()
    );

    let mut u = sgx_rand::random::<u64>().to_biguint().unwrap();
    let mut name = vec![0u8; 512];
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut name);
    tag.n = n_blocks as i64;
    tag.u = base64::encode(u.clone().to_bytes_be());
    tag.name = base64::encode(name);
    let tag_serialized = serde_json::to_string(&tag).unwrap();
    let t_serialized_bytes = tag_serialized.clone().into_bytes();
    t.tag = tag;

    let mut t_hash = match sgx_tcrypto::rsgx_sha256_slice(&t_serialized_bytes) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(format!("{}", e.to_string())),
            })
        }
    };

    let (enc_data, n, e, skey) = {
        let rsa_keys = crate::KEYS.lock().unwrap().rsa_keys.clone();
        let enc_data =
            match rsa_keys
                .skey
                .sign(PaddingScheme::PKCS1v15, Some(&Hashes::SHA2_256), &t_hash)
            {
                Ok(data) => data,
                Err(e) => {
                    return Err(PoDR2Error {
                        message: Some(format!("{:?}", e)),
                    })
                }
            };
        (
            enc_data,
            rsa_keys.clone().pkey.n().to_string(),
            rsa_keys.clone().pkey.e().to_string(),
            rsa_keys.skey.clone(),
        )
    };

    t.sig_above = utils::convert::u8v_to_hexstr(&enc_data);

    //Generate MHT root
    let root_hash = match utils::mht::get_mht_root(data, n_blocks) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(format!("{}", e.message.unwrap())),
            })
        }
    };

    let mut response = SigGenResponse::new();
    response.t = t;
    response.sig_root_hash = utils::convert::u8v_to_hexstr(&root_hash);
    response.spk.N = n;
    response.spk.E = e;
    response.phi = vec![String::new(); n_blocks];

    // Spawn Threads in batches
    for i in (0..n_blocks).step_by(MAX_THREAD) {
        let max = if i + MAX_THREAD > n_blocks {
            n_blocks
        } else {
            i + MAX_THREAD
        };

        let (tx, rx) = channel();
        for j in i..max {
            //get piece duplicate
            let mut piece = vec![];
            if j == n_blocks - 1 {
                piece = data[j * block_size..].to_vec().clone();
            } else {
                piece = data[j * block_size..(j + 1) * block_size].to_vec();
            }

            //get u duplicate
            let u_copy = u.clone();

            //get ssk
            let skey = skey.clone();

            let tx = tx.clone();
            thread::Builder::new()
                .name("generate_sigma".to_string())
                .spawn(move || {
                    let mut data = "".to_string();
                    if j == n_blocks - 1 {
                        data = generate_sigma(skey, piece, u_copy)
                    } else {
                        data = generate_sigma(skey, piece, u_copy)
                    }
                    tx.send((data, j)).unwrap();
                })
                .unwrap();
        }
        let iter = rx.iter().take(max - i);
        for k in iter {
            response.phi[k.1] = k.0;
        }
    }
    Ok(response)
}

pub fn generate_sigma(ssk: RSAPrivateKey, data: Vec<u8>, u_bigint: BigUint) -> String {
    let d_bytes = ssk.clone().d().to_bytes_be();
    let n_bytes = ssk.clone().n().to_bytes_be();
    let d = num_bigint::BigUint::from_bytes_be(&d_bytes);
    let n = num_bigint::BigUint::from_bytes_be(&n_bytes);

    let data_hash = sgx_tcrypto::rsgx_sha256_slice(&data).unwrap();
    let mut data_bigint = num_bigint::BigUint::from_bytes_be( &data);
    let mut data_hash_bigint = num_bigint::BigUint::from_bytes_be( &data_hash);

    //(H(mi) · u^mi )^α
    let umi = u_bigint.modpow(&data_bigint, &n);

    let summary = data_hash_bigint * umi;
    let mut productory = summary.modpow(&d, &n);

    productory.to_string()
}
