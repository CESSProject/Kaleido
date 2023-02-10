use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::ops::{Deref, Mul};
use hex;
use num::{One, Zero};
use num_bigint::{BigInt, Sign, ToBigInt};
use podr2_v2_pub_rsa::{SigGenResponse, T};
use rand;
use rand::rngs::OsRng;
use rsa::hash::Hashes;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use sgx_rand::Rng;
use std::thread;
use utils;
use std::sync::SgxMutex;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;

use super::Tag;
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

    let mut u = sgx_rand::random::<i64>().to_bigint().unwrap();
    let mut name = vec![0u8; 512];
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut name);
    tag.n = n_blocks as i64;
    tag.u = base64::encode(u.clone().to_bytes_be().1);
    tag.name = base64::encode(name);

    let tag_serialized = serde_json::to_string(&tag).unwrap();
    let t_serialized_bytes = tag_serialized.clone().into_bytes();

    let mut t_hash = match sgx_tcrypto::rsgx_sha256_slice(&t_serialized_bytes) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(PoDR2Error {
                message: Some(format!("{}", e.to_string())),
            })
        }
    };

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
    t.tag = tag;
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
    let N =rsa_keys.clone().pkey.n().to_string();
    let E=rsa_keys.clone().pkey.e().to_string();

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let response = Arc::new(SgxMutex::new(SigGenResponse::new()));
    let result_tmp =Arc::clone(&response);
    let handle_tmp = thread::spawn(move || {
        let mut result=result_tmp.lock().unwrap();
        result.sig_root_hash = utils::convert::u8v_to_hexstr(&root_hash);
        result.t = t;
        result.spk.N = N;
        result.spk.E = E;
        result.phi = vec![String::new(); n_blocks];
    });
    handles.push(handle_tmp);
    for thread in handles.into_iter() {
        thread.join().unwrap();
    }

    let pool = ThreadPool::new(utils::thread_controller::MAX_THREAD);
    let (tx, rx) = channel();
    for i in 0..n_blocks {

        //get piece duplicate
        let mut piece = vec![];
        if i == n_blocks - 1 {
            piece = data[i * block_size..].to_vec().clone();
        } else {
            piece = data[i * block_size..(i + 1) * block_size].to_vec();
        }

        //get ssk
        let skey = rsa_keys.skey.clone();

        //get u duplicate
        let u_copy = u.clone();

        let tx = tx.clone();
        let result_tmp = Arc::clone(&response);
        pool.execute(move|| {
            dbg!(i);
            let mut data="".to_string();
            if i == n_blocks - 1 {
                data=generate_sigma(skey, piece, u_copy)
            } else {
                data=generate_sigma(skey, piece, u_copy)
            }
            let mut result = match result_tmp.lock(){
                Ok(r)=>r,
                Err(e)=>panic!("{:?}",e.to_string())
            };
            result.phi[i]=data;
            tx.send(1).unwrap();
        });
    }
    pool.join();

    let res =Arc::clone(&response);
    let result=res.lock().unwrap();
    Ok(result.clone())
}

pub fn generate_sigma(ssk: RSAPrivateKey, data: Vec<u8>, u_bigint: BigInt) -> String {
    let d_bytes = ssk.clone().d().to_bytes_be();
    let n_bytes = ssk.clone().n().to_bytes_be();
    let d = num_bigint::BigInt::from_bytes_be(Sign::Plus, &d_bytes);
    let n = num_bigint::BigInt::from_bytes_be(Sign::Plus, &n_bytes);

    let data_hash = sgx_tcrypto::rsgx_sha256_slice(&data).unwrap();
    let mut data_bigint = num_bigint::BigInt::from_bytes_be(Sign::Plus, &data);
    let mut data_hash_bigint = num_bigint::BigInt::from_bytes_be(Sign::Plus, &data_hash);

    //(H(mi) · u^mi )^α
    let umi = u_bigint.modpow(&data_bigint, &n.clone());

    let summary = data_hash_bigint * umi;
    let mut productory = summary.modpow(&d, &n);

    productory.to_string()
}
