use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::Mul;
use num::{One,Zero};
use num_bigint::{BigInt, ToBigInt, Sign};
use sgx_rand::Rng;
use rand::rngs::OsRng;
use podr2_v2_pub_rsa::{SigGenResponse, T};
use rsa::{PublicKey,RSAPrivateKey, PaddingScheme};
use hex;
use utils;
use rand;

use super::Tag;
use crate::{
    param::podr2_commit_data::{PoDR2Error},
    keys::Keys,
};

pub fn sig_gen(data: &mut Vec<u8>,
               n_blocks: usize
) -> Result<SigGenResponse, PoDR2Error> {
    let rsa_keys =crate::KEYS.lock().unwrap().rsa_keys.clone();
    let mut result =SigGenResponse::new();
    let mut t =T::new();
    let mut tag =Tag::new();
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;
    debug!(
        "NBlocks: {}, Block Size: {:?}, Total Data Size: {:?}",
        n_blocks,
        block_size,
        data.len()
    );

    let mut u = sgx_rand::random::<i64>().to_bigint().unwrap();
    let mut name = vec![0u8;512];
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut name);
    tag.n=n_blocks as i64;
    tag.u= base64::encode(u.clone().to_bytes_be().1);
    tag.name=base64::encode(name);

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
    let mut rng = OsRng;
    let enc_data = match rsa_keys.skey.encrypt(&mut rng, PaddingScheme::PKCS1v15, &t_hash){
        Ok(data) =>data,
        Err(e)=>{
            return Err(PoDR2Error {
                message: Some(format!("{:?}",e)),
            })
        }
    };
    t.tag=tag;
    t.sig_above=hex::encode_hex(&enc_data);


    //Generate MHT root
    let root_hash=match utils::mht::get_mht_root(data, n_blocks){
        Ok(hash)=>hash,
        Err(e)=>
            return Err(PoDR2Error {
                message: Some(format!("{}", e.message.unwrap())),
            })
    };
    result.sig_root_hash=hex::encode_hex(&root_hash);
    result.t=t;

    for i in 0..n_blocks{
        if i==n_blocks-1{
            result.phi.push(generate_sigma(rsa_keys.skey.clone(),data[i*block_size..].to_vec(),u.clone()))
        }else {
            result.phi.push(generate_sigma(rsa_keys.skey.clone(),data[i*block_size..(i+1)*block_size].to_vec(),u.clone()))
        }
    }

    Ok(result)
}

pub fn generate_sigma(
    ssk:RSAPrivateKey,
    data:Vec<u8>,
    u_bigint:BigInt,
)->String {
    let d_bytes=ssk.clone().d().to_bytes_be();
    let n_bytes=ssk.clone().n().to_bytes_be();
    let d=num_bigint::BigInt::from_bytes_be(Sign::Plus,&d_bytes);
    let n=num_bigint::BigInt::from_bytes_be(Sign::Plus,&n_bytes);

    let data_hash = sgx_tcrypto::rsgx_sha256_slice(&data).unwrap();
    let mut data_bigint=num_bigint::BigInt::from_bytes_be(Sign::Plus,&data);
    let mut data_hash_bigint=num_bigint::BigInt::from_bytes_be(Sign::Plus,&data_hash);

    //(H(mi) · u^mi )^α
    println!("{}",data_bigint);
    println!("{}",u_bigint);
    let umi=u_bigint.modpow(&data_bigint, &n.clone());
    println!("{}",umi);

    let summary=data_hash_bigint * umi;
    let mut productory=summary.modpow(&d,&n);

    productory.to_string()
}