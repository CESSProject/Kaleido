use alloc::string::ToString;
use alloc::vec::Vec;
use core::any::Any;
use core::ops::{Add, Mul};
// use libc::rand;
use podr2_v1_pri::key_gen::{MacHash, Symmetric};
use num::bigint::BigUint;
use num::ToPrimitive;
use num::traits::{Zero, One};
use num_bigint::{BigInt,ToBigInt,Sign};
use sgx_rand::Rng;
use sgx_types::uint8_t;
use podr2_v1_pri::{EncEncrypt, Tag, Tag0};

pub fn sig_gen<T>(file_data: &Vec<u8>,block_size:usize ,n :usize,s :usize,seg :usize,file_hash:Vec<u8>, ct: T) -> (Vec<Vec<u8>>, Tag)
    where T: Symmetric + MacHash
{

    let mut alphas:Vec<i64> =vec![];
    let mut alpha_big :Vec<BigInt>=vec![];
    for item in 0..s{
        let mut rng_64 = sgx_rand::random::<i64>();
        alphas.push(rng_64);
        alpha_big.push(rng_64.to_bigint().unwrap());
    }

    let mut tag =Tag::new();
    let mut t0=Tag0::new();
    let mut enc =EncEncrypt::new();
    enc.prf=ct.get_prf();
    enc.alpha=alphas;
    let mut enc_serialized_bytes = serde_json::to_vec(&enc).unwrap();

    //t0 be n||Enckencc(kprf||α1||···||αs)
    t0.n= n as i64;
    t0.enc=ct.symmetric_encrypt(&enc_serialized_bytes,"enc").unwrap();
    t0.file_hash=file_hash;
    let mut t0_serialized_bytes = serde_json::to_vec(&t0).unwrap();

    tag.t=t0;
    tag.mac_t0=ct.mac_encrypt(&t0_serialized_bytes).unwrap();
    let mut sigmas:Vec<Vec<u8>>=vec![vec![];n];
    // for item in matrix{
    //     let f_kprf=ct.symmetric_encrypt(&i.to_ne_bytes(),"prf").unwrap();
    //     let mut sum=0.to_bigint().unwrap();
    //     let mut j=0_usize;
    //     for per in item{
    //         let tmp=(alpha_big[j].clone()) * ((per as i64).to_bigint().unwrap());
    //         sum+=tmp;
    //         j+=1;
    //     }
    //     sigmas[i]=(num_bigint::BigInt::from_bytes_be(Sign::Plus,&f_kprf)+sum).to_bytes_be().1;
    //     i+=1;
    // }

    let mut i =0_usize;
    for l in 0..n{
        let f_kprf=ct.symmetric_encrypt(&i.to_ne_bytes(),"prf").unwrap();
        let mut sum=0.to_bigint().unwrap();
        // let mut j=0_usize;
        if l == n - 1 {
            let mut last_chunk=file_data.clone()[l * block_size..].to_vec();
            let pad=block_size as i64 -last_chunk.len() as i64;
            if pad>0{
                let pad_data =&mut vec![0u8; pad as usize];
                last_chunk.append(pad_data);
            }
            for j in 0..s{
                // let tmp=(alpha_big[j].clone()) * ((per as i64).to_bigint().unwrap());
                let tmp=(alpha_big[j].clone()) * num_bigint::BigInt::from_bytes_be(Sign::Plus,&last_chunk[j*seg..(j+1)*seg]);
                sum+=tmp;
                // j+=1;
            }
        }else {
            for j in 0..s{
                // let tmp=(alpha_big[j].clone()) * ((per as i64).to_bigint().unwrap());
                let tmp=(alpha_big[j].clone()) * num_bigint::BigInt::from_bytes_be(Sign::Plus,&file_data[l * block_size..(l + 1) * block_size].to_vec()[(j*seg)..(j+1)*seg]);
                sum+=tmp;
                // j+=1;
            }
        }

        sigmas[i]=(num_bigint::BigInt::from_bytes_be(Sign::Plus,&f_kprf)+sum).to_bytes_be().1;
        i+=1;
    }

    println!("The length of sigmas is :{}",sigmas[0].len()*sigmas.len());
    println!("The length of n is :{}",tag.t.n);
    println!("The length of enc is :{}",tag.t.enc.len());
    println!("The length of file_hash is :{}",tag.t.file_hash.len());
    println!("The length of mac_t0 is :{}",tag.mac_t0.len());

    (sigmas, tag)
}