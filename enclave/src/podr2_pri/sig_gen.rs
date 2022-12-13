use alloc::string::ToString;
use alloc::vec::Vec;
use core::any::Any;
use core::ops::{Add, Mul};
// use libc::rand;
use podr2_pri::key_gen::{MacHash, Symmetric};
use num::bigint::BigUint;
use num::ToPrimitive;
use num::traits::{Zero, One};
use num_bigint::{BigInt,ToBigInt,Sign};
use sgx_rand::Rng;
use podr2_pri::{EncEncrypt, Tag, Tag0};

// pub fn notify(matrix: &Vec<Vec<u8>>, et: &EncryptionType) {
//     println!("Breaking news! {}", item.summarize());
// }

pub fn sig_gen<T>(matrix:Vec<Vec<u8>>, ct: T) -> (Vec<Vec<u8>>, Tag)
    where T: Symmetric + MacHash
{

    let mut alphas:Vec<i128> =vec![];
    // let mut alpha_big :Vec<BigInt>=Default::default();
    let mut alpha_big :Vec<BigInt>=vec![];

    for item in matrix[0].iter(){
        let mut rng_128 = sgx_rand::random::<i128>();
        // let mut rng_128 = 100_i128;
        alphas.push(rng_128);
        alpha_big.push(rng_128.to_bigint().unwrap());
    }

    let mut tag =Tag::new();
    let mut t0=Tag0::new();
    let mut enc =EncEncrypt::new();
    enc.prf=ct.get_prf();
    enc.alpha=alphas;
    let mut enc_serialized = serde_json::to_string(&enc).unwrap();
    let mut enc_serialized_bytes = enc_serialized.clone().into_bytes();

    //t0 be n||Enckencc(kprf||α1||···||αs)
    t0.n= matrix.len() as i64;
    t0.enc=ct.symmetric_encrypt(&enc_serialized_bytes,"enc").unwrap();
    let mut t0_serialized_bytes = serde_json::to_vec(&t0).unwrap();
    // let mut t0_serialized_bytes = t0_serialized.clone().into_bytes();

    tag.t=t0;
    tag.mac_t0=ct.mac_encrypt(&t0_serialized_bytes).unwrap();

    let mut sigmas:Vec<Vec<u8>>=vec![vec![];matrix.len()];
    let mut i =0_usize;
    for item in matrix{
        let f_kprf=ct.symmetric_encrypt(&i.to_ne_bytes(),"prf").unwrap();
        let mut sum=0.to_bigint().unwrap();
        let mut j=0_usize;
        for per in item{
            let tmp=(alpha_big[j].clone()) * ((per as i64).to_bigint().unwrap());
            // let sum_b=sum.clone();
            sum+=tmp;
            j+=1;
        }
        sigmas[i]=(num_bigint::BigInt::from_bytes_le(Sign::Plus,&f_kprf)+sum).to_bytes_le().1;
        i+=1;
    }
    (sigmas, tag)
}