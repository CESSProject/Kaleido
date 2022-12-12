use alloc::vec::Vec;
use core::ops::Add;
// use libc::rand;
use podr2_pri::key_gen::{MacHash, Symmetric,EncryptionType};
use num::bigint::BigUint;
use num::ToPrimitive;
use num::traits::{Zero, One};
use num_bigint::{BigInt};
use sgx_rand::Rng;
use podr2_pri::{EncEncrypt, Tag, Tag0};

// pub fn notify(matrix: &Vec<Vec<u8>>, et: &EncryptionType) {
//     println!("Breaking news! {}", item.summarize());
// }

pub fn sig_gen<T>(matrix:Vec<Vec<u8>>,ct: T)
    where T: Symmetric + MacHash
{
    let s=matrix[0].len();
    let mut alphas =vec![0i128];
    let mut alphas_big :Vec<BigInt>=Default::default();
    let mut f0: BigInt = Zero::zero();
    let mut f1: BigInt = One::one();
    for item in matrix.iter(){

        // let mut rng = sgx_rand::SgxRng::new().unwrap();
        // let alpha=rng.gen_bigint(1000);
        // alphas.push(alpha.to_i128().unwrap());
        // alphas_big.push(alpha);
    }

    let mut tag =Tag::new();
    let mut t0=Tag0::new();
    let mut enc =EncEncrypt::new();

    enc.alpha=alphas;
}