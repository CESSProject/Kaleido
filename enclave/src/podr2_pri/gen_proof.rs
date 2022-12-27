use alloc::string::ToString;
use alloc::vec::Vec;
use num::bigint::BigUint;
use num::ToPrimitive;
use num::traits::{Zero, One};
use num_bigint::{BigInt,ToBigInt,Sign};
use podr2_pri::QElement;

pub fn gen_proof(sigmas:Vec<Vec<u8>>,q_slice:Vec<super::QElement>,matrix:Vec<Vec<u8>>)
    ->(Vec<u8>,Vec<Vec<u8>>)
{
    let mut miu =vec![vec![0u8]; matrix[0].len()];
    let mut j=0_usize;
    for m in miu.clone(){
        let mut sum: BigInt=Zero::zero();
        for q in &q_slice{
            let mij=(matrix[q.i as usize][j] as i64).to_bigint().unwrap();
            let vi=q.v.to_bigint().unwrap();
            // let sum_b=sum.clone();
            sum+=vi*mij;
        }
        miu[j]=sum.to_bytes_be().1;
        j+=1;
    };
    let mut sigma: BigInt=Zero::zero();
    for q in &q_slice{
        let sigma_i=num_bigint::BigInt::from_bytes_be(Sign::Plus,&sigmas[q.i as usize]);
        let vi=q.v.to_bigint().unwrap();
        sigma+=sigma_i*vi;
    };

    return (sigma.to_bytes_be().1,miu)

}