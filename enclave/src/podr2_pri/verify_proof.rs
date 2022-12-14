use alloc::string::ToString;
use alloc::vec::Vec;
use param::podr2_commit_data::PoDR2Error;
use podr2_pri::EncEncrypt;
use podr2_pri::key_gen::{MacHash, Symmetric};
use num::traits::{Zero, One};
use num_bigint::{BigInt,ToBigInt,Sign};

use super::ProofTimer;

pub fn verify_proof<T>(sigma :Vec<u8>,q_slice :Vec<super::QElement>,miu :Vec<Vec<u8>>,tag :super::Tag,ct: T, proof_timer: ProofTimer)->bool
    where T: Symmetric + MacHash
{

    // TODO: Check if the proof provided is within the time frame.
    
    let mut t_serialized_bytes = serde_json::to_vec(&tag.t).unwrap();
    let t0_mac=match ct.mac_encrypt(&t_serialized_bytes) {
        Ok(mac_value) => { mac_value }
        Err(err) => { return false } };
    if t0_mac!=(tag.mac_t0){
        return false
    }
    let enc_json=match ct.symmetric_decrypt(&tag.t.enc,"enc"){
        Ok(result) =>result,
        Err(e)=> return false
    };

    let enc: EncEncrypt = serde_json::from_slice(enc_json.as_slice()).unwrap();
    if enc.prf!=ct.get_prf(){
        return false
    }
    let mut first: BigInt=Zero::zero();
    for q in q_slice{
        let f_kprf=ct.symmetric_encrypt(&q.i.to_ne_bytes(),"prf").unwrap();
        let vi =q.v.to_bigint().unwrap();
        first+=num_bigint::BigInt::from_bytes_le(Sign::Plus,&f_kprf)*vi
    }

    let mut second: BigInt=Zero::zero();
    let mut j =0_usize;
    for m in miu{
        let alpha_j =enc.alpha[j].to_bigint().unwrap();
        let miu_j=num_bigint::BigInt::from_bytes_le(Sign::Plus,&m);
        second+=alpha_j*miu_j;
        j+=1;
    }
    println!("first add second {:?}",(first.clone()+second.clone()).to_string());
    println!("sigma {:?}",num_bigint::BigInt::from_bytes_le(Sign::Plus,&sigma).to_string());
    num_bigint::BigInt::from_bytes_le(Sign::Plus,&sigma)==first+second
}