use alloc::string::ToString;
use alloc::vec::Vec;
use param::podr2_commit_data::PoDR2Error;
use podr2_pri::EncEncrypt;
use podr2_pri::key_gen::{MacHash, Symmetric};
use num::traits::{Zero, One};
use num_bigint::{BigInt,ToBigInt,Sign};
use core::ops::Index;
use std::time::SystemTime;

use crate::podr2_pri::PROOF_TIMER_LIST;
use sgx_types::*;

use super::ProofTimer;

pub fn verify_proof<T>(sigma :Vec<u8>,q_slice :Vec<super::QElement>,miu :Vec<Vec<u8>>,tag :super::Tag,ct: T, proof_timer: &ProofTimer)->bool
    where T: Symmetric + MacHash
{

    let mut proof_timer_list = PROOF_TIMER_LIST.lock().unwrap();
    if !proof_timer_list.timers.contains(&proof_timer) {
        warn!("Invalid ProofTimer! Does not exist.");
        return false;
    }


    // TODO: Get trusted time instead of system time.
    let t = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => {
            warn!("SystemTime before UNIX EPOCH!");
            return false;
        },
    };

    // Time of submission of proof should be lower than the given time frame.
    if proof_timer.time < t {
        warn!("Stale Proof! Proof invalid.");
        return false;
    }

    // proof_timer_list.timers.index(index)
    // Element will exist because we check above it the proof_timer is contained in the list.
    let index = proof_timer_list.timers.iter().position(|x| *x == *proof_timer).unwrap();
    debug!("Removing ProofTimer at index: {}", index);
    proof_timer_list.timers.remove(index);
    info!("Valid ProofTimer");
    
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