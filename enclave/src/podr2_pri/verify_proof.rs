use alloc::string::ToString;
use alloc::vec::Vec;
use sgx_tcrypto::rsgx_sha256_slice;
use timer::Time;
use core::ops::Index;
use num::ToPrimitive;
use num::traits::{One, Zero};
use num_bigint::{BigInt, Sign, ToBigInt};
use param::podr2_commit_data::PoDR2Error;
use podr2_pri::key_gen::{MacHash, Symmetric};
use podr2_pri::EncEncrypt;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::podr2_pri::chal_gen::Challenge;
use crate::utils::post::post_data;
use sgx_types::*;

use super::CHALLENGE;

pub fn verify_proof<T>(
    sigma: Vec<u8>,
    miu: Vec<Vec<u8>>,
    tag: super::Tag,
    ct: T,
    proof_id: &Vec<u8>,
) -> bool
where
    T: Symmetric + MacHash,
{
    let mut challenge = CHALLENGE.lock().unwrap();

    // TODO: Get trusted time instead of system time.
    let now = Time::now();

    // Time of submission of proof should be lower than the given time frame.
    // If the proof is already submitted to the chain chal_ident_time_out will be set to i64::MIN.
    // Resulting all the proofs submitted after the time expiration to be invalid.
    if challenge.time_out < now.timestamp() {
        warn!("Stale Proof! Proof invalid.");
        return false;
    }

    let q_elements = challenge.q_elements.clone();

    let mut t_serialized_bytes = serde_json::to_vec(&tag.t).unwrap();
    let t0_mac = match ct.mac_encrypt(&t_serialized_bytes) {
        Ok(mac_value) => mac_value,
        Err(err) => return false,
    };
    if t0_mac != (tag.mac_t0) {
        return false;
    }
    let enc_json = match ct.symmetric_decrypt(&tag.t.enc, "enc") {
        Ok(result) => result,
        Err(e) => return false,
    };

    let enc: EncEncrypt = serde_json::from_slice(enc_json.as_slice()).unwrap();
    if enc.prf != ct.get_prf() {
        return false;
    }
    let mut first: BigInt = Zero::zero();
    for q in q_elements {
        let f_kprf = ct.symmetric_encrypt(&q.i.to_ne_bytes(), "prf").unwrap();
        let vi = q.v.to_bigint().unwrap();
        first += num_bigint::BigInt::from_bytes_be(Sign::Plus, f_kprf.as_slice()) * vi
    }

    let mut second: BigInt = Zero::zero();
    let mut j = 0_usize;
    for m in miu {
        let alpha_j = enc.alpha[j].to_bigint().unwrap();
        let miu_j = num_bigint::BigInt::from_bytes_be(Sign::Plus, m.as_slice());
        second += alpha_j * miu_j;
        j += 1;
    }

    let left =num_bigint::BigInt::from_bytes_be(Sign::Plus, sigma.as_slice());
    left == first + second
}
