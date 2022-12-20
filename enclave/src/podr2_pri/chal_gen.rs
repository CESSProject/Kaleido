use super::{ProofIdentifier, QElement, PROOF_TIMER_LIST};
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use std::{collections::HashMap, time::SystemTime};

#[derive( Serialize, Deserialize)]
pub struct PoDR2Chal {
    pub q_elements: Vec<QElement>,
    pub time_out: u64,
}

pub fn chal_gen(n: i64, proof_id: &Vec<u8>) -> PoDR2Chal {
    let mut q_elements: Vec<QElement> = vec![];
    if n == 0 {
        return PoDR2Chal {
            q_elements,
            time_out: 0,
        };
    }

    let mut rng = thread_rng();

    let range = (n as f64 * 4.6) / 100_f64;

    let mut low = range.floor();
    let mut high = range.ceil();

    if low < 1_f64 {
        low = 1_f64;
    }
    if high < 1_f64 {
        high = 1_f64;
    }

    let between = Range::new(low, high + 1_f64);
    let n_samples = between.ind_sample(&mut rng) as usize;

    // Choose random blocks
    let mut n_blocks = sgx_rand::sample(&mut rng, 0..n, n_samples);
    n_blocks.sort();

    for i in 0..n_samples {
        let mut rng = thread_rng();
        let v_between = Range::new(0_i64, i64::MAX);
        let v = v_between.ind_sample(&mut rng);
        q_elements.push(QElement { i: n_blocks[i], v });
    }

    let mut proof_timer_list = PROOF_TIMER_LIST.lock().unwrap();
    let time_out = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    };
    debug!("1970-01-01 00:00:00 UTC was {} seconds ago!", time_out);

    let proof_id = ProofIdentifier {
        id: proof_id.to_vec(),
        time_out: time_out + (10_u64 * 60_u64),
    };

    if !proof_timer_list.identifiers.contains(&proof_id) {
        proof_timer_list.identifiers.push(proof_id);
    }

    PoDR2Chal {
        q_elements,
        time_out,
    }
}
