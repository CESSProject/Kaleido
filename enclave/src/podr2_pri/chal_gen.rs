use super::{ProofTimer, QElement, PROOF_TIMER_LIST};
use alloc::vec::Vec;
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use std::collections::HashMap;

pub fn chal_gen(n: i64, proof_timer: ProofTimer) -> Vec<QElement> {
    let mut challenge: Vec<QElement> = vec![];
    if n == 0 {
        return challenge;
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
        challenge.push(QElement { i: n_blocks[i], v });
    }

    let mut proof_timer_list = PROOF_TIMER_LIST.lock().unwrap();
    if !proof_timer_list.timers.contains(&proof_timer) {
        proof_timer_list.timers.push(proof_timer);
    }

    challenge
}
