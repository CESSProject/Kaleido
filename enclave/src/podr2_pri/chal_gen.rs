use super::QElement;
use alloc::vec::Vec;
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use std::collections::HashMap;

pub fn chal_gen(n: i64) -> Vec<QElement> {
    println!("*******************************CHAL*******************************");   
    let mut challenge: Vec<QElement> = vec![];
    if (n == 0) {
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
    println!("N_SAMPLES {}", n_samples);
    // Choose random blocks
    let mut n_blocks = sgx_rand::sample(&mut rng, 0..n, n_samples);
    n_blocks.sort();

    for i in 0..n_samples {
        let mut rng = thread_rng();
        let v_between = Range::new(0_i64, i64::MAX);
        let v = v_between.ind_sample(&mut rng);  
        challenge.push(QElement {
            i: n_blocks[i],
            v
        });
    }

    // let l=(n/100)*46;
    // let blocks =HashMap::new();
    // let chal1 = QElement { i: 0, v: 123 };
    // let chal2 = QElement { i: 1, v: 123 };
    // let chal3 = QElement { i: 2, v: 123 };
    // let chal4 = QElement { i: 3, v: 123 };
    // challenge.push(chal1);
    // challenge.push(chal2);
    // challenge.push(chal3);
    // challenge.push(chal4);

    
    for i in 0..challenge.len() {
        let chal = &challenge[i];
        println!("i {}", chal.i);    
        println!("v {}", chal.v);    
    }
    println!("*******************************CHAL*******************************");   

    challenge
}
