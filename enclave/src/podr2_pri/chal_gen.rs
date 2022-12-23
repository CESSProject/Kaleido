use crate::utils::{
    bloom_filter::{BloomFilter, Hash},
    post::post_data,
    timer::{self, Guard, Time, Timer},
};

use super::{QElement, CHAL_DATA, CHAL_IDENTIFIER};
use alloc::{string::ToString, vec::Vec};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use core::ops::Index;
use serde::{Deserialize, Serialize};
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use std::{
    collections::HashMap,
    sync::{mpsc::channel, SgxMutex},
    thread,
    time::SystemTime,
};

/// Random Challenge for which the miner have to prove data possession.
#[derive(Serialize, Deserialize)]
pub struct PoDR2Chal {
    pub q_elements: Vec<QElement>,
    pub time_out: i64,
}

/// Contains {bloom_filter, failed_file_hashes, proof_id} to be send back to CESS chain
#[derive(Debug, Serialize, Deserialize)]
pub struct ChalData {
    bloom_filter: BloomFilter,
    failed_file_hashes: Vec<Hash>,
    chal_id: Vec<u8>,
}

impl ChalData {
    pub fn new() -> ChalData {
        ChalData {
            bloom_filter: BloomFilter::zero(),
            failed_file_hashes: Vec::new(),
            chal_id: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChalIdentifier {
    /// Unique random value sent by CESS Chain
    pub chal_id: Vec<u8>,

    /// Proof Submission TimeOut in seconds
    pub time_out: i64,

    /// Challenge
    pub q_elements: Vec<QElement>,
}

impl ChalIdentifier {
    pub fn new() -> ChalIdentifier {
        ChalIdentifier {
            chal_id: Vec::new(),
            time_out: 0,
            q_elements: Vec::new(),
        }
    }
}

impl PartialEq for ChalIdentifier {
    fn eq(&self, other: &Self) -> bool {
        // Match only id
        self.chal_id == other.chal_id // && self.time == other.time
    }
}

pub fn chal_gen(n: i64, chal_id: &Vec<u8>) -> PoDR2Chal {
    let mut q_elements: Vec<QElement> = vec![];
    if n == 0 {
        return PoDR2Chal {
            q_elements,
            time_out: 0,
        };
    }

    let mut chal_ident = CHAL_IDENTIFIER.lock().unwrap();
    let mut time_out: i64;

    if chal_ident.chal_id.is_empty() {
        let now = Time::now();
        debug!("New Challenge ID Received At {}: {}!", now, now.timestamp());

        let schedule_time = now + Duration::seconds(10);
        time_out = schedule_time.timestamp();

        chal_ident.chal_id = chal_id.to_vec();
        q_elements = QElement::get_elements(n);
        chal_ident.q_elements = q_elements.clone();
        chal_ident.time_out = schedule_time.timestamp();

        let _ = thread::Builder::new()
            .name(format!(
                "post_challenge_{}",
                base64::encode(chal_id.to_vec())
            ))
            .spawn(move || {
                let (tx, rx) = channel();

                let timer = Timer::new();
                let _guard = timer.schedule_with_date(schedule_time, move || {
                    tx.send(()).unwrap();
                });

                debug!(
                    "Challenge Post Scheduled for {}: {}!",
                    schedule_time, time_out
                );

                rx.recv().unwrap();
                post_chal_data()
            });
    } else {
        time_out = chal_ident.time_out;
        q_elements = chal_ident.q_elements.clone();
    }

    PoDR2Chal {
        q_elements,
        time_out,
    }
}

fn post_chal_data() {
    info!("Submitting Proofs to Chain");
    let mut chal_data = CHAL_DATA.lock().unwrap();

    post_data::<ChalData>(
        "https://webhook.site/78f20830-9832-42c4-bd0f-91e29aeea930".to_string(),
        &chal_data,
    );

    // Clear contents of CHAL_DATA
    chal_data.bloom_filter = BloomFilter::zero();
    chal_data.failed_file_hashes = Vec::new();
    chal_data.chal_id = Vec::new();

    // Clear CHAL_IDENTIFIER as well
    let mut chal_ident = CHAL_IDENTIFIER.lock().unwrap();
    chal_ident.chal_id = Vec::new();
    chal_ident.q_elements = Vec::new();
    chal_ident.time_out = 0;
}
