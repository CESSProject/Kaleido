use crate::{
    param::podr2_commit_data::PoDR2Error,
    utils::{
        bloom_filter::{BloomFilter, Hash},
        post::post_data,
        timer::{self, Guard, Time, Timer},
    },
    CHAL_DATA,
};

use super::{QElement, CHAL_IDENTIFIER};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use core::ops::Index;
use serde::{Deserialize, Serialize};
use sgx_rand::{
    distributions::{IndependentSample, Range},
    thread_rng,
};
use std::{
    collections::HashMap,
    env,
    sync::{mpsc::channel, SgxMutex},
    thread,
    time::SystemTime,
};

lazy_static! (
    static ref TIMER: SgxMutex<Timer> = SgxMutex::new(Timer::new());
);

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

    pub fn clear(&mut self) {
        self.bloom_filter.clear();
        self.failed_file_hashes.clear();
        self.chal_id.clear();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique random value sent by CESS Chain
    pub chal_id: Vec<u8>,

    /// Proof Submission TimeOut in seconds
    pub time_out: i64,

    /// Challenge
    pub q_elements: Vec<QElement>,
}

impl Challenge {
    pub fn new() -> Challenge {
        Challenge {
            chal_id: Vec::new(),
            time_out: i64::MIN,
            q_elements: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.chal_id.clear();
        self.time_out = i64::MIN;
        self.q_elements.clear();
    }
}

pub fn chal_gen(n: i64, chal_id: &Vec<u8>) -> Result<PoDR2Chal, PoDR2Error> {
    let mut q_elements: Vec<QElement> = vec![];
    if n < 0 {
        return Err(PoDR2Error {
            message: Some("n should be greater than 0".to_string()),
        });
    }

    let mut chal_ident = CHALLENGE.lock().unwrap();
    let mut time_out: i64;

    if chal_ident.chal_id.is_empty() {
        let now = Time::now();
        info!("New Challenge ID Received At {}: {}!", now, now.timestamp());

        let schedule_time = now + Duration::seconds(30);
        time_out = schedule_time.timestamp();

        let mut chal_data = CHAL_DATA.lock().unwrap();
        chal_data.chal_id = chal_id.to_vec().clone();
        chal_ident.chal_id = chal_id.to_vec().clone();
        q_elements = QElement::get_elements(n);
        chal_ident.q_elements = q_elements.clone();
        chal_ident.time_out = schedule_time.timestamp();

        let _ = match thread::Builder::new()
            .name(format!(
                "post_challenge_{}",
                base64::encode(chal_id.to_vec())
            ))
            .spawn(move || {
                let (tx, rx) = channel();

                let _guard = TIMER
                    .lock()
                    .unwrap()
                    .schedule_with_date(schedule_time, move || {
                        match tx.send(()) {
                            Ok(m) => m,
                            Err(e) => {
                                error!("Failed to post_challenge thread message: {}", e.to_string())
                            }
                        };
                    });

                debug!(
                    "Challenge Post Scheduled for {}: {}!",
                    schedule_time, time_out
                );

                match rx.recv() {
                    Ok(_) => post_chal_data(),
                    Err(e) => error!("Failed to submit proofs to chain: {}", e.to_string()),
                };
            }) {
            Ok(handle) => handle,
            Err(e) => {
                return Err(PoDR2Error {
                    message: Some(format!("{}", e.to_string())),
                })
            }
        };
    } else {
        info!(
            "Existing Challenge! ID: {:?}, Scheduled At: {}!",
            chal_ident.chal_id, chal_ident.time_out
        );
        time_out = chal_ident.time_out;
        q_elements = chal_ident.q_elements.clone();
    }

    Ok(PoDR2Chal {
        q_elements,
        time_out,
    })
}

fn post_chal_data() {
    info!("Submitting Proofs to Chain");
    let mut chal_data = CHAL_DATA.lock().unwrap();
    let mut challenge = CHALLENGE.lock().unwrap();
    
    let url: String = match env::var("CESS_POST_CHAL_URL") {
        Ok(url) => url,
        Err(e) => {
            warn!("CESS_POST_CHAL_URL environment variable not set. Resetting Challenge Data");
            challenge.clear();
            chal_data.clear();
            debug!("Resetting Completed!");
            return;
        }
    };

    post_data::<ChalData>(url, &chal_data);

    info!("Resetting Challenge Data");
    chal_data.clear();
    challenge.clear();
    debug!("Resetting Completed!");
}
