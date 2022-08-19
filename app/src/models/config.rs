use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub ra_peers: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ra_peers: vec!["139.180.145.138:8088".to_owned()],
        }
    }
}