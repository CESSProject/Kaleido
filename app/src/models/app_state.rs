use serde::{Deserialize, Serialize};
// This struct represents state
pub struct AppState {
    // Enclave Id
    pub eid: u64,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct EnclaveMemoryCounter{
    pub data_len:usize
}