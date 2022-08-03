use super::config::Config;

// This struct represents state
pub struct AppState {
    // Enclave Id
    pub eid: u64,
    pub config: Config,
}
