use sgx_types::*;

extern "C" {
    pub fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn gen_keys(eid: sgx_enclave_id_t, retval: *mut sgx_status_t);
    pub fn process_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        data: *mut u8,
        data_len: usize,
        n_blocks: usize,
        callback_url: *const c_char,
    ) -> sgx_status_t;
    pub fn gen_chal(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        n_blocks: usize,
        random: *mut u8,
        random_len: usize,
        time: u64,
        callback_url: *const c_char,
    ) -> sgx_status_t;

    pub fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
    pub fn get_report(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        callback_url: *const c_char
    ) -> sgx_status_t;
}
