use sgx_types::*;

extern "C" {
    pub fn get_rng(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        length: usize,
        value: *mut u8,
    ) -> sgx_status_t;
    pub fn test_pbc(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn gen_keys(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        seed: *const u8,
        seed_len: usize,
    );
    pub fn process_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        data: *mut u8,
        data_len: usize,
        block_size: usize,
        segment_size: usize,
        callback_url: *const c_char,
    ) -> sgx_status_t;
    pub fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                  socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
    pub fn run_client(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                  socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
}
