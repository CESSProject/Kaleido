use sgx_types::*;

extern "C" {
    pub fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    // pub fn gen_keys(eid: sgx_enclave_id_t, retval: *mut sgx_status_t);
    pub fn process_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        file_path: *const c_char,
        block_size: usize,
        callback_url: *const c_char,
    ) -> sgx_status_t;
    pub fn gen_chal(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        n_blocks: usize,
        proof_id: *mut u8,
        proof_id_len: usize,
        callback_url: *const c_char,
    ) -> sgx_status_t;

    pub fn verify_proof(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        verify_type: usize,
        proof_id: *mut u8,
        proof_id_len: usize,
        proof_json: *const c_char,
    ) -> sgx_status_t;
    pub fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
    pub fn get_report(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        callback_url: *const c_char
    ) -> sgx_status_t;
    pub fn fill_random_file(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        file_path_ptr: *const c_char,
        data_len: usize,
    ) -> sgx_status_t;
    pub fn message_signature(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        msg: *const c_char,
        callback_url: *const c_char,
    ) -> sgx_status_t;
    pub fn test_func(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        msg: *const c_char,
    ) -> sgx_status_t;
}
