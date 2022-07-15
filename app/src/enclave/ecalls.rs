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
    pub fn enclave_init_ra(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        b_pse:bool,
        p_context: *mut sgx_ra_context_t,
    ) -> sgx_status_t;
    pub fn enclave_ra_close(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context:sgx_ra_context_t,
    ) -> sgx_status_t;
    pub fn verify_att_result_mac(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context:sgx_ra_context_t,
        message: *mut u8,
        message_size:usize,
        mac: *mut u8,
        mac_size:usize,
    ) -> sgx_status_t;
    pub fn verify_secret_data(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context:sgx_ra_context_t,
        p_secret: *mut u8,
        secret_size:u32,
        gcm_mac: *mut u8,
        max_verification_length:u32,
        p_ret: *mut u8,
    ) -> sgx_status_t;
}
