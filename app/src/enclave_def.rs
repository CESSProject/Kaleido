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
        sigmas_len: &usize,
        u_len: &usize,
        name_len: usize,
        name_out: *mut u8,
        sig_len: usize,
        sig_out: *mut u8,
    ) -> sgx_status_t;
    pub fn sign_message(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        data: *mut u8,
        data_len: usize,
        sig_len: usize,
        sig: *mut u8,
    ) -> sgx_status_t;
    pub fn get_public_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pkey_len: usize,
        pkey: *mut u8,
    ) -> sgx_status_t;
    pub fn get_signature(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        index: usize,
        sig_len: usize,
        sigs: *mut u8,
    ) -> sgx_status_t;
    pub fn get_sigmas(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        index: usize,
        sigmas_len: usize,
        sigmas_out: *mut u8,
    ) -> sgx_status_t;
    pub fn get_u(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        index: usize,
        u_len: usize,
        u_out: *mut u8,
    ) -> sgx_status_t;
}
