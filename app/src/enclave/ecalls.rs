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
    pub fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                  socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
}
