use libc::c_char;

extern "C" {
    pub fn ocall_post_podr2_commit_data(data: *const c_char);
}