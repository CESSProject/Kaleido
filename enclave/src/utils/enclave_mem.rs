use core::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

pub static ENCLAVE_MEM_CAP: AtomicUsize = AtomicUsize::new(0);


pub fn has_enough_mem(data_len: usize) -> bool {
    //Determine the remaining enclave memory size
    let mem = ENCLAVE_MEM_CAP.fetch_add(0, Ordering::SeqCst);
    if mem < data_len {
        return false;
    }
    true
}