use std::sync::atomic::{AtomicUsize,AtomicPtr, Ordering};
use std::sync::{SgxMutex, SgxCondvar};
use std::boxed::Box;

pub const MAX_THREAD:usize=8;

pub static THREAD_POOL: AtomicUsize = AtomicUsize::new(0);
pub struct CondBuffer{
    pub occupied: i32,
}

impl Default for CondBuffer {
    fn default() -> CondBuffer {
        CondBuffer {
            occupied: 0,
        }
    }
}

pub fn gen_cond_buffer()->AtomicPtr<()>{
    AtomicPtr::new(0 as * mut ())
}

pub fn init_cond_buffer(cond_buffer:&mut AtomicPtr<()>){
    let lock = Box::new((
        SgxMutex::<CondBuffer>::new(CondBuffer::default()),
        SgxCondvar::new(),
    ));
    let ptr = Box::into_raw(lock);
    cond_buffer.store(ptr as *mut (), Ordering::SeqCst);
}

pub fn get_ref_cond_buffer(global_cond_buffer:&AtomicPtr<()>) -> Option<&'static (SgxMutex<CondBuffer>, SgxCondvar)> {
    let ptr = global_cond_buffer.load(Ordering::SeqCst)
        as *mut (SgxMutex<CondBuffer>, SgxCondvar);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}