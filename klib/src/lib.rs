extern crate libc;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::mem;


#[no_mangle]
pub extern "C" fn rustdemo(name: *const libc::c_char) -> *const libc::c_char {
    let cstr_name = unsafe { CStr::from_ptr(name) };
    let mut str_name = cstr_name.to_str().unwrap().to_string();
    println!("Rust get Input:  \"{}\"", str_name);
    let r_string: &str = " Rust say: Hello Go ";
    str_name.push_str(r_string);
    CString::new(str_name).unwrap().into_raw()
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PoDR2Response{
    pub vec_ptr :*const u8,
    pub len     :libc::size_t,
    pub cap     :libc::size_t,
}
impl Default for PoDR2Response {
    fn default() -> PoDR2Response {
        PoDR2Response {
            vec_ptr: std::ptr::null(),
            len: 0,
            cap: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn proof_generate_api(path: *const libc::c_char) ->*mut PoDR2Response{
    let cstr_path = unsafe { CStr::from_ptr(path) };
    let str_path = cstr_path.to_str().unwrap().to_string();
    println!("Rust get file path:  \"{}\"", str_path);
    let f =fs::File::open(str_path);
    let mut f =match f {
        Ok(file) =>file,
        Err(error) => {
            panic!("The error happened when open file error:{:?}",error)
        }
    };
    let mut data = Vec::new();
    let file_info=f.read_to_end(&mut data);
    match file_info {
        Ok(size) => {
            println!("The size of file is {}", size);
        },
        Err(error) => {
            panic!("The error happened when read file error:{:?}",error)
        }
    }
    let vec_ptr=data.as_ptr();
    let vec_len=data.len();
    let vec_cap=data.capacity();
    let mut response: PoDR2Response = Default::default();
    response.vec_ptr=vec_ptr;
    response.len=vec_len;
    response.cap=vec_cap;

    mem::forget(data);
    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn destroy_PoDR2_response(
    ptr: *mut PoDR2Response,
) {
    let _ = Box::from_raw(ptr);
    println!("Rust destroy PoDR2Response");
}

pub fn raw_ptr<T>(thing: T) -> *mut T {
    Box::into_raw(Box::new(thing))
}
