#![crate_type = "staticlib"]
extern crate libc;
extern crate sgx_types;
extern crate sgx_urts;
use std::ffi::{CStr};
// use std::fs;
// use std::io::Read;
// use std::mem;
use sgx_urts::SgxEnclave;
use sgx_types::*;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

// #[no_mangle]
// pub extern "C" fn rustdemo(name: *const libc::c_char) -> *const libc::c_char {
//     let cstr_name = unsafe { CStr::from_ptr(name) };
//     let mut str_name = cstr_name.to_str().unwrap().to_string();
//     println!("Rust get Input:  \"{}\"", str_name);
//     let r_string: &str = " Rust say: Hello Go ";
//     str_name.push_str(r_string);
//     CString::new(str_name).unwrap().into_raw()
// }
//
// #[repr(C)]
// #[derive(Clone, Copy)]
// pub struct PoDR2Response{
//     pub vec_ptr :*const u8,
//     pub len     :libc::size_t,
//     pub cap     :libc::size_t,
// }
// impl Default for PoDR2Response {
//     fn default() -> PoDR2Response {
//         PoDR2Response {
//             vec_ptr: std::ptr::null(),
//             len: 0,
//             cap: 0,
//         }
//     }
// }
//
// #[no_mangle]
// pub extern "C" fn proof_generate_api(path: *const libc::c_char) ->*mut PoDR2Response{
//     let cstr_path = unsafe { CStr::from_ptr(path) };
//     let str_path = cstr_path.to_str().unwrap().to_string();
//     println!("Rust get file path:  \"{}\"", str_path);
//     let f =fs::File::open(str_path);
//     let mut f =match f {
//         Ok(file) =>file,
//         Err(error) => {
//             panic!("The error happened when open file error:{:?}",error)
//         }
//     };
//     let mut data = Vec::new();
//     let file_info=f.read_to_end(&mut data);
//     match file_info {
//         Ok(size) => {
//             println!("The size of file is {}", size);
//         },
//         Err(error) => {
//             panic!("The error happened when read file error:{:?}",error)
//         }
//     }
//     let vec_ptr=data.as_ptr();
//     let vec_len=data.len();
//     let vec_cap=data.capacity();
//     let mut response: PoDR2Response = Default::default();
//     response.vec_ptr=vec_ptr;
//     response.len=vec_len;
//     response.cap=vec_cap;
//
//     mem::forget(data);
//
//     // let _ = match init_enclave() {
//     //     Ok(r) => {
//     //         println!("[+] Init Enclave Successful {}!", r.geteid());
//     //     }
//     //     Err(x) => {
//     //         println!("[-] Init Enclave Failed {}!", x.as_str());
//     //     }
//     // };
//
//     raw_ptr(response)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn destroy_PoDR2_response(
//     ptr: *mut PoDR2Response,
// ) {
//     let _ = Box::from_raw(ptr);
//     println!("Rust destroy PoDR2Response");
// }
//
// pub fn raw_ptr<T>(thing: T) -> *mut T {
//     Box::into_raw(Box::new(thing))
// }

#[no_mangle]
pub extern "C" fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[no_mangle]
pub extern "C" fn hello(name: *const libc::c_char) {
    let buf_name = unsafe { CStr::from_ptr(name).to_bytes() };
    let str_name = String::from_utf8(buf_name.to_vec()).unwrap();
    let _ = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
        }
    };
    println!("Hello {}!", str_name);
}