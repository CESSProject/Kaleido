// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "cess_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate cess_pbc;
extern crate sgx_rand;
extern crate sgx_types;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use cess_pbc::*;
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::ptr;
use std::string::String;
use sgx_types::*;
use alloc::slice;

#[no_mangle]
pub extern "C" fn get_rng(length: usize, value: *mut u8) -> sgx_status_t {
    let mut random_vec = vec![0u8; length];
    let random_slice = &mut random_vec[..];

    let mut rng = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    rng.fill_bytes(random_slice);

    unsafe {
        ptr::copy_nonoverlapping(random_slice.as_ptr(), value, length);
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_pbc() -> sgx_status_t {
    println!("Hello, Testing PBC!");
    let input = "Hello!".as_bytes();
    let output = vec![0u8; input.len()];
    unsafe {
        let echo_out = cess_pbc::echo(
            input.len() as u64,
            input.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        );
        assert_eq!(echo_out, input.len() as u64);
        assert_eq!(input.to_vec(), output);
    }
    
    // Rust style convertion
    let mut out_str = String::from("");
    out_str += String::from_utf8(output).expect("Invalid UTF-8").as_str();

    println!("PBC Echo Output: {}", out_str);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn file_chunk(length: usize, value: *const u8) ->sgx_status_t{
    let mut file_data = vec![0u8; length];
    let file_data_slice = &mut file_data[..];

    unsafe {
        ptr::copy_nonoverlapping(value, file_data_slice.as_mut_ptr(), length);
    }
    sgx_status_t::SGX_SUCCESS
}