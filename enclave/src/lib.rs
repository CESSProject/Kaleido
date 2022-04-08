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

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_rand;
extern crate sgx_types;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use core::convert::TryInto;

use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::ptr;

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
        ptr::copy_nonoverlapping(
            random_slice.as_ptr(),
            value,
            length
        );
    }
    sgx_status_t::SGX_SUCCESS
}

pub extern "C" fn random_creator() -> u32 {
    use sgx_rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let random: u32 = rng.gen_range(0, 10);
    println!("{}", n);
    random
}