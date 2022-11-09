#[cfg(test)] 
use core::time;
use std::ffi::CString;
use std::io::{Read, Write};
use std::thread;
use std::{env, fs};

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::net::{TcpListener, TcpStream};

use crate::enclave;

static ENCLAVE_FILE: &'static str = "../bin/enclave.signed.so";
static CALLBACK_URL: &'static str = "";
static DUMMY_DATA: &'static str = "SGVsbG8gO2pzZGE7bGZqa2RzaiBqZnMnO2dqIDtkZnNqZyBmIGQKZzsnZjsgZHNnOydkc2dsJ2tkZmogaHBpMHU0dzUwIHktdTU0LXd1MztkZnNcO2dcIHNkZmZnXCBmZHNcXWdkIGZzXFwgc2RcXGRmClwgcwoKZCBmc2cKZCBmcwpnIGRzZmcgZA==";
static N_BLOCKS: usize = 4;

fn init_enclave() -> SgxResult<SgxEnclave> {
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

#[test]
fn podr2_sign_ge() {
    env::set_var("HEAP_MAX_SIZE", "0x8000000");
    let enclave = match init_enclave() {
        Ok(enclave) => enclave,
        Err(e) => {
            panic!(
                "Failed to start enclave! {},\nMake sure you have build Kaleido first.",
                e.as_str()
            );
        }
    };

    let eid = enclave.geteid();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        enclave::ecalls::init(eid, &mut retval);
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        enclave.destroy();
        panic!("Failed to initialize enclave libraries");
    }

    retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        enclave::ecalls::gen_keys(eid, &mut retval);
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        enclave.destroy();
        panic!("Failed to generate PBC keys");
    }

    let c_callback_url_str = CString::new(CALLBACK_URL.as_bytes().to_vec()).unwrap();
    let file_data = base64::decode(DUMMY_DATA);
    let file_data = match file_data {
        Ok(data) => data,
        Err(_) => {
            panic!("Invalid base64 encoded data.");
        }
    };


    // TODO: Start a TCPListner and pass a callback url of the same to the process_data function to listen to its post PoDR2 data request. 
    let mut result = sgx_status_t::SGX_SUCCESS;
    // The sgx_status_t returned from ecall is reflected in `result` and not from the returned value here
    let res = unsafe {
        enclave::ecalls::process_data(
            eid,
            &mut result,
            file_data.as_ptr() as *mut u8,
            file_data.len(),
            N_BLOCKS,
            c_callback_url_str.as_ptr(),
        )
    };

    if res != sgx_status_t::SGX_SUCCESS || result != sgx_status_t::SGX_SUCCESS {
       panic!("process_data error");
    }

    // TODO: Once PoDR2

    thread::sleep(time::Duration::from_secs(1));
    fs::remove_file("keys");
    enclave.destroy();
    assert_eq!(1, 1);
}

fn handle_read(mut stream: &TcpStream) {
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(_) => {
            let req_str = String::from_utf8_lossy(&buf);
            println!("REQUEST {}", req_str);
            
        }
        Err(e) => println!("Unable to read stream: {}", e),
    }
}

fn handle_write(mut stream: TcpStream) {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Hello world</body></html>\r\n";
    match stream.write(response) {
        Ok(_) => println!("Response sent"),
        Err(e) => println!("Failed sending response: {}", e),
    }
}

fn handle_client(stream: TcpStream) {
    handle_read(&stream);
    handle_write(stream);
}
