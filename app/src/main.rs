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

extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate log;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use log::{error, info};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{env, str};
use std::io::Read;

mod enclave;
mod models;
mod routes;
#[derive(Debug, Deserialize)]
struct Document {
    param: Option<String>,
    first_element: String,
    second_element: SecondElement,
}
//Request fusing
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
static Enclave_Cap: AtomicUsize = AtomicUsize::new(0);

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    //init enclave cap
    let mut file = std::fs::File::open("../enclave/Enclave.config.xml").unwrap();
    let mut enclave_conf_data:String=String::new();
    file.read_to_string(&mut enclave_conf_data);
    let pos :Vec<&str> = enclave_conf_data.split("<HeapMaxSize>").collect();
    let heap_max_size_str:Vec<&str>=pos[pos.len()-1].split("</HeapMaxSize>").collect();
    let max_value_in_conf =i64::from_str_radix(heap_max_size_str[0].clone().trim_start_matches("0x"), 16).unwrap();
    let all_cap=Enclave_Cap.fetch_add((max_value_in_conf as f32 * 0.65) as usize,Ordering::SeqCst);
    println!("all enclave capture is {}",all_cap);
    // test_rma();
    let port: u16 = env::var("KALEIDO_PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap();

    env_logger::init();
    info!("Initializing Enclave");
    let result = match init_enclave() {
        Ok(enclave) => {
            let eid = enclave.geteid();
            info!("Enclave Initialized! ID: {}!", eid);

            let mut retval = sgx_status_t::SGX_SUCCESS;
            unsafe {
                enclave::ecalls::init(eid, &mut retval);
            }
            if retval != sgx_status_t::SGX_SUCCESS {
                enclave.destroy();
                panic!("Failed to initialize enclave libraries");
            }

            unsafe {
                enclave::ecalls::gen_keys(eid, &mut retval);
            }
            if retval != sgx_status_t::SGX_SUCCESS {
                enclave.destroy();
                panic!("Failed to generate key pair");
            }

            let res = HttpServer::new(move || {
                let logger = Logger::default();
                let eid = eid.clone();
                App::new()
                    .wrap(logger)
                    .app_data(web::JsonConfig::default().limit(1024 * 1024 * 1024))
                    .app_data(web::Data::new(models::app_state::AppState { eid }))
                    .service(routes::r_process_data)
            })
            .bind(("0.0.0.0", port))?
            .run()
            .await?;
            enclave.destroy();
            info!("Enclave destroyed");
            Ok(res)
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            panic!("Failed to start enclave!");
        }
    };

    result
}

enum Mode {
    Client,
    Server,
}

fn test_rma() {
    use std::env;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::io::{AsRawFd, IntoRawFd};
    use std::str;

    let mut mode: Mode = Mode::Server;
    let mut args: Vec<_> = env::args().collect();
    let mut sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    args.remove(0);
    while !args.is_empty() {
        match args.remove(0).as_ref() {
            "--client" => mode = Mode::Client,
            "--server" => mode = Mode::Server,
            "--unlink" => sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
            _ => {
                panic!("Only --client/server/unlink is accepted");
            }
        }
    }

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    match mode {
        Mode::Server => {
            println!("Running as server...");
            let listener = TcpListener::bind("0.0.0.0:3443").unwrap();
            //loop{
            match listener.accept() {
                Ok((socket, addr)) => {
                    println!("new client from {:?}", addr);
                    let mut retval = sgx_status_t::SGX_SUCCESS;
                    let result = unsafe {
                        enclave::ecalls::run_server(
                            enclave.geteid(),
                            &mut retval,
                            socket.as_raw_fd(),
                            sign_type,
                        )
                    };
                    match result {
                        sgx_status_t::SGX_SUCCESS => {
                            println!("ECALL success!");
                        }
                        _ => {
                            println!("[-] ECALL Enclave Failed {}!", result.as_str());
                            return;
                        }
                    }
                }
                Err(e) => println!("couldn't get client: {:?}", e),
            }
            //} //loop
        }
        Mode::Client => {
            println!("Running as client...");
            let socket = TcpStream::connect("127.0.0.1:3443").unwrap();
            let mut retval = sgx_status_t::SGX_SUCCESS;
            let result = unsafe {
                enclave::ecalls::run_client(
                    enclave.geteid(),
                    &mut retval,
                    socket.as_raw_fd(),
                    sign_type,
                )
            };
            match result {
                sgx_status_t::SGX_SUCCESS => {
                    println!("ECALL success!");
                }
                _ => {
                    println!("[-] ECALL Enclave Failed {}!", result.as_str());
                    return;
                }
            }
        }
    }

    println!("[+] Done!");

    enclave.destroy();
}