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
extern crate dotenv;

mod enclave;
mod models;
mod routes;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use log::{error, info};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::borrow::{Borrow, BorrowMut};
use std::fs;
use std::io::Read;
use std::{
    env,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    os::unix::io::{AsRawFd, IntoRawFd},
    str,
    str::FromStr,
};


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
    env_logger::init();
    dotenv().ok();

    let port: u16 = env::var("KALEIDO_PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap();
    
    // let cfg = fs::read_to_string("./config.toml");
    // let cfg: Config = match cfg {
    //     Ok(cfg_str) => toml::from_str(&cfg_str).expect("Invalid configuration file."),
    //     Err(_) => Config::default(),
    // };

    let heap_max_size = env::var("HEAP_MAX_SIZE").expect("HEAP_MAX_SIZE is not set.");
    let heap_max_size = i64::from_str_radix(heap_max_size.trim_start_matches("0x"), 16).unwrap();
    info!("Initializing Enclave with {} MB of memory", heap_max_size / (1024 * 1024) );
    
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

            let result = unsafe {
                enclave::ecalls::run_server(
                    eid,
                    &mut retval,
                    sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
                )
            };
            println!("Get intel result is {:?}",result);

            let res = HttpServer::new(move || {
                let logger = Logger::default();
                let eid = eid.clone();
                App::new()
                    .wrap(logger)
                    .app_data(web::JsonConfig::default().limit(1024 * 1024 * 1024 * 3)) //3G limmit
                    .app_data(web::Data::new(models::app_state::AppState {
                        eid,
                    }))
                    .service(routes::r_process_data)
                    .service(routes::r_get_chal)
                    .service(routes::r_get_report)
                    .service(routes::r_fill_random_file)
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

#[cfg(test)] 
mod test_podr2;