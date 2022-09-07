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
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::io::{AsRawFd, IntoRawFd},
    str,
    str::FromStr,
};

use crate::models::config::Config;

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

    let cfg = fs::read_to_string("./config.toml");
    let cfg: Config = match cfg {
        Ok(cfg_str) => toml::from_str(&cfg_str).expect("Invalid configuration file."),
        Err(_) => Config::default(),
    };

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

            // Start Remote Attestation server.
            std::thread::Builder::new()
                .name("ra_server".to_owned())
                .spawn(move || {
                    start_ra_server(eid);
                })
                .expect("Failed to launch ra_server thread");

            // // Get attested from peers to receive Signing Keys.
            // if !get_attested_keys(eid, cfg.ra_peers.clone()).await {
            //     enclave.destroy();
            //     panic!("Failed to get/generate key pair");
            // }

            let res = HttpServer::new(move || {
                let logger = Logger::default();
                let eid = eid.clone();
                App::new()
                    .wrap(logger)
                    .app_data(web::JsonConfig::default().limit(1024 * 1024 * 1024 * 3)) //3G limmit
                    .app_data(web::Data::new(models::app_state::AppState {
                        eid,
                        config: cfg.clone(),
                    }))
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

fn start_ra_server(eid: u64) {
    let port : u16 = env::var("REMOTE_ATTESTATION_PORT")
        .unwrap_or("8088".to_string())
        .parse()
        .unwrap();
        
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port.to_string())).unwrap();
    info!(
        "Remote attestation server listening on port: {}",
        port.to_string()
    );
    loop {
        match listener.accept() {
            Ok((socket, addr)) => {
                info!("New client from {:?}", addr);
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result = unsafe {
                    enclave::ecalls::run_server(
                        eid,
                        &mut retval,
                        socket.as_raw_fd(),
                        sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
                    )
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {
                        info!("Attestation success for client {:?}!", addr);
                    }
                    _ => {
                        error!("Failed to attest client {:?} {}!", addr, result.as_str());
                        return;
                    }
                }
            }
            Err(e) => error!("Failed to get client: {:?}", e),
        }
    }
}

fn gen_keys(eid: u64) -> bool {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    unsafe {
        enclave::ecalls::gen_keys(eid, &mut retval);
    }
    retval == sgx_status_t::SGX_SUCCESS
}
