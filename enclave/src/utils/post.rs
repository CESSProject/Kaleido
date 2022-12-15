use alloc::string::ToString;
use http_req::{
    request::{Method, RequestBuilder},
    tls,
    uri::Uri,
};
use std::{
    string::String,
    net::TcpStream,
    time::{Duration, Instant, SystemTime},
};
use serde::Serialize;
use alloc::vec::Vec;
use sgx_status_t;

pub fn post_data<T>(url: String, data: &T)
where
     T: ?Sized + Serialize,
{
    let addr: Uri = match url.parse() {
        Ok(add) => add,
        Err(_) => {
            warn!("Failed to Parse Url");
            return
        }
    };

    let conn_addr = get_host_with_port(&addr);

    //Connect to remote host
    let mut stream = TcpStream::connect(&conn_addr);
    let mut stream = match stream {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to {}, {}", addr, e);
            return
        }
    };
    let json_data = match serde_json::to_string(data) {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to serialize when post");
            return
        }
    };
    let json_bytes = json_data.as_bytes();
    let mut writer = Vec::new();
    let time_out = Some(Duration::from_millis(200));
    if addr.scheme() == "https" {
        //Open secure connection over TlsStream, because of `addr` (https)
        let mut stream = tls::Config::default().connect(addr.host().unwrap_or(""), &mut stream);

        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to {}, {}", addr, e);
                return
            }
        };

        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .method(Method::POST)
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                warn!("Failed to send https request to {}, {}", addr, e);
                return
            }
        };

        info!(
            "PoDR2 Post Data Status: {} {}",
            response.status_code(),
            response.reason()
        );
    } else {
        let response = RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .header("Content-Type", "Application/Json")
            .header("Content-Length", &json_bytes.len())
            .method(Method::POST)
            .timeout(time_out)
            .body(json_bytes)
            .send(&mut stream, &mut writer);
        let response = match response {
            Ok(res) => res,
            Err(e) => {
                warn!("Failed to send http request to {}, {}", addr, e);
                return
            }
        };

        info!(
            "PoDR2 Post Data Status: {} {}",
            response.status_code(),
            response.reason()
        );
    }
}

fn get_host_with_port(addr: &Uri) -> String {
    let port = addr.port();
    let port: u16 = if port.is_none() {
        let scheme = addr.scheme();
        if scheme == "http" {
            80
        } else {
            443
        }
    } else {
        port.unwrap()
    };
    format!("{}:{}", addr.host().unwrap(), port)
}