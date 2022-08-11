use std::env;

fn main() {
    let ias_env = env::var("IAS_ENV").unwrap_or_else(|_| "DEV".to_string());

    match ias_env.as_ref() {
        "PROD" => {
            println!("cargo:rustc-env=IAS_HOSTNAME=api.trustedservices.intel.com");
            println!("cargo:rustc-env=IAS_SIGRL_SUFFIX=/sgx/attestation/v4/sigrl/");
            println!("cargo:rustc-env=IAS_REPORT_SUFFIX=/sgx/attestation/v4/report");
        }
        _ => {
            // DEV by default
            println!("cargo:rustc-env=IAS_HOSTNAME=api.trustedservices.intel.com");
            println!("cargo:rustc-env=IAS_SIGRL_SUFFIX=/sgx/dev/attestation/v4/sigrl/");
            println!("cargo:rustc-env=IAS_REPORT_SUFFIX=/sgx/dev/attestation/v4/report");
        }
    }

    if env::var("IAS_SPID").is_err() {
        println!("cargo:rustc-env=IAS_SPID=''");
    }
    println!("cargo:rerun-if-env-changed=IAS_SPID");

    if env::var("IAS_API_KEY").is_err() {
        println!("cargo:rustc-env=IAS_API_KEY=''");
    }
    println!("cargo:rerun-if-env-changed=IAS_API_KEY");
}
