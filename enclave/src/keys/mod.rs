mod aes_keys;
mod rsa_keys;

use alloc::{vec::Vec, sync::Arc};
use core::convert::TryInto;
use secp256k1::{PublicKey, SecretKey};
use sgx_rand::Rng;
use sgx_serialize::{DeSerializable, DeSerializeHelper, SerializeHelper};
use std::{
    io::{Read, Write},
    sgxfs::SgxFile,
};

use self::{aes_keys::AesKeys, rsa_keys::RsaKeys};

#[derive(Serializable, DeSerializable)]
pub struct Keys {
    pub aes_keys: Arc<AesKeys>,
    pub rsa_keys: Arc<RsaKeys>,
}

impl Keys {
    const FILE_NAME: &'static str = "rakeys";

    // Try to Load from the file 1st
    // If not generate new.
    pub fn get_instance() -> Keys {
        let mut file = match SgxFile::open(Keys::FILE_NAME) {
            Ok(f) => f,
            Err(_) => {
                info!("{} file not found, creating new file.", Keys::FILE_NAME);

                // Generate Keys
                let keys = Keys::gen_keys();
                let saved = keys.save();
                if !saved {
                    error!("Failed to save keys");
                }

                info!("Signing keys generated!");
                return keys;
            }
        };

        Keys::load(&mut file)
    }

    pub fn gen_keys() -> Keys {
        info!("Generating Keys");
        Keys {
            aes_keys: Arc::new(AesKeys::new()),
            rsa_keys: Arc::new(RsaKeys::new()),
        }
    }

    fn save(&self) -> bool {
        let helper = SerializeHelper::new();
        let data = match helper.encode(self) {
            Some(d) => d,
            None => {
                warn!("Key encoding failed");
                return false;
            }
        };

        let mut file = match SgxFile::create(Keys::FILE_NAME) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create file {}", Keys::FILE_NAME);
                return false;
            }
        };

        let _write_size = match file.write(data.as_slice()) {
            Ok(len) => len,
            Err(_) => {
                warn!("Failed to write file {}", Keys::FILE_NAME);
                return false;
            }
        };
        return true;
    }

    fn load(file: &mut SgxFile) -> Keys {
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data);

        let helper = DeSerializeHelper::<Keys>::new(data);

        match helper.decode() {
            Some(d) => {
                info!("Keys Loaded!");
                d
            }
            None => {
                panic!("Failed to decode file {}.", Keys::FILE_NAME);
            }
        }
    }
}
