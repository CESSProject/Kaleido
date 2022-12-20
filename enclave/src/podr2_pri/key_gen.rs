use alloc::string::{String, ToString};
use std::{
    vec::Vec,
    sgxfs::SgxFile,
    io::ErrorKind,
    io::{Error, Write},
};
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::hmac::Hmac;
use crypto::mac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use sgx_rand;
use sgx_rand::Rng;
use crate::param::podr2_commit_data::PoDR2Error;
use utils::{convert::u8v_to_hexstr};
use sgx_serialize::{DeSerializeHelper, SerializeHelper,Serializable};
use std::io::Read;

#[derive(Serializable, DeSerializable)]
#[derive(Clone)]
pub struct EncryptionType {
    pub aes: AES,
    pub hmacsha1: HMACSHA1,
}

pub trait Symmetric {
    fn symmetric_encrypt(&self, orig_data: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error>;
    fn symmetric_decrypt(&self, ciphertext: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error>;
    fn get_prf(&self) ->String;
    fn get_enc(&self) ->String;
}

pub trait MacHash {
    fn mac_encrypt(&self, orig_data: &[u8]) -> Result<Vec<u8>, PoDR2Error>;
    fn get_mac(&self) ->String;
}

#[derive(Serializable, DeSerializable)]
#[derive(Clone)]
pub struct HMACSHA1 {
    mac: [u8; 16],
}

#[derive(Serializable, DeSerializable)]
#[derive(Clone)]
pub struct AES {
    enc: [u8; 16],
    prf: [u8; 16],
}

impl Symmetric for EncryptionType {
    fn symmetric_encrypt(&self, orig_data: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error> {
        let key = match key_type {
            "prf" => &self.aes.prf,
            "enc" => &self.aes.enc,
            _ => return Err(PoDR2Error{ message: Some("error,not such key type!".to_string())}),
        };
        let mut iv = [0u8; 16];
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            &iv,
            blockmodes::PkcsPadding);
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(orig_data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        loop {
            let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
        Ok(final_result)
    }

    fn symmetric_decrypt(&self, ciphertext: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error> {
        let key = match key_type {
            "prf" => &self.aes.prf,
            "enc" => &self.aes.enc,
            _ => return Err(PoDR2Error{ message: Some("error,not such key type!".to_string())}),
        };
        let mut iv = [0u8; 16];
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            &iv,
            blockmodes::PkcsPadding);
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        loop {
            let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }

        Ok(final_result)
    }

    fn get_prf(&self) ->String{
        u8v_to_hexstr(&self.aes.prf.clone())
    }

    fn get_enc(&self) ->String{
        u8v_to_hexstr(&self.aes.enc.clone())
    }
}

impl MacHash for EncryptionType {
    fn mac_encrypt(&self, orig_data: &[u8]) -> Result<Vec<u8>, PoDR2Error> {
        let mut hmac = Hmac::new(Sha256::new(), &self.hmacsha1.mac);
        hmac.input(orig_data);
        Ok(hmac.result().code().to_vec())
    }

    fn get_mac(&self) ->String{
        u8v_to_hexstr(&self.hmacsha1.mac.clone())
    }
}


pub fn key_gen() -> EncryptionType {
    // let mut enc = String::from("1234567891234567");
    let mut enc_byte = [0u8; 16];
    let mut prf_byte = [0u8; 16];
    let mut mac_byte = [0u8; 16];
    // let mut i = 0;
    // for ix in enc.as_bytes() {
    //     enc_byte[i] = *ix;
    //     prf_byte[i] = *ix;
    //     mac_byte[i] = *ix;
    //     i += 1;
    // }
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut enc_byte);
    os_rng.fill_bytes(&mut prf_byte);
    os_rng.fill_bytes(&mut mac_byte);

    let aes = AES {
        enc: enc_byte,
        prf: prf_byte
    };
    let hmacsha1 = HMACSHA1 {
        mac: mac_byte
    };
    EncryptionType {
        aes,
        hmacsha1,
    }
}

impl EncryptionType{
    pub const FILE_NAME: &'static str = "keys";

    pub fn save(self: &mut Self) -> bool {
        let helper = SerializeHelper::new();
        let data = match helper.encode(self.clone()) {
            Some(d) => d,
            None => {
                return false;
            }
        };

        let mut file = match SgxFile::create(EncryptionType::FILE_NAME) {
            Ok(f) => f,
            Err(e) => {
                return false;
            }
        };

        let _write_size = match file.write(data.as_slice()) {
            Ok(len) => len,
            Err(_) => {
                return false;
            }
        };
        return true;
    }

    pub fn load(self: &mut Self) -> bool {
        let mut file = SgxFile::open(EncryptionType::FILE_NAME).unwrap();

        let mut data = Vec::new();
        file.read_to_end(&mut data);

        let helper = DeSerializeHelper::<EncryptionType>::new(data);

        let d=match helper.decode() {
            Some(d) => d,
            None => {
                error!("Failed to decode file {}", EncryptionType::FILE_NAME);
                return false
            }
        };
        self.aes.enc=d.aes.enc;
        self.aes.prf=d.aes.prf;
        self.hmacsha1.mac=d.hmacsha1.mac;

        return true
    }
}