use alloc::string::{String, ToString};
use std::vec::Vec;
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

#[derive(Clone)]
pub struct EncryptionType {
    pub aes: AES,
    pub hmacsha1: HMACSHA1,
}

pub trait Symmetric {
    fn symmetric_encrypt(&self, orig_data: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error>;
    fn symmetric_decrypt(&self, ciphertext: &[u8],key_type: &str) -> Result<Vec<u8>, PoDR2Error>;
    fn get_prf(&self) ->String;
}

pub trait MacHash {
    fn mac_encrypt(&self, orig_data: &[u8]) -> Result<Vec<u8>, PoDR2Error>;
}
#[derive(Clone)]
pub struct HMACSHA1 {
    pub mac: [u8; 16],
}
#[derive(Clone)]
pub struct AES {
    pub enc: [u8; 16],
    pub prf: [u8; 16],
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
        // std::str::from_utf8(&self.aes.prf.to_vec()).unwrap().to_string()
        crate::u8v_to_hexstr(&self.aes.prf.clone())
    }
}

impl MacHash for EncryptionType {
    fn mac_encrypt(&self, orig_data: &[u8]) -> Result<Vec<u8>, PoDR2Error> {
        let mut hmac = Hmac::new(Sha256::new(), &self.hmacsha1.mac);
        hmac.input(orig_data);
        Ok(hmac.result().code().to_vec())
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