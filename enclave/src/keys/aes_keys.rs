use core::convert::TryInto;

use alloc::vec::Vec;
use secp256k1::{PublicKey, SecretKey};
use sgx_serialize::DeSerializable;

#[derive(Clone)]
pub struct AesKeys {
    pub skey: secp256k1::SecretKey,
    pub pkey: secp256k1::PublicKey,
}

impl sgx_serialize::Serializable for AesKeys {
    fn encode<S: sgx_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let skey = self.skey.serialize();
        s.emit_seq(skey.len(), |s| {
            for (i, e) in skey.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        });

        let pkey = self.pkey.serialize();
        s.emit_seq(pkey.len(), |s| {
            for (i, e) in pkey.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        });
        Ok(())
    }
}

impl sgx_serialize::DeSerializable for AesKeys {
    fn decode<D: sgx_serialize::Decoder>(d: &mut D) -> Result<Self, D::Error> {
        // TODO: Combine Secretkey and Privatekey extraction code to a single function - Code Duplication.

        let skey = match d.read_seq(|d, len| {
            let key_len = secp256k1::util::SECRET_KEY_SIZE;

            // Retrieve Secret Key
            let mut ssk = Vec::with_capacity(key_len);

            for i in 0..key_len {
                ssk.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }

            let skey_res = ssk.try_into();
            let skey_arr: [u8; secp256k1::util::SECRET_KEY_SIZE] = match skey_res {
                Ok(arr) => arr,
                Err(v) => {
                    error!(
                        "Expected a SecretKey of length {} but it was {}",
                        key_len,
                        v.len()
                    );
                    return Err(d.error(
                        format!(
                            "Expected a SecretKey of length {} but it was {}",
                            key_len,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            let skey = match SecretKey::parse(&skey_arr) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to parse SecretKey");
                    return Err(d.error("Failed to parse SecretKey"));
                }
            };

            Ok(skey)
        }) {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to Decode SecretKey");
                return Err(d.error("Failed to Decode SecretKey"));
            }
        };

        let pkey = match d.read_seq(|d, len| {
            let key_len = secp256k1::util::FULL_PUBLIC_KEY_SIZE;
            let mut spk = Vec::with_capacity(key_len);

            for i in 0..key_len {
                spk.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }

            let pkey_res = spk.try_into();
            let pkey_arr: [u8; secp256k1::util::FULL_PUBLIC_KEY_SIZE] = match pkey_res {
                Ok(arr) => arr,
                Err(v) => {
                    error!(
                        "Expected a PublicKey of length {} but it was {}",
                        key_len,
                        v.len()
                    );
                    return Err(d.error(
                        format!(
                            "Expected a PublicKey of length {} but it was {}",
                            key_len,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            let pkey = match PublicKey::parse(&pkey_arr) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to parse PublicKey");
                    return Err(d.error("Failed to parse PublicKey"));
                }
            };

            Ok(pkey)
        }) {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to Decode PublicKey");
                return Err(d.error("Failed to Decode PublicKey"));
            }
        };

        Ok(AesKeys { skey, pkey })
    }
}
