extern crate rand;
extern crate rsa;

use core::str::FromStr;

use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec::Vec;

use self::rand::rngs::OsRng;
use self::rsa::{BigUint, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};

#[derive(Clone)]
pub struct RsaKeys {
    pub skey: RSAPrivateKey,
    pub pkey: RSAPublicKey,
}

impl RsaKeys {
    pub fn new() -> RsaKeys {
        let mut rng = OsRng;
        // let mut os_rng = sgx_rand::SgxRng::new().unwrap();
        let bits = 1024;
        let skey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pkey = skey.to_public_key();
        RsaKeys { skey, pkey }
    }
}

impl sgx_serialize::Serializable for RsaKeys {
    fn encode<S: sgx_serialize::Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let skey = self.skey.clone();
        let n = skey.n().to_string();
        let e = skey.e().to_string();
        let d = skey.d().to_string();
        let primes = skey.primes();

        s.emit_str(&n);
        s.emit_str(&e);
        s.emit_str(&d);

        s.emit_seq(primes.len(), |s| {
            primes.iter().for_each(|prime| {
                s.emit_str(&prime.to_string());
            });
            Ok(())
        });

        Ok(())
    }
}

impl sgx_serialize::DeSerializable for RsaKeys {
    fn decode<D: sgx_serialize::Decoder>(decoder: &mut D) -> Result<Self, D::Error> {
        // Ok(RsaKeys::new())
        let n = match decoder.read_str() {
            Ok(s) => BigUint::from_str(&s).unwrap(),
            Err(e) => {
                error!("Failed to Decode n");
                return Err(decoder.error("Failed to Decode n"));
            }
        };

        let e = match decoder.read_str() {
            Ok(s) => BigUint::from_str(&s).unwrap(),
            Err(e) => {
                error!("Failed to Decode e");
                return Err(decoder.error("Failed to Decode e"));
            }
        };

        let d = match decoder.read_str() {
            Ok(s) => BigUint::from_str(&s).unwrap(),
            Err(e) => {
                error!("Failed to Decode d");
                return Err(decoder.error("Failed to Decode d"));
            }
        };

        let primes: Vec<BigUint> = match decoder.read_seq(|d, len| {
            let mut primes = Vec::new();
            for i in 0..len {
                let p = match d.read_str() {
                    Ok(s) => BigUint::from_str(&s).unwrap(),
                    Err(e) => {
                        error!("Failed to Decode primes");
                        return Err(d.error("Failed to Decode primes"));
                    }
                };
                primes.push(p);
            }
            Ok(primes)
        }) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to Decode primes");
                return Err(decoder.error("Failed to Decode primes"));
            }
        };

        let skey = RSAPrivateKey::from_components(n, e, d, primes);
        let pkey = skey.to_public_key();

        Ok(RsaKeys { skey, pkey })
    }
}
