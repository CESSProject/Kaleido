use alloc::vec::Vec;
use merkletree::hash::{Algorithm, Hashable};
use sgx_tcrypto::SgxShaHandle;
use sgx_types::sgx_sha256_hash_t;
use std::hash::Hasher;
use crypto::sha3::{Sha3, Sha3Mode};
use crypto::digest::Digest;

pub struct Sha256Algorithm(Sha3);

impl Sha256Algorithm {
    pub fn new() -> Sha256Algorithm {
      Sha256Algorithm(Sha3::new(Sha3Mode::Sha3_256))
    }
}

impl Default for Sha256Algorithm {
    fn default() -> Sha256Algorithm {
      Sha256Algorithm::new()
    }
}

impl Hasher for Sha256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<[u8; 32]> for Sha256Algorithm {
    #[inline]
    fn hash(&mut self) -> [u8; 32] {
        let mut h = [0u8; 32];
        self.0.result(&mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}
