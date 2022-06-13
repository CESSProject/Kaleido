
// use std::hash::Hasher;
// use sgx_tcrypto::SgxShaHandle;
// use merkletree::merkle::MerkleTree;
// use merkletree::hash::Algorithm;
// use sgx_types::sgx_sha256_hash_t;

// pub struct Sha256Algorithm(sgx_sha256_hash_t);

// impl Sha256Algorithm {
//   pub fn new() -> Sha256Algorithm {
//       Sha256Algorithm(Sha3::new(Sha3Mode::Sha3_256))
//   }
// }

// impl Default for Sha256Algorithm {
//   fn default() -> Sha256Algorithm {
//       Sha256Algorithm::new()
//   }
// }

// impl Hasher for Sha256Algorithm {
//   #[inline]
//   fn write(&mut self, msg: &[u8]) {
//       self.0.input(msg)
//   }

//   #[inline]
//   fn finish(&self) -> u64 {
//       unimplemented!()
//   }
// }

// impl Algorithm<[u8; 32]> for Sha256Algorithm {
//   #[inline]
//   fn hash(&mut self) -> [u8; 32] {
//       let mut h = [0u8; 32];
//       self.0.result(&mut h);
//       h
//   }

//   #[inline]
//   fn reset(&mut self) {
//       self.0.reset();
//   }
// }

// pub fn gen_mth() {
//   let mut h1 = [0u8; 32];
//   let mut h2 = [0u8; 32];
//   let mut h3 = [0u8; 32];
//   h1[0] = 0x11;
//   h2[0] = 0x22;
//   h3[0] = 0x33;
//   let t: MerkleTree<[u8; 32], Sha256Algorithm> = MerkleTree::from_iter(vec![h1, h2, h3]);
// }