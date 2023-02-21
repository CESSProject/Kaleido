use alloc::string::String;
use alloc::vec::Vec;
use sgx_tcrypto::*;
use utils;


// pub fn key_gen(cipherhex:String){
//     let mod_size: i32 = 256;
//     let exp_size: i32 = 4;
//     let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
//     let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
//     let mut e: Vec<u8> = vec![1, 0, 1];
//     let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
//     let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
//     let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
//     let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
//     let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];
//
//     let result = rsgx_create_rsa_key_pair(mod_size,
//                                           exp_size,
//                                           n.as_mut_slice(),
//                                           d.as_mut_slice(),
//                                           e.as_mut_slice(),
//                                           p.as_mut_slice(),
//                                           q.as_mut_slice(),
//                                           dmp1.as_mut_slice(),
//                                           dmq1.as_mut_slice(),
//                                           iqmp.as_mut_slice());
//     let privkey = SgxRsaPrivKey::new();
//     let pubkey = SgxRsaPubKey::new();
//     let result = pubkey.create(mod_size,
//                                exp_size,
//                                n.as_slice(),
//                                e.as_slice());
//     let result = privkey.create(mod_size,
//                                 exp_size,
//                                 e.as_slice(),
//                                 p.as_slice(),
//                                 q.as_slice(),
//                                 dmp1.as_slice(),
//                                 dmq1.as_slice(),
//                                 iqmp.as_slice());
//
//     dbg!(e.len(),n.len());
//     dbg!(utils::convert::u8v_to_hexstr(&e.clone()),utils::convert::u8v_to_hexstr(&n.clone()));
//
//
//     let mut ciphertext=vec![];
//     utils::convert::hexstr_to_u8v(&cipherhex, &mut ciphertext);
//
//     let mut plaintext: Vec<u8> = vec![0_u8; ciphertext.len()];
//     let mut plaintext_len: usize = plaintext.len();
//     let ret = privkey.decrypt_sha256(plaintext.as_mut_slice(),
//                                      &mut plaintext_len,
//                                      ciphertext.as_slice());
//     dbg!(plaintext);
//
// }
