#![cfg_attr(not(target_env = "sgx"), no_std)]
pub mod config;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate sgx_serialize_derive;
extern crate sgx_serialize;

use sgx_serialize::{DeSerializable, Decoder, Encoder, Serializable};

use sgx_tcrypto::rsgx_sha256_slice;

use core::fmt;
use std::string::String;
use std::vec::Vec;

pub struct PBCInfo {
    pub context: u8, // which slot in the gluelib context table
    pub text: *const str,
    pub g1_size: usize,
    pub g2_size: usize,
    pub pairing_size: usize,
    pub field_size: usize,
    pub g1: *const str,
    pub g2: *const str,
}

pub const CURVE_INFO: PBCInfo = PBCInfo {
    context: config::PBC_CONTEXT,
    text: config::INIT_TEXT,
    g1_size: config::G1_SIZE,
    g2_size: config::G2_SIZE,
    pairing_size: config::GT_SIZE,
    field_size: config::ZR_SIZE,
    g1: config::G1,
    g2: config::G2,
};

#[derive(Copy, Clone)]
pub struct Zr([u8; config::ZR_SIZE]);

impl Serializable for Zr {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.0.len(), |s| {
            for (i, e) in self.0.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        })
    }
}

impl DeSerializable for Zr {
    fn decode<D: Decoder>(d: &mut D) -> Result<Zr, D::Error> {
        d.read_seq(|d, len| {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }
            let result = v.try_into();
            let arr: [u8; config::ZR_SIZE] = match result {
                Ok(arr) => arr,
                Err(v) => {
                    return Err(d.error(
                        format!(
                            "Expected a Vec of length {} but it was {}",
                            config::ZR_SIZE,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            Ok(Zr(arr))
        })
    }
}

impl Zr {
    pub const fn zero() -> Zr {
        Zr([0u8; config::ZR_SIZE])
    }

    pub fn random() -> Zr {
        Zr(sgx_rand::random::<[u8; config::ZR_SIZE]>())
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_str(s: &str) -> Zr {
        // result might be larger than prime order, r,
        // but will be interpreted by PBC lib as (Zr mod r).
        let mut v = [0u8; config::ZR_SIZE];
        hexstr_to_u8v(&s, &mut v);
        Zr(v)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Zr", &self.base_vector())
    }
}

impl fmt::Display for Zr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Copy, Clone)]
pub struct Hash([u8; config::HASH_SIZE]);

impl Serializable for Hash {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.0.len(), |s| {
            for (i, e) in self.0.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        })
    }
}

impl DeSerializable for Hash {
    fn decode<D: Decoder>(d: &mut D) -> Result<Hash, D::Error> {
        d.read_seq(|d, len| {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }
            let result = v.try_into();
            let arr: [u8; config::HASH_SIZE] = match result {
                Ok(arr) => arr,
                Err(v) => {
                    return Err(d.error(
                        format!(
                            "Expected a Vec of length {} but it was {}",
                            config::HASH_SIZE,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            Ok(Hash(arr))
        })
    }
}

impl Hash {
    pub fn new(hash: &[u8; 32]) -> Hash {
        Hash(*hash)
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_vector(msg: &[u8]) -> Hash {
        hash(msg)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G1([u8; config::G1_SIZE]);

impl Serializable for G1 {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.0.len(), |s| {
            for (i, e) in self.0.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        })
    }
}

impl DeSerializable for G1 {
    fn decode<D: Decoder>(d: &mut D) -> Result<G1, D::Error> {
        d.read_seq(|d, len| {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }
            let result = v.try_into();
            let arr: [u8; config::G1_SIZE] = match result {
                Ok(arr) => arr,
                Err(v) => {
                    return Err(d.error(
                        format!(
                            "Expected a Vec of length {} but it was {}",
                            config::G1_SIZE,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            Ok(G1(arr))
        })
    }
}

impl G1 {
    pub const fn zero() -> G1 {
        G1([0u8; config::G1_SIZE])
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G1", &self.base_vector())
    }
}

impl fmt::Display for G1 {
    // for display of signatures
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G2([u8; config::G2_SIZE]);

impl Serializable for G2 {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.0.len(), |s| {
            for (i, e) in self.0.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        })
    }
}

impl DeSerializable for G2 {
    fn decode<D: Decoder>(d: &mut D) -> Result<G2, D::Error> {
        d.read_seq(|d, len| {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }
            let result = v.try_into();
            let arr: [u8; config::G2_SIZE] = match result {
                Ok(arr) => arr,
                Err(v) => {
                    return Err(d.error(
                        format!(
                            "Expected a Vec of length {} but it was {}",
                            config::G2_SIZE,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            Ok(G2(arr))
        })
    }
}

impl G2 {
    pub const fn zero() -> G2 {
        G2([0u8; config::G2_SIZE])
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G2", &self.base_vector())
    }
}

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct GT([u8; config::GT_SIZE]);

impl Serializable for GT {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_seq(self.0.len(), |s| {
            for (i, e) in self.0.iter().enumerate() {
                s.emit_seq_elt(i, |s| e.encode(s))?
            }
            Ok(())
        })
    }
}

impl DeSerializable for GT {
    fn decode<D: Decoder>(d: &mut D) -> Result<GT, D::Error> {
        d.read_seq(|d, len| {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(d.read_seq_elt(i, |d| DeSerializable::decode(d))?);
            }
            let result = v.try_into();
            let arr: [u8; config::GT_SIZE] = match result {
                Ok(arr) => arr,
                Err(v) => {
                    return Err(d.error(
                        format!(
                            "Expected a Vec of length {} but it was {}",
                            config::GT_SIZE,
                            v.len()
                        )
                        .as_str(),
                    ));
                }
            };

            Ok(GT(arr))
        })
    }
}

impl GT {
    pub fn zero() -> GT {
        GT([0u8; config::GT_SIZE])
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("GT", &self.base_vector())
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone, Serializable, DeSerializable)]
pub struct SecretKey(Zr);

impl SecretKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("SKey", &self.base_vector())
    }

    pub const fn zero() -> SecretKey {
        SecretKey(Zr::zero())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone, Serializable, DeSerializable)]
pub struct PublicKey(G2);

impl PublicKey {
    pub const fn new(pkey: G2) -> PublicKey {
        PublicKey(pkey)
    }

    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("PKey", &self.base_vector())
    }

    pub const fn zero() -> PublicKey {
        PublicKey(G2::zero())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct SecretSubKey(G1);

impl SecretSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("SSubKey", &self.base_vector())
    }
}

impl fmt::Display for SecretSubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct PublicSubKey(G2);

impl PublicSubKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("PSubKey", &self.base_vector())
    }
}

impl fmt::Display for PublicSubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// ------------------------------------------------------------------------
// BLS Signature Generation & Checking

pub fn sign_hash(h: &Hash, skey: &SecretKey) -> G1 {
    // return a raw signature on a hash
    let v = G1::zero();
    unsafe {
        cess_pbc::sign_hash(
            config::PBC_CONTEXT as u64,
            v.base_vector().as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    v
}

pub fn check_hash(h: &Hash, sig: &G1, pkey: &PublicKey) -> bool {
    // check a hash with a raw signature, return t/f
    unsafe {
        0 == cess_pbc::check_signature(
            config::PBC_CONTEXT as u64,
            sig.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
            pkey.base_vector().as_ptr() as *mut _,
        )
    }
}

/// Accepts: a message to be signed and secretKey
/// Returns: signature
pub fn sign_message(msg: &[u8], skey: &SecretKey) -> G1 {
    // hash the message and form a BLS signature
    sign_hash(&Hash::from_vector(&msg), skey)
}

/// Accepts: a message, publicKey and signature
/// Returns: true if signature is valid, false otherwise
pub fn check_message(msg: &[u8], pkey: &PublicKey, sig: &G1) -> bool {
    // check the message against the BLS signature, return t/f
    check_hash(&Hash::from_vector(&msg), &sig, &pkey)
}

// ------------------------------------------------------------------
// Key Generation & Checking

pub fn make_deterministic_keys(seed: &[u8]) -> (SecretKey, PublicKey, G1) {
    let h = hash(&seed);
    let sk = [0u8; config::ZR_SIZE]; // secret keys in Zr
    let pk = [0u8; config::G2_SIZE]; // public keys in G2
    unsafe {
        cess_pbc::make_key_pair(
            config::PBC_CONTEXT as u64,
            sk.as_ptr() as *mut _,
            pk.as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    let hpk = hash(&pk);
    let skey = SecretKey(Zr(sk));
    let pkey = PublicKey(G2(pk));
    let sig = sign_hash(&hpk, &skey);
    (skey, pkey, sig)
}

pub fn check_keying(pkey: &PublicKey, sig: &G1) -> bool {
    check_hash(&hash(&pkey.base_vector()), &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey, G1) {
    make_deterministic_keys(&Zr::random().base_vector())
}

// ------------------------------------------------------------------------
// Subkey generation and Sakai-Kasahara Encryption

pub fn make_secret_subkey(skey: &SecretKey, seed: &[u8]) -> SecretSubKey {
    let h = Hash::from_vector(&seed);
    let sk = [0u8; config::G1_SIZE];
    unsafe {
        cess_pbc::make_secret_subkey(
            config::PBC_CONTEXT as u64,
            sk.as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    SecretSubKey(G1(sk))
}

pub fn make_public_subkey(pkey: &PublicKey, seed: &[u8]) -> PublicSubKey {
    let h = Hash::from_vector(&seed);
    let pk = [0u8; config::G2_SIZE];
    unsafe {
        cess_pbc::make_public_subkey(
            config::PBC_CONTEXT as u64,
            pk.as_ptr() as *mut _,
            pkey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    PublicSubKey(G2(pk))
}

// structure of a SAKKI encryption.
// ---------------------------------
// For use in UTXO's you will only want to store the
// ciphertext, cmsg, and the rval. Proper recipients
// already know their own public keys, and the IBE ID
// that was used to encrypt their payload.
// ----------------------------------
pub struct EncryptedPacket {
    pkey: PublicKey, // public key of recipient
    id: Vec<u8>,     // IBE ID
    rval: G2,        // R_val used for SAKE encryption
    cmsg: Vec<u8>,   // encrypted payload
}

pub fn ibe_encrypt(msg: &[u8], pkey: &PublicKey, id: &[u8]) -> EncryptedPacket {
    let nmsg = msg.len();

    // compute IBE public key
    let pkid = make_public_subkey(&pkey, &id);

    // compute hash of concatenated id:msg
    let mut concv = Vec::from(id);
    for b in msg.to_vec() {
        concv.push(b);
    }
    let rhash = hash(&concv);

    let rval = G2::zero();
    let pval = GT::zero();
    unsafe {
        cess_pbc::sakai_kasahara_encrypt(
            config::PBC_CONTEXT as u64,
            rval.base_vector().as_ptr() as *mut _,
            pval.base_vector().as_ptr() as *mut _,
            pkid.base_vector().as_ptr() as *mut _,
            rhash.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    // encrypt with (msg XOR H(pairing-val))
    let mut cmsg = hash_nbytes(nmsg, &pval.base_vector());
    for ix in 0..nmsg {
        cmsg[ix] ^= msg[ix];
    }
    EncryptedPacket {
        pkey: *pkey,
        id: id.to_vec(),
        rval: rval,
        cmsg: cmsg,
    }
}

pub fn ibe_decrypt(pack: &EncryptedPacket, skey: &SecretKey) -> Option<Vec<u8>> {
    let skid = make_secret_subkey(&skey, &pack.id);
    let pkid = make_public_subkey(&pack.pkey, &pack.id);
    let nmsg = pack.cmsg.len();
    let pval = GT::zero();
    unsafe {
        cess_pbc::sakai_kasahara_decrypt(
            config::PBC_CONTEXT as u64,
            pval.base_vector().as_ptr() as *mut _,
            pack.rval.base_vector().as_ptr() as *mut _,
            skid.base_vector().as_ptr() as *mut _,
        );
    }
    // decrypt using (ctxt XOR H(pairing_val))
    let mut msg = hash_nbytes(nmsg, &pval.base_vector());
    for ix in 0..nmsg {
        msg[ix] ^= pack.cmsg[ix];
    }
    // Now check that message was correctly decrypted
    // compute hash of concatenated id:msg
    let mut concv = pack.id.clone();
    for b in msg.clone() {
        concv.push(b);
    }
    let rhash = hash(&concv);
    unsafe {
        let ans = cess_pbc::sakai_kasahara_check(
            config::PBC_CONTEXT as u64,
            pack.rval.base_vector().as_ptr() as *mut _,
            pkid.base_vector().as_ptr() as *mut _,
            rhash.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
        if ans == 0 {
            Some(msg)
        } else {
            None
        }
    }
}

pub fn hash(msg: &[u8]) -> Hash {
    let result = rsgx_sha256_slice(&msg).unwrap();
    Hash(result)
}

pub fn hash_nbytes(nb: usize, msg: &[u8]) -> Vec<u8> {
    let nmsg = msg.len();
    let mut ct = nb;
    let mut ans = vec![0u8; nb];
    let mut jx = 0;
    let mut kx = 0u8;
    while ct > 0 {
        let mut inp = vec![kx];
        for ix in 0..nmsg {
            inp.push(msg[ix]);
        }
        let hash = rsgx_sha256_slice(&inp).unwrap();
        let end = if ct > config::HASH_SIZE {
            config::HASH_SIZE
        } else {
            ct
        };
        for ix in 0..end {
            ans[jx + ix] = hash[ix];
        }
        jx += end;
        ct -= end;
        kx += 1;
    }
    ans
}

pub fn hexstr_to_u8v(s: &str, x: &mut [u8]) {
    let nx = x.len();
    let mut pos = 0;
    let mut val: u8 = 0;
    let mut cct = 0;
    for c in s.chars() {
        if pos < nx {
            match c.to_digit(16) {
                Some(d) => {
                    val += d as u8;
                    cct += 1;
                    if (cct & 1) == 0 {
                        x[pos] = val;
                        pos += 1;
                        val = 0;
                    } else {
                        val <<= 4;
                    }
                }
                None => panic!("Invalid hex digit"),
            }
        } else {
            break;
        }
    }
    for ix in pos..nx {
        x[ix] = val;
        val = 0;
    }
}

pub fn u8v_to_hexstr(x: &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0..x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

pub fn u8v_to_typed_str(pref: &str, vec: &[u8]) -> String {
    // produce a type-prefixed hexnum from a byte vector
    let mut s = String::from(pref);
    s.push_str("(");
    s.push_str(&u8v_to_hexstr(&vec));
    s.push_str(")");
    s
}

pub fn u8v_from_str(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for c in s.chars() {
        v.push(c as u8);
    }
    v
}
