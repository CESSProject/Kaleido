use crate::*;
use core::convert::TryFrom;
use sgx_types::*;
use std::string::String;

#[no_mangle]
pub extern "C" fn test_pbc() -> sgx_status_t {
    println!("Hello, Testing PBC!");
    let input = "Hello!".as_bytes();
    let output = vec![0u8; input.len()];
    unsafe {
        let echo_out = cess_pbc::echo(
            input.len() as u64,
            input.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        );
        assert_eq!(echo_out, input.len() as u64);
        assert_eq!(input.to_vec(), output);
    }

    // Rust style convertion
    let mut out_str = String::from("");
    out_str += String::from_utf8(output).expect("Invalid UTF-8").as_str();

    println!("PBC Echo Output: {}", out_str);

    pbc::init_pairings();

    // -------------------------------------
    // on Secure pairings
    // test PRNG
    println!("rand Zr = {}", cess_bncurve::Zr::random().to_str());

    // Test Hash
    let h = Hash::from_vector(b" ");
    println!("hash(\"\") = {}", h.to_str());
    assert_eq!(
        h.to_str(),
        "H(36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068)"
    );
    println!("");

    // test keying...
    let (skey, pkey, sig) = pbc::key_gen();
    println!("-------RANDOM KEY-------");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(check_keying(&pkey, &sig));

    // test keying...
    let (skey, pkey, sig) = pbc::key_gen_deterministic(b"TestKey");
    println!("-------DETERMINISTIC KEY-------");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(check_keying(&pkey, &sig));

    sgx_status_t::SGX_SUCCESS
}

pub fn init_pairings() {
    let context = BN_CURVE_INFO.context as u64;
    unsafe {
        let psize = [0u64; 4];
        cess_pbc::init_pairing(
            context,
            BN_CURVE_INFO.text as *mut _,
            (*BN_CURVE_INFO.text).len() as u64,
            psize.as_ptr() as *mut _,
        );

        let mut g1 = vec![0u8; BN_CURVE_INFO.g1_size];
        hexstr_to_u8v(&(*BN_CURVE_INFO.g1), &mut g1);
        let len = cess_pbc::set_g1(context, g1.as_ptr() as *mut _);
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, BN_CURVE_INFO.g1_size as i64);

        let mut g2 = vec![0u8; BN_CURVE_INFO.g2_size];
        hexstr_to_u8v(&(*BN_CURVE_INFO.g2), &mut g2);
        let len = cess_pbc::set_g2(context, g2.as_ptr() as *mut _);
        // returns nbr bytes read, should equal length of G2
        assert_eq!(len, BN_CURVE_INFO.g2_size as i64);
    }
}

pub fn init_zr() {
    let context = BN_CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::init_Zr(
            context,
            BN_CURVE_INFO.text as *mut _,
            (*BN_CURVE_INFO.text).len() as u64,
        );
    }
}

pub fn get_zr() -> Zr {
    let context = BN_CURVE_INFO.context as u64;
    let mut zr = Zr::zero();
    unsafe {
        let len = cess_pbc::get_Zr(
            context,
            zr.base_vector().as_ptr() as *mut _,
            BN_CURVE_INFO.field_size as u64,
        );
        // returns nbr bytes read, should equal length of Zr
        assert_eq!(len, BN_CURVE_INFO.field_size as u64);
    }
    zr
}

pub fn get_g1() -> G1 {
    let context = BN_CURVE_INFO.context as u64;
    let mut g1 = G1::zero();
    unsafe {
        let len = cess_pbc::get_g1(
            context,
            g1.base_vector().as_ptr() as *mut _,
            BN_CURVE_INFO.g1_size as u64,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, BN_CURVE_INFO.g1_size as u64);
    }
    g1
}

pub fn get_g1_from_hash(h: &Hash)-> G1 {
    let context = BN_CURVE_INFO.context as u64;
    let mut g1 = G1::zero();
    unsafe {
        let len = cess_pbc::get_G1_from_hash(
            context,
            g1.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, BN_CURVE_INFO.g1_size as u64);
    }
    g1
}

pub fn get_g1_from_byte(byte:&Vec<u8>)->G1{
    let context = BN_CURVE_INFO.context as u64;
    let mut g1 = G1::zero();
    unsafe {
        let len = cess_pbc::get_G1_from_byte(
            context,
            g1.base_vector().as_ptr() as *mut _,
            byte.as_ptr() as *mut _,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, BN_CURVE_INFO.g1_size as u64);
    }
    g1
}

pub fn get_zr_from_hash(h: &Vec<u8>)->Zr{
    let context = BN_CURVE_INFO.context as u64;
    let mut zr = Zr::zero();
    unsafe {
        let len = cess_pbc::get_Zr_from_hash(
            context,
            zr.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            h.len() as u64,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, BN_CURVE_INFO.field_size as u64);
    }
    zr
}

pub fn g1_pow_zn(g1:&G1,zr:&Zr){
    let context = BN_CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::exp_G1z(
            context,
            g1.base_vector().as_ptr() as *mut _,
            zr.base_vector().as_ptr() as *mut _,
        );
    }
}

pub fn g1_mul_g1(g1_f:&G1,g1_s:&G1){
    let context = BN_CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::mul_G1_pts(
            context,
            g1_f.base_vector().as_ptr() as *mut _,
            g1_s.base_vector().as_ptr() as *mut _,
        );
    }
}

/// Generates a Randon keypair based on PBC
/// Before calling this function make sure you have initialized PBC library by calling init_pairings function
pub fn key_gen() -> (SecretKey, PublicKey, G1) {
    make_random_keys()
}

/// Generates a Randon keypair based on PBC
/// Before calling this function make sure you have initialized PBC library by calling init_pairings function
pub fn key_gen_deterministic(seed: &[u8]) -> (SecretKey, PublicKey, G1) {
    make_deterministic_keys(&seed)
}
