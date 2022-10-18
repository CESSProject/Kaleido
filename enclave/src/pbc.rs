use crate::*;
use core::convert::TryFrom;
use sgx_types::*;
use std::string::String;

pub fn init_pairings() {
    let context = CURVE_INFO.context as u64;
    unsafe {
        let psize = [0u64; 4];
        cess_pbc::init_pairing(
            context,
            CURVE_INFO.text as *mut _,
            (*CURVE_INFO.text).len() as u64,
            psize.as_ptr() as *mut _,
        );

        let mut g1 = vec![0u8; CURVE_INFO.g1_size];
        hexstr_to_u8v(&(*CURVE_INFO.g1), &mut g1);
        let len = cess_pbc::set_g1(context, g1.as_ptr() as *mut _);
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, CURVE_INFO.g1_size as i64);

        let mut g2 = vec![0u8; CURVE_INFO.g2_size];
        hexstr_to_u8v(&(*CURVE_INFO.g2), &mut g2);
        let len = cess_pbc::set_g2(context, g2.as_ptr() as *mut _);
        // returns nbr bytes read, should equal length of G2
        assert_eq!(len, CURVE_INFO.g2_size as i64);
    }
}

pub fn init_zr() {
    let context = CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::init_Zr(
            context,
            CURVE_INFO.text as *mut _,
            (*CURVE_INFO.text).len() as u64,
        );
    }
}

pub fn get_zr() -> Zr {
    let context = CURVE_INFO.context as u64;
    let zr = Zr::zero();
    unsafe {
        let len = cess_pbc::get_Zr(
            context,
            zr.base_vector().as_ptr() as *mut _,
            CURVE_INFO.field_size as u64,
        );
        // returns nbr bytes read, should equal length of Zr
        assert_eq!(len, CURVE_INFO.field_size as u64);
    }
    zr
}

pub fn get_g1() -> G1 {
    let context = CURVE_INFO.context as u64;
    let g1 = G1::zero();
    unsafe {
        let len = cess_pbc::get_g1(
            context,
            g1.base_vector().as_ptr() as *mut _,
            CURVE_INFO.g1_size as u64,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, CURVE_INFO.g1_size as u64);
    }
    g1
}

pub fn get_g2() -> G2 {
    let context = CURVE_INFO.context as u64;
    let g2 = G2::zero();
    unsafe {
        let len = cess_pbc::get_g2(
            context,
            g2.base_vector().as_ptr() as *mut _,
            CURVE_INFO.g2_size as u64,
        );
        // returns nbr bytes read, should equal length of G1
        assert_eq!(len, CURVE_INFO.g2_size as u64);
    }
    g2
}

pub fn get_g1_from_hash(h: &Hash)-> G1 {
    let context = CURVE_INFO.context as u64;
    let g1 = G1::zero();
    unsafe {
        cess_pbc::get_G1_from_hash(
            context,
            g1.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    g1
}

pub fn get_g1_from_byte(byte:&Vec<u8>)->G1{
    let context = CURVE_INFO.context as u64;
    let g1 = G1::zero();
    unsafe {
        cess_pbc::get_G1_from_byte(
            context,
            g1.base_vector().as_ptr() as *mut _,
            byte.as_ptr() as *mut _,
        );
    }
    g1
}

pub fn get_zr_from_hash(h: &Vec<u8>)->Zr{
    let context = CURVE_INFO.context as u64;
    let zr = Zr::zero();
    unsafe {
        cess_pbc::get_Zr_from_hash(
            context,
            zr.base_vector().as_ptr() as *mut _,
            h.as_ptr() as *mut _,
            config::HASH_SIZE as u64,
        );
    }
    zr
}

pub fn get_zr_from_byte(byte: &Vec<u8>)->Zr{
    let context = CURVE_INFO.context as u64;
    let zr = Zr::zero();
    unsafe {
        cess_pbc::get_Zr_from_byte(
            context,
            zr.base_vector().as_ptr() as *mut _,
            byte.as_ptr() as *mut _,
        );
    }
    zr
}

pub fn g1_pow_zn(g1:&G1,zr:&Zr){
    let context = CURVE_INFO.context as u64;
    //let g11 = G1::zero();
    unsafe {
        cess_pbc::exp_G1z(
            context,

            g1.base_vector().as_ptr() as *mut _,
            zr.base_vector().as_ptr() as *mut _,
        );
    }
}

// pub fn g1_pow_zn_t(g1:&G1,zr:&Zr)->G1{
//     let context = CURVE_INFO.context as u64;
//     let g11 = G1::zero();
//     unsafe {
//         cess_pbc::exp_G1z(
//             context,
//             g11.base_vector().as_ptr() as *mut _,
//             g1.base_vector().as_ptr() as *mut _,
//             zr.base_vector().as_ptr() as *mut _,
//         );
//     }
//     g11
// }

pub fn g1_mul_g1(g1_f:&G1,g1_s:&G1) {
    let context = CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::mul_G1_pts(
            context,
            g1_f.base_vector().as_ptr() as *mut _,
            g1_s.base_vector().as_ptr() as *mut _,
        );
    }
}

pub fn get_random_g1() -> G1 {
    let context = CURVE_INFO.context as u64;
    let g1 = G1::zero();
    unsafe {
        let len = cess_pbc::get_random_g1(
            context,
            g1.base_vector().as_ptr() as *mut _,
            CURVE_INFO.g1_size as u64,
        );
        // returns nbr bytes read, should equal length of G1
        //assert_eq!(len, CURVE_INFO.g1_size as u64);
    }
    g1
}

// pub fn get_byte_from_element(el_pt:&[u8],pbyte:&Vec<u8>){
//     unsafe {
//         cess_pbc::get_byte_from_element(
//             el_pt.as_ptr() as *mut _,
//             pbyte.as_ptr() as *mut _,
//         );
//     }
// }

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
