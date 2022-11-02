use crate::*;
use core::convert::TryFrom;
use sgx_trts::c_str::CString;
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

        if cess_pbc::is_pairing_symmetric(context) {
            info!("Symmetric Pairing");
        } else {
            info!("Asymmetric Pairing");
        }

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

#[allow(unused)]
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

#[allow(unused)]
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

#[allow(unused)]
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

// Set x = a * b.
#[allow(unused)]
pub fn zr_mul_mpz(a: &Zr, b: String) -> Zr {
    let context = CURVE_INFO.context as u64;
    let x = Zr::zero(); // element_t type

    let c_str = CString::new(b).expect("CString::new Failed");
    unsafe {
        cess_pbc::mul_Zr_mpz(
            context,
            x.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            c_str.as_ptr() as *mut _,
        );
    }
    x
}

#[allow(unused)]
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

#[allow(unused)]
pub fn get_g1_from_hash(h: &Hash) -> G1 {
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

#[allow(unused)]
pub fn get_g1_from_byte(byte: &Vec<u8>) -> G1 {
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

#[allow(unused)]
pub fn get_zr_from_hash(h: &Vec<u8>) -> Zr {
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

#[allow(unused)]
pub fn get_zr_from_byte(byte: &Vec<u8>) -> Zr {
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

// Set a = a + b.
#[allow(unused)]
pub fn add_zr(a: &Zr, b: &Zr) {
    let context = CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::add_Zr_vals(
            context,
            a.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
        );
    };
}

#[allow(unused)]
pub fn g1_pow_zn(g1: &G1, zr: &Zr) {
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

// Set x = a^n, that is a times a times … times a where there are n a's.
#[allow(unused)]
pub fn g1_pow_mpz(a: &G1, n: String) -> G1 {
    let context = CURVE_INFO.context as u64;
    let x = G1::zero(); // element_t type

    let c_str = CString::new(n).expect("CString::new Failed");
    unsafe {
        cess_pbc::exp_G1_mpz(
            context,
            x.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            c_str.as_ptr() as *mut _,
        );
    }
    x
}

// Set x = a * b.
#[allow(unused)]
pub fn g1_mul_mpz(a: &G1, b: String) -> G1 {
    let context = CURVE_INFO.context as u64;
    let x = G1::zero(); // element_t type

    let c_str = CString::new(b).expect("CString::new Failed");
    unsafe {
        cess_pbc::mul_G1_mpz(
            context,
            x.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            c_str.as_ptr() as *mut _,
        );
    }
    x
}

#[allow(unused)]
pub fn g1_mul_g1(g1_f: &G1, g1_s: &G1) {
    let context = CURVE_INFO.context as u64;
    unsafe {
        cess_pbc::mul_G1_pts(
            context,
            g1_f.base_vector().as_ptr() as *mut _,
            g1_s.base_vector().as_ptr() as *mut _,
        );
    }
}

#[allow(unused)]
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

#[allow(unused)]
pub fn get_G2_from_bytes(byte: &Vec<u8>) -> G2 {
    let context = CURVE_INFO.context as u64;
    let g2 = G2::zero();
    unsafe {
        cess_pbc::get_G2_from_byte(
            context,
            g2.base_vector().as_ptr() as *mut _,
            byte.as_ptr() as *mut _,
        );
    }
    g2
}

/// e(a, b) ?= e(x, y)
#[allow(unused)]
pub fn validate_bilinearity(a: G1, b: G1, x: G1, y: G2) -> bool {
    unsafe {
        0 == cess_pbc::validate_bilinearity(
            CURVE_INFO.context as u64,
            a.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _,
            x.base_vector().as_ptr() as *mut _,
            y.base_vector().as_ptr() as *mut _,
        )
    }
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
#[allow(unused)]
pub fn key_gen() -> (SecretKey, PublicKey, G1) {
    make_random_keys()
}

/// Generates a Randon keypair based on PBC
/// Before calling this function make sure you have initialized PBC library by calling init_pairings function
#[allow(unused)]
pub fn key_gen_deterministic(seed: &[u8]) -> (SecretKey, PublicKey, G1) {
    make_deterministic_keys(&seed)
}
