use sgx_types::*;
use std::string::String;
use std::string::ToString;

// -------------------------------------------------------------------
// Secure BN curves, security approx 2^128

const PBC_CONTEXT_FR256: u8 = 1;
const NAME_FR256: &str = "FR256";
const INIT_TEXT_FR256: &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";
const ORDER_FR256: &str =
    "115792089237314936872688561244471742058035595988840268584488757999429535617037";
const G1_FR256: &str = "ff8f256bbd48990e94d834fba52da377b4cab2d3e2a08b6828ba6631ad4d668500";
const G2_FR256 : &str = "e20543135c81c67051dc263a2bc882b838da80b05f3e1d7efa420a51f5688995e0040a12a1737c80def47c1a16a2ecc811c226c17fb61f446f3da56c420f38cc01";
const ZR_SIZE_FR256: usize = 32;
const G1_SIZE_FR256: usize = 33;
const G2_SIZE_FR256: usize = 65;
const GT_SIZE_FR256: usize = 384;

struct PBCInfo {
    context: u8, // which slot in the gluelib context table
    name: *const str,
    text: *const str,
    g1_size: usize,
    g2_size: usize,
    pairing_size: usize,
    field_size: usize,
    order: *const str,
    g1: *const str,
    g2: *const str,
}

const CURVES: &[PBCInfo] = &[PBCInfo {
    context: PBC_CONTEXT_FR256,
    name: NAME_FR256,
    text: INIT_TEXT_FR256,
    g1_size: G1_SIZE_FR256,
    g2_size: G2_SIZE_FR256,
    pairing_size: GT_SIZE_FR256,
    field_size: ZR_SIZE_FR256,
    order: ORDER_FR256,
    g1: G1_FR256,
    g2: G2_FR256,
}];

#[no_mangle]
pub extern "C" fn echo_pbc() -> sgx_status_t {
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
    sgx_status_t::SGX_SUCCESS
}

fn init_pairings() {
    for info in CURVES {
        let context = info.context as u64;
        unsafe {
            println!("Init curve {}", (*info.name).to_string());
            println!("Context: {}", context);
            println!("{}", (*info.text).to_string());

            let psize = [0u64; 4];
            let ans = cess_pbc::init_pairing(
                context,
                info.text as *mut _,
                (*info.text).len() as u64,
                psize.as_ptr() as *mut _,
            );
            println!("Ans: {}", ans);
        }
    }
}

pub fn key_gen() {
    println!("Generating Keys");
    init_pairings();
}
