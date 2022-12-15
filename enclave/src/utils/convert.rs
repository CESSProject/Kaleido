use std::{
    string::String,
};

pub fn u8v_to_hexstr(x: &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0..x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}