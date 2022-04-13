#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn echo_test() {
        let input = "hello!".as_bytes();
        let output: Vec<u8> = vec![0; input.len()];
        unsafe {
            let echo_out = echo(
                input.len() as u64,
                input.as_ptr() as *mut _,
                output.as_ptr() as *mut _,
            );
            assert_eq!(echo_out, input.len() as u64);
            assert_eq!(input.to_vec(), output);
        }
    }
}
