use alloc::vec::Vec;
use std::collections::HashMap;
use super::QElement;

pub fn chal_gen(n: i64) -> Vec<QElement> {
    let mut challenge:Vec<QElement>=vec![];
    // let l=(n/100)*46;
    // let blocks =HashMap::new();
    let chal1=QElement{
        i: 0,
        v: 123
    };
    let chal2=QElement{
        i: 1,
        v: 123
    };
    let chal3=QElement{
        i: 2,
        v: 123
    };
    let chal4=QElement{
        i: 3,
        v: 123
    };
    challenge.push(chal1);
    challenge.push(chal2);
    challenge.push(chal3);
    challenge.push(chal4);
    challenge
}