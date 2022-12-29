use alloc::string::{String, ToString};
use alloc::vec::Vec;
// use sgx_rand;
use sgx_rand::Rng;
use std::{
    untrusted::fs,
    io::{Read, Seek, Write},
};
use param::podr2_commit_data::PoDR2Error;
pub fn write_untrusted_file(file_path: String, data_len: usize) -> bool {
    let mut data = vec![0u8; 1024];
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut data);
    let mut file = match fs::File::create(file_path.clone()) {
        Ok(f) => { f }
        Err(e) => {
            error!("Error create file {:?} fail,because :{:?}",file_path.clone(),e.to_string());
            return false;
        }
    };

    let mut total_size = 0_usize;
    let mut i = 0;
    loop {
        if i == data_len {
            break;
        }
        let write_len = match file.write(data.as_slice()) {
            Ok(l) => { l }
            Err(e) => {
                error!("Write file in {:?} fail ,because: {:?}",file_path.clone(),e.to_string());
                return false;
            }
        };
        i += 1;
        total_size += write_len;
    }

    info!("write file success, write size: {}.", total_size);
    return true;
}

pub fn read_untrusted_file(file_path: String) -> Result<(usize, Vec<u8>),PoDR2Error> {
    let mut file_data = match fs::File::open(file_path) {
        Ok(data) => data,
        Err(e) => {
            error!("Get file error :{:?}",e.to_string());
            return Err(PoDR2Error {
                message: Some("Get file error :".to_string()+&e.to_string()),
            })
        }
    };

    let file_len=match file_data.stream_len(){
        Ok(len) => {len}
        Err(e) => {
            return Err(PoDR2Error {
                message: Some("Get file length error :".to_string()+&e.to_string()),
            })
        }
    };
    if !super::enclave_mem::has_enough_mem(file_len as usize){
        return Err(PoDR2Error {
            message: Some("There are not enough space in enclave ,Enclave busy!".to_string()),
        })
    }

    let mut file_vec: Vec<u8> = Vec::new();
    let file_size = file_data.read_to_end(&mut file_vec).expect("cannot read the file");

    Ok((file_size, file_vec))
}

pub fn split_file(file_data: &Vec<u8>, block_size: usize) -> Vec<Vec<u8>> {
    let mut matrix: Vec<Vec<u8>> = vec![];
    let mut block_num = file_data.len() / block_size;
    if file_data.len()%block_size!=0{
        block_num+=1
    }
    for num in 0..block_num {
        if num == block_num - 1 {
            let mut last_chunk=file_data.clone()[num * block_size..].to_vec();
            let pad=block_size as i64 -last_chunk.len() as i64;
            if pad>0{
                let pad_data =&mut vec![0u8; pad as usize];
                last_chunk.append(pad_data);
            }
            matrix.push(last_chunk);
            continue
        }
        matrix.push(file_data.clone()[num * block_size..(num + 1) * block_size].to_vec())
    };
    matrix
}

pub fn count_file(file_data: &Vec<u8>, block_size: usize) -> usize{
    let mut block_num = file_data.len() / block_size;
    if file_data.len()%block_size!=0{
        block_num+=1
    };

    block_num
}