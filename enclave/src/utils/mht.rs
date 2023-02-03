use alloc::string::{String, ToString};
use alloc::vec::Vec;
use merkletree::merkle::MerkleTree;
use sgx_tcrypto::rsgx_sha256_slice;
use merkletree_generator::Sha256Algorithm;

#[derive(Debug)]
pub struct MhtError {
    pub message: Option<String>,
}
pub const HASH_SIZE: usize = 32;
#[derive(Copy, Clone)]
pub struct Hash([u8; HASH_SIZE]);

pub fn get_mht_root(
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<Vec<u8>, MhtError> {
    // Generate MHT
    let tree: MerkleTree<[u8; 32], Sha256Algorithm> = match get_mht(data, n_blocks) {
        Ok(tree)=>tree,
        Err(e)=>
        return Err(e)
    };

    //get sha256
    let root_hash = match rsgx_sha256_slice(&tree.root().as_slice()){
        Ok(h) => h,
        Err(e) => {
            return Err(MhtError {
                message: Some("Sha256 hash failed while generating MTH root".to_string()),
            })
        }
    };

    Ok(root_hash.to_vec())
}

// Generate MHT
pub fn get_mht(
    data: &mut Vec<u8>,
    n_blocks: usize,
) -> Result<MerkleTree<[u8; 32], Sha256Algorithm>, MhtError> {
    let leaves_hashes = match get_mht_leaves_hashes(data, n_blocks){
        Ok(hash) =>hash,
        Err(e)=>
            return Err(e)
    };

    Ok(MerkleTree::from_data(leaves_hashes))
}

pub fn get_mht_leaves_hashes(data: &mut Vec<u8>, n_blocks: usize) -> Result<Vec<Vec<u8>>, MhtError> {
    let block_size = (data.len() as f32 / n_blocks as f32) as usize;
    let mut leaves_hashes = vec![vec![0u8; 32]; n_blocks];

    for i in 0..n_blocks {
        let mi: Vec<u8> = if i == n_blocks - 1 {
            data[i * block_size..].to_vec()
        } else {
            data[i * block_size..(i + 1) * block_size].to_vec()
        };

        let hash =match rsgx_sha256_slice(&mi){
            Ok(h) => h,
            Err(e) => {
                return Err(MhtError {
                    message: Some("Sha256 hash failed while generating MTH leaves".to_string()),
                })
            }
        };
        leaves_hashes[i] = hash.to_vec();
    }

    Ok(leaves_hashes)
}