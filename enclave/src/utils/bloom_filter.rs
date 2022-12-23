use core::fmt;
use std::error::Error;

use super::arrays;
use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

pub const BLOOM_FILTER_LENGTH: usize = 256;

// TODO: Convert error to enum
#[derive(Debug)]
pub struct BloomError {
    pub message: Option<String>,
}

impl BloomError {
    fn message(&self) -> String {
        match &*self {
            BloomError {
                message: Some(message),
            } => message.clone(),
            BloomError { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for BloomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BloomFilter(#[serde(with = "arrays")] pub [u64; BLOOM_FILTER_LENGTH]);

impl BloomFilter {
    #[inline]
    pub const fn zero() -> BloomFilter {
        BloomFilter([0u64; BLOOM_FILTER_LENGTH])
    }

    pub fn insert(&mut self, elem: [u8; 256]) -> Result<(), BloomError> {
        let mut index: usize = 0;
        for value in elem {
            if value != 1 && value != 0 {
                return Err(BloomError {
                    message: Some("Failed to insert Bloom".to_string()),
                });
            }
            self.0[index] = self.0[index] + value as u64;
            index = index + 1;
        }

        Ok(())
    }

    pub fn delete(&mut self, elem: [u8; 256]) -> Result<(), BloomError> {
        let mut index: usize = 0;
        for value in elem {
            if value != 1 && value != 0 {
                return Err(BloomError {
                    message: Some("Failed to delete Bloom".to_string()),
                });
            }
            self.0[index] = self.0[index] - value as u64;
            index = index + 1;
        }

        Ok(())
    }
}

// TODO: Convert error to enum
#[derive(Debug)]
pub struct HashError {
    pub message: Option<String>,
}

impl HashError {
    fn message(&self) -> String {
        match &*self {
            HashError {
                message: Some(message),
            } => message.clone(),
            HashError { message: None } => "An unexpected error has occurred".to_string(),
        }
    }
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "arrays")] pub [u8; 64]);

impl Hash {
    pub fn binary(&self) -> Result<[u8; 256], HashError> {
        let mut elem: [u8; 256] = [0u8; 256];
        let mut index: usize = 0;
        for value in self.0.iter() {
            let binary = match value {
                b'0' => [0, 0, 0, 0],
                b'1' => [0, 0, 0, 1],
                b'2' => [0, 0, 1, 0],
                b'3' => [0, 0, 1, 1],
                b'4' => [0, 1, 0, 0],
                b'5' => [0, 1, 0, 1],
                b'6' => [0, 1, 1, 0],
                b'7' => [0, 1, 1, 1],
                b'8' => [1, 0, 0, 0],
                b'9' => [1, 0, 0, 1],
                b'a' => [1, 0, 1, 0],
                b'b' => [1, 0, 1, 1],
                b'c' => [1, 1, 0, 0],
                b'd' => [1, 1, 0, 1],
                b'e' => [1, 1, 1, 0],
                b'f' => [1, 1, 1, 1],
                _ => {
                    return Err(HashError {
                        message: Some("Binary Error".to_string()),
                    })
                }
            };

            elem[index * 4] = binary[0];
            elem[index * 4 + 1] = binary[1];
            elem[index * 4 + 2] = binary[2];
            elem[index * 4 + 3] = binary[3];

            index = index + 1;
        }
        Ok(elem)
    }
}
