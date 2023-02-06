use std::sync::SgxMutex;

use alloc::string::String;

use crate::{podr2_v1_pri::{self, chal_gen::ChalData}, keys::Keys};

lazy_static! (
    pub static ref KEYS: SgxMutex<Keys> = SgxMutex::new(Keys::get_instance());
    pub static ref ENCRYPTIONTYPE: SgxMutex<podr2_v1_pri::key_gen::EncryptionType> =
        SgxMutex::new(podr2_v1_pri::key_gen::key_gen());
    pub static ref PAYLOAD: SgxMutex<String> = SgxMutex::new(String::new());
    pub static ref CHAL_DATA: SgxMutex<ChalData> = SgxMutex::new(ChalData::new());
);
