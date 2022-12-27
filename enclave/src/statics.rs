use std::sync::SgxMutex;

use alloc::string::String;

use crate::{Keys, podr2_pri::{self, chal_gen::ChalData}};

lazy_static! (
    pub static ref KEYS: SgxMutex<Keys> = SgxMutex::new(Keys::get_instance());
    pub static ref ENCRYPTIONTYPE: SgxMutex<podr2_pri::key_gen::EncryptionType> =
        SgxMutex::new(podr2_pri::key_gen::key_gen());
    pub static ref PAYLOAD: SgxMutex<String> = SgxMutex::new(String::new());
    pub static ref CHAL_DATA: SgxMutex<ChalData> = SgxMutex::new(ChalData::new());
);
