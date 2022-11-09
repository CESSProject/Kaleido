pub mod podr2_commit_response;
pub mod podr2_commit_data;

pub enum Podr2Status {
    PoDr2Success                        =       0,
    PoDr2Unexpected                     =       100001,
    PoDr2ErrorInvalidParameter          =       100002,
    PoDr2ErrorOutOfMemory               =       100003,
    PoDr2ErrorNotexistFile              =       100004,
}