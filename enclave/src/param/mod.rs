pub mod podr2_commit_response;
pub mod podr2_commit_data;

pub enum podr2_status {
    PoDR2_SUCCESS                       =       0,
    PoDR2_UNEXPECTED                    =       100001,
    PoDR2_ERROR_INVALID_PARAMETER       =       100002,
    PoDR2_ERROR_OUT_OF_MEMORY           =       100003,
    PoDR2_ERROR_NOTEXIST_FILE           =       100004,
}