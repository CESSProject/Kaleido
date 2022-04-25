#include <stdint.h>
#include <sgx_trts.h>

#include "pbc_sgx_ext.h"

struct _errmsg_s errmsg;
errmsg_s_ptr errmsg_ptr; // allow 64 maximum error message.

int sgx_rand(){

  uint32_t val;
  sgx_read_rand((unsigned char *)&val, 4);

  return (int)(val/2.0);
}

void sgx_init_errmsg(){
  errmsg.err_num = 0;
  for(int i = 0; i < ERROR_MSG_COUNT_MAX; i++){
    for(int j = 0; j < ERROR_MSG_LEN_MAX; j++){
      errmsg.errs[i].msg[j] = '\0';
    }
    for(int j = 0; j < ERROR_FUN_NAME_LEN_MAX; j++){
      errmsg.errs[i].fun_name[j] = '\0';
    }
    errmsg.errs[i].size = 0;
  }
  errmsg_ptr = &errmsg;
}

errmsg_s_ptr sgx_get_errmsg(){
  return errmsg_ptr;
}

void sgx_clear_errmsg(){
  sgx_init_errmsg();
}
