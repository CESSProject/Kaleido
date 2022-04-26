#ifndef PBC_SGX_EXT_H
#define PBC_SGX_EXT_H

#define ERROR_MSG_COUNT_MAX 128
#define ERROR_MSG_LEN_MAX 1024
#define ERROR_FUN_NAME_LEN_MAX 128

struct _err_s{
  char msg[ERROR_MSG_LEN_MAX];
  char fun_name[ERROR_FUN_NAME_LEN_MAX];
  int size;
};

struct _errmsg_s {
  struct _err_s errs[ERROR_MSG_COUNT_MAX];
  int err_num;
};

typedef struct _err_s *err_s_ptr;
typedef struct _errmsg_s *errmsg_s_ptr;

int sgx_rand(void);

/*
* used for err message output in enclave
*/
void sgx_init_errmsg(void);
errmsg_s_ptr sgx_get_errmsg(void);
void sgx_clear_errmsg(void);

#endif//PBC_SGX_EXT_H
