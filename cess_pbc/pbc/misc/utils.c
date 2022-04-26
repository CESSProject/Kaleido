#include <stdarg.h>
#include <stdio.h> // for vsnprintf
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // for intptr_t
#include <sgx_tgmp.h>

#include "pbc_utils.h"
#include "pbc_field.h"

#include "pbc_sgx_ext.h"

extern struct _errmsg_s errmsg;

static int pbc_msg_to_stderr = 1;

int pbc_set_msg_to_stderr(int i) {
  return pbc_msg_to_stderr = i;
}

static int out(const char *format, ...) {
  if (!pbc_msg_to_stderr) return 0;
  va_list params;

  va_start(params, format);
  // int res = vfprintf(stderr, format, params);
  int res = 1;
  va_end(params);
  return res;
}

static void print_warning(void) {
  static int first = 1;
  if (first) {
    out("*** PBC asserts enabled: potential performance penalties ***\n");
    first = 0;
  }
}

void pbc_assert(int expr, char *msg, const char *func) {
  print_warning();
  if (!expr) {
    out("PBC assert failed: %s(): %s\n", func, msg);
    abort();
  }
}

void pbc_assert_match2(element_ptr a, element_ptr b, const char *func) {
  print_warning();
  if (a->field != b->field) {
    out("PBC assert failed: %s(): field mismatch\n", func);
    abort();
  }
}

void pbc_assert_match3(element_ptr a, element_ptr b, element_ptr c,
    const char *func) {
  print_warning();
  if (a->field != b->field) {
    out("PBC assert failed: %s(): first two args field mismatch\n", func);
    abort();
  }
  if (b->field != c->field) {
    out("PBC assert failed: %s(): last two args field mismatch\n", func);
    abort();
  }
}

// Print at most the first 1024 bytes of an error message.
static void report(const char *prefix, const char *err, va_list params) {
  char msg[1024];
  int size = vsnprintf(msg, sizeof(msg), err, params);
  int index = errmsg.err_num;
  strncpy(errmsg.errs[index].msg,msg,size);
  errmsg.errs[index].size = size;
  errmsg.err_num++;
  // out("%s%s\n", prefix, msg);
}

void pbc_die(const char *err, ...) {
  va_list params;

  va_start(params, err);
  // report("fatal: ", err, params);
  va_end(params);
  // exit(128);
}

void pbc_info(const char *err, ...) {
  va_list params;

  va_start(params, err);
  // report("", err, params);
  va_end(params);
}

void pbc_warn(const char *err, ...) {
  va_list params;

  va_start(params, err);
  // report("warning: ", err, params);
  va_end(params);
}

void pbc_error(const char *err, ...) {
  va_list params;
  va_start(params, err);
  report("error: ", err, params);
  va_end(params);
}
