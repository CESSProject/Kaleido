#include <stdio.h>
#include <stdint.h> // for intptr_t
#include <stdlib.h>
#include <sgx_tgmp.h>
#include "pbc_utils.h"
#include "pbc_random.h"

#include "pbc_init_random.h"

#if HAVE_CONFIG_H
#include <config.h>
#endif

void pbc_init_random(void) {
  #ifdef DEBUG
  pbc_error("[Prober][init_random.c][16]: pbc_init_random()......");
  #endif

  // FILE *fp;
  // fp = fopen("/dev/urandom", "rb");
  // if (!fp) {
  //   pbc_warn("could not open /dev/urandom, using deterministic random number generator");
    pbc_random_set_deterministic(0);
  // } else {
  //   pbc_random_set_file("/dev/urandom");
  //   fclose(fp);
  // }
}
