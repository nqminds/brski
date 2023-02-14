#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "utils/log.h"
#include "utils/os.h"

#ifdef WITH_OPENSSL
#include "voucher/crypto_openssl.h"
#elif WITH_WOLFSSL
#include "voucher/crypto_wolfssl.h"
#endif
static void test_crypto_free_keycontext(void **state) {
  (void)state;
}


int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_crypto_free_keycontext),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
