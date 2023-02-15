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

#include "voucher/crypto_defs.h"

static void test_crypto_generate_rsakey(void **state) {
  (void)state;
  uint8_t *key = NULL;
  ssize_t length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  assert_true(length > 0);
  sys_free(key);
}

static void test_crypto_generate_eckey(void **state) {
  (void)state;
  
  uint8_t *key = NULL;
  ssize_t length = crypto_generate_eckey(&key);
  assert_non_null(key);
  assert_true(length > 0);
  sys_free(key);
}

static void test_crypto_eckey2context(void **state) {
  (void)state;

  uint8_t *key = NULL;
  ssize_t length = crypto_generate_rsakey(2048, &key);

  CRYPTO_KEY ctx = crypto_eckey2context(key, length);
  assert_null(ctx);
  crypto_free_keycontext(ctx);
  sys_free(key);

  length = crypto_generate_eckey(&key);

  ctx = crypto_eckey2context(key, length);
  assert_non_null(ctx);
  crypto_free_keycontext(ctx);
  sys_free(key);
}

static void test_crypto_rsakey2context(void **state) {
  (void)state;

  uint8_t *key = NULL;
  ssize_t length = crypto_generate_eckey(&key);

  CRYPTO_KEY ctx = crypto_rsakey2context(key, length);
  assert_null(ctx);
  crypto_free_keycontext(ctx);
  sys_free(key);

  length = crypto_generate_rsakey(2048, &key);

  ctx = crypto_rsakey2context(key, length);
  assert_non_null(ctx);
  crypto_free_keycontext(ctx);
  sys_free(key);
}

static void test_crypto_free_keycontext(void **state) {
  (void)state;
}


int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_crypto_generate_rsakey),
    cmocka_unit_test(test_crypto_generate_eckey),
    cmocka_unit_test(test_crypto_eckey2context),
    cmocka_unit_test(test_crypto_rsakey2context),
    cmocka_unit_test(test_crypto_free_keycontext),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
