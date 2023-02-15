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

static void test_crypto_free_keycontext(void **state) { (void)state; }

static void test_crypto_generate_eccert(void **state) {
  (void)state;

  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};
  uint8_t *key = NULL;
  uint8_t *cert = NULL;

  ssize_t length = crypto_generate_eccert(&meta, NULL, 0, &cert);
  assert_int_equal(length, -1);

  ssize_t key_length = crypto_generate_eckey(&key);

  length = crypto_generate_eccert(&meta, key, key_length, &cert);
  assert_true(length > 0);
  assert_non_null(cert);
  sys_free(cert);
  sys_free(key);

  key_length = crypto_generate_rsakey(2048, &key);
  length = crypto_generate_eccert(&meta, key, key_length, &cert);
  assert_true(length < 0);
  assert_null(cert);
  sys_free(key);

  key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuertest.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subjecttest.info"));

  length = crypto_generate_eccert(&meta, key, key_length, &cert);
  assert_true(length > 0);
  assert_non_null(cert);
  sys_free(cert);
  sys_free(key);

  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

static void test_crypto_generate_rsacert(void **state) {
  (void)state;

  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};
  uint8_t *key = NULL;
  uint8_t *cert = NULL;

  ssize_t length = crypto_generate_rsacert(&meta, NULL, 0, &cert);
  assert_int_equal(length, -1);

  ssize_t key_length = crypto_generate_rsakey(2048, &key);

  length = crypto_generate_rsacert(&meta, key, key_length, &cert);
  assert_true(length > 0);
  assert_non_null(cert);
  sys_free(cert);
  sys_free(key);

  key_length = crypto_generate_eckey(&key);
  length = crypto_generate_rsacert(&meta, key, key_length, &cert);
  assert_true(length < 0);
  assert_null(cert);
  sys_free(key);

  key_length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuertest.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subjecttest.info"));

  length = crypto_generate_rsacert(&meta, key, key_length, &cert);
  assert_true(length > 0);
  assert_non_null(cert);
  sys_free(cert);
  sys_free(key);

  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
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
      cmocka_unit_test(test_crypto_generate_eccert),
      cmocka_unit_test(test_crypto_generate_rsacert)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
