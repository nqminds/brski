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

/*
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

static void test_crypto_sign_eccms(void **state) {
  (void)state;
  uint8_t data[5] = {1, 2, 3, 4, 5};
  ssize_t data_length = 5;
  uint8_t *cms = NULL;
  uint8_t *key = NULL;
  uint8_t *cert = NULL;
  struct buffer_list *certs = init_buffer_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuertest.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subjecttest.info"));

  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_eckey(&key_in_list);
  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_eccert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  assert_int_equal(
      push_buffer_list(certs, cert_in_list, cert_in_list_length, 0), 0);

  ssize_t length =
      crypto_sign_eccms(data, data_length, NULL, 0, NULL, 0, NULL, &cms);

  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_eccms(data, data_length, cert, cert_length, NULL, 0,
                             NULL, &cms);
  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_eccms(data, data_length, cert, cert_length, key,
                             key_length, NULL, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);

  cms = NULL;
  length = crypto_sign_eccms(data, data_length, cert, cert_length, key,
                             key_length, certs, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  cms = NULL;
  key_length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  cert_length = crypto_generate_rsacert(&meta, key, key_length, &cert);

  length = crypto_sign_eccms(data, data_length, cert, cert_length, key,
                             key_length, certs, &cms);
  assert_true(length < 0);
  assert_null(cms);
  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  free_buffer_list(certs);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

static void test_crypto_sign_rsacms(void **state) {
  (void)state;
  uint8_t data[5] = {1, 2, 3, 4, 5};
  ssize_t data_length = 5;
  uint8_t *cms = NULL;
  uint8_t *key = NULL;
  uint8_t *cert = NULL;
  struct buffer_list *certs = init_buffer_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuertest.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subjecttest.info"));

  ssize_t cert_length = crypto_generate_rsacert(&meta, key, key_length, &cert);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_rsakey(2048, &key_in_list);
  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_rsacert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  assert_int_equal(
      push_buffer_list(certs, cert_in_list, cert_in_list_length, 0), 0);

  ssize_t length =
      crypto_sign_rsacms(data, data_length, NULL, 0, NULL, 0, NULL, &cms);

  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_rsacms(data, data_length, cert, cert_length, NULL, 0,
                              NULL, &cms);
  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_rsacms(data, data_length, cert, cert_length, key,
                              key_length, NULL, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);

  cms = NULL;
  length = crypto_sign_rsacms(data, data_length, cert, cert_length, key,
                              key_length, certs, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  cms = NULL;
  key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);

  length = crypto_sign_rsacms(data, data_length, cert, cert_length, key,
                              key_length, certs, &cms);
  assert_true(length < 0);
  assert_null(cms);
  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  free_buffer_list(certs);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}
*/

struct buffer_list *create_cert_list(void) {
  struct buffer_list *certs = init_buffer_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 123456789,
                                  .issuer = NULL,
                                  .subject = NULL};
  uint8_t *key = NULL;
  ssize_t key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("cert_list_issuer.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("cert_list_subject.info"));

  uint8_t *cert = NULL;
  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);
  assert_non_null(cert);

  push_buffer_list(certs, cert, cert_length, 0);

  sys_free(key);
  return certs;
}

static void test_crypto_verify_cms(void **state) {
  (void)state;

  struct buffer_list *certs = create_cert_list();

  char *data = "This is a message in cms";
  ssize_t data_length = strlen(data);
  uint8_t *cms = NULL;
  uint8_t *key = NULL;
  uint8_t *cert = NULL;
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuer.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subject.info"));

  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);
  // push_buffer_list(certs, cert, cert_length, 0);

  ssize_t cms_length = crypto_sign_eccms((uint8_t*)data, data_length, cert, cert_length, key, key_length, certs, &cms);
  assert_non_null(cms);

  uint8_t *extracted_data = NULL;
  ssize_t extracted_data_legth = crypto_verify_cms(cms, cms_length, NULL, NULL, &extracted_data);
  assert_int_equal(extracted_data_legth, data_length);
  assert_non_null(extracted_data);

  assert_memory_equal(extracted_data, data, extracted_data_legth);

  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  free_buffer_list(certs);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      // cmocka_unit_test(test_crypto_generate_rsakey),
      // cmocka_unit_test(test_crypto_generate_eckey),
      // cmocka_unit_test(test_crypto_eckey2context),
      // cmocka_unit_test(test_crypto_rsakey2context),
      // cmocka_unit_test(test_crypto_free_keycontext),
      // cmocka_unit_test(test_crypto_generate_eccert),
      // cmocka_unit_test(test_crypto_generate_rsacert),
      // cmocka_unit_test(test_crypto_sign_eccms),
      // cmocka_unit_test(test_crypto_sign_rsacms),
      cmocka_unit_test(test_crypto_verify_cms)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}


/*
openssl cms -sign -in message.txt -text -out out-cms.msg -signer cert.pem -inkey private.pem -nodetach
openssl cms -verify -in out-cms.msg -certfile cert.pem -out signedtext.txt -noverify
openssl cms -verify -in out-cms.msg -out signedtext.txt -noverify

*/