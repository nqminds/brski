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

#include "voucher/crypto.h"
#include "voucher/keyvalue.h"

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

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN",
                     "issuertest.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN",
                     "subjecttest.info");

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

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "issuertest.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN", "subjecttest.info");

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
  struct BinaryArrayList *certs = init_array_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_eckey(&key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "issuertest.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN",
                     "subjecttest.info");

  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_eckey(&key_in_list);

  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_eccert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  sys_free(key_in_list);

  assert_int_equal(push_array_list(certs, cert_in_list, cert_in_list_length, 0),
                   0);

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

  free_array_list(certs);
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
  struct BinaryArrayList *certs = init_array_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN",
                     "issuertest.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN", "subjecttest.info");

  ssize_t cert_length = crypto_generate_rsacert(&meta, key, key_length, &cert);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_rsakey(2048, &key_in_list);
  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_rsacert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  sys_free(key_in_list);

  assert_int_equal(push_array_list(certs, cert_in_list, cert_in_list_length, 0),
                   0);

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

  free_array_list(certs);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

static void test_crypto_sign_cert(void **state) {
  (void)state;

  uint8_t *ca_key = NULL;
  ssize_t ca_key_length = crypto_generate_eckey(&ca_key);

  struct crypto_cert_meta ca_meta = {.serial_number = 1,
                                     .not_before = 0,
                                     .not_after = 1234567,
                                     .issuer = NULL,
                                     .subject = NULL,
                                     .basic_constraints = "critical,CA:TRUE"};

  ca_meta.issuer = init_keyvalue_list();
  ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(ca_meta.issuer, "C", "IE");
  push_keyvalue_list(ca_meta.issuer, "CN", "catest");
  push_keyvalue_list(ca_meta.subject, "C", "IE");
  push_keyvalue_list(ca_meta.subject, "CN", "catest");

  uint8_t *ca_cert = NULL;
  ssize_t ca_cert_length =
      crypto_generate_eccert(&ca_meta, ca_key, ca_key_length, &ca_cert);
  assert_true(ca_cert_length > 0);
  assert_non_null(ca_cert);

  uint8_t *intermediate_key = NULL;
  ssize_t intermediate_key_length = crypto_generate_eckey(&intermediate_key);

  struct crypto_cert_meta intermediate_meta = {.serial_number = 12345,
                                               .not_before = 0,
                                               .not_after = 1234567,
                                               .issuer = NULL,
                                               .subject = NULL,
                                               .basic_constraints = "CA:false"};

  intermediate_meta.issuer = init_keyvalue_list();
  intermediate_meta.subject = init_keyvalue_list();
  push_keyvalue_list(intermediate_meta.subject, "C", "IE");
  push_keyvalue_list(intermediate_meta.subject, "CN", "subjectintermediate");

  uint8_t *intermediate_cert = NULL;
  ssize_t intermediate_cert_length =
      crypto_generate_eccert(&intermediate_meta, intermediate_key,
                             intermediate_key_length, &intermediate_cert);
  assert_true(intermediate_cert_length > 0);
  assert_non_null(intermediate_cert);

  ssize_t signed_intermediate_cert_length =
      crypto_sign_cert(ca_key, ca_key_length, ca_cert, ca_cert_length,
                       intermediate_cert_length, &intermediate_cert);
  assert_true(signed_intermediate_cert_length > 0);
  assert_non_null(intermediate_cert);

  uint8_t *untrusted_key = NULL;
  ssize_t untrusted_key_length = crypto_generate_eckey(&untrusted_key);

  struct crypto_cert_meta untrusted_meta = {.serial_number = 12345,
                                            .not_before = 0,
                                            .not_after = 1234567,
                                            .issuer = NULL,
                                            .subject = NULL,
                                            .basic_constraints = "CA:false"};

  untrusted_meta.issuer = init_keyvalue_list();
  untrusted_meta.subject = init_keyvalue_list();
  push_keyvalue_list(untrusted_meta.subject, "C", "IE");
  push_keyvalue_list(untrusted_meta.subject, "CN", "subjectuntrusted");

  uint8_t *untrusted_cert = NULL;
  ssize_t untrusted_cert_length = crypto_generate_eccert(
      &untrusted_meta, untrusted_key, untrusted_key_length, &untrusted_cert);
  assert_true(untrusted_cert_length > 0);
  assert_non_null(untrusted_cert);

  ssize_t signed_untrusted_cert_length = crypto_sign_cert(
      intermediate_key, intermediate_key_length, intermediate_cert,
      signed_intermediate_cert_length, untrusted_cert_length, &untrusted_cert);
  assert_true(signed_untrusted_cert_length > 0);
  assert_non_null(untrusted_cert);

  sys_free(untrusted_key);
  sys_free(untrusted_cert);
  sys_free(intermediate_key);
  sys_free(intermediate_cert);
  sys_free(ca_key);
  sys_free(ca_cert);
  free_keyvalue_list(untrusted_meta.issuer);
  free_keyvalue_list(untrusted_meta.subject);
  free_keyvalue_list(intermediate_meta.issuer);
  free_keyvalue_list(intermediate_meta.subject);
  free_keyvalue_list(ca_meta.issuer);
  free_keyvalue_list(ca_meta.subject);
}

static void test_crypto_verify_cert(void **state) {
  (void)state;

  uint8_t *ca_key = NULL;
  ssize_t ca_key_length = crypto_generate_eckey(&ca_key);

  struct crypto_cert_meta ca_meta = {.serial_number = 1,
                                     .not_before = 0,
                                     .not_after = 1234567,
                                     .issuer = NULL,
                                     .subject = NULL,
                                     .basic_constraints = "critical,CA:TRUE"};

  ca_meta.issuer = init_keyvalue_list();
  ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(ca_meta.issuer, "C", "IE");
  push_keyvalue_list(ca_meta.issuer, "CN", "catest");
  push_keyvalue_list(ca_meta.subject, "C", "IE");
  push_keyvalue_list(ca_meta.subject, "CN", "catest");

  uint8_t *ca_cert = NULL;
  ssize_t ca_cert_length =
      crypto_generate_eccert(&ca_meta, ca_key, ca_key_length, &ca_cert);
  assert_true(ca_cert_length > 0);
  assert_non_null(ca_cert);

  uint8_t *intermediate_key = NULL;
  ssize_t intermediate_key_length = crypto_generate_eckey(&intermediate_key);

  struct crypto_cert_meta intermediate_meta = {.serial_number = 12345,
                                               .not_before = 0,
                                               .not_after = 1234567,
                                               .issuer = NULL,
                                               .subject = NULL,
                                               .basic_constraints = "CA:false"};

  intermediate_meta.issuer = init_keyvalue_list();
  intermediate_meta.subject = init_keyvalue_list();
  push_keyvalue_list(intermediate_meta.subject, "C", "IE");
  push_keyvalue_list(intermediate_meta.subject, "CN", "subjectintermediate");

  uint8_t *intermediate_cert = NULL;
  ssize_t intermediate_cert_length =
      crypto_generate_eccert(&intermediate_meta, intermediate_key,
                             intermediate_key_length, &intermediate_cert);
  assert_true(intermediate_cert_length > 0);
  assert_non_null(intermediate_cert);

  ssize_t signed_intermediate_cert_length =
      crypto_sign_cert(ca_key, ca_key_length, ca_cert, ca_cert_length,
                       intermediate_cert_length, &intermediate_cert);
  assert_true(signed_intermediate_cert_length > 0);
  assert_non_null(intermediate_cert);

  uint8_t *untrusted_key = NULL;
  ssize_t untrusted_key_length = crypto_generate_eckey(&untrusted_key);

  struct crypto_cert_meta untrusted_meta = {.serial_number = 12345,
                                            .not_before = 0,
                                            .not_after = 1234567,
                                            .issuer = NULL,
                                            .subject = NULL,
                                            .basic_constraints = "CA:false"};

  untrusted_meta.issuer = init_keyvalue_list();
  untrusted_meta.subject = init_keyvalue_list();
  push_keyvalue_list(untrusted_meta.subject, "C", "IE");
  push_keyvalue_list(untrusted_meta.subject, "CN", "subjectuntrusted");

  uint8_t *untrusted_cert = NULL;
  ssize_t untrusted_cert_length = crypto_generate_eccert(
      &untrusted_meta, untrusted_key, untrusted_key_length, &untrusted_cert);
  assert_true(untrusted_cert_length > 0);
  assert_non_null(untrusted_cert);

  ssize_t signed_untrusted_cert_length = crypto_sign_cert(
      intermediate_key, intermediate_key_length, intermediate_cert,
      signed_intermediate_cert_length, untrusted_cert_length, &untrusted_cert);
  assert_true(signed_untrusted_cert_length > 0);
  assert_non_null(untrusted_cert);

  struct BinaryArrayList *ca_certs = init_array_list();
  push_array_list(ca_certs, ca_cert, ca_cert_length, 0);

  struct BinaryArrayList *intermediate_certs = init_array_list();
  push_array_list(intermediate_certs, intermediate_cert,
                  signed_intermediate_cert_length, 0);

  int verified =
      crypto_verify_cert(untrusted_cert, signed_untrusted_cert_length,
                         intermediate_certs, ca_certs);
  assert_int_equal(verified, 0);

  verified = crypto_verify_cert(untrusted_cert, signed_untrusted_cert_length,
                                ca_certs, intermediate_certs);
  assert_int_equal(verified, -1);

  free_array_list(intermediate_certs);
  free_array_list(ca_certs);
  sys_free(untrusted_key);
  sys_free(untrusted_cert);
  sys_free(intermediate_key);
  sys_free(ca_key);
  free_keyvalue_list(untrusted_meta.issuer);
  free_keyvalue_list(untrusted_meta.subject);
  free_keyvalue_list(intermediate_meta.issuer);
  free_keyvalue_list(intermediate_meta.subject);
  free_keyvalue_list(ca_meta.issuer);
  free_keyvalue_list(ca_meta.subject);
}

static void test_crypto_sign_cms(void **state) {
  (void)state;
  uint8_t data[5] = {1, 2, 3, 4, 5};
  ssize_t data_length = 5;
  uint8_t *cms = NULL;
  uint8_t *key = NULL;
  uint8_t *cert = NULL;
  struct BinaryArrayList *certs = init_array_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  ssize_t key_length = crypto_generate_rsakey(2048, &key);
  assert_non_null(key);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "issuertest.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN", "subjecttest.info");

  ssize_t cert_length = crypto_generate_rsacert(&meta, key, key_length, &cert);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_rsakey(2048, &key_in_list);
  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_rsacert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  assert_int_equal(push_array_list(certs, cert_in_list, cert_in_list_length, 0),
                   0);

  sys_free(key_in_list);

  ssize_t length =
      crypto_sign_cms(data, data_length, NULL, 0, NULL, 0, NULL, &cms);

  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_cms(data, data_length, cert, cert_length, NULL, 0, NULL,
                           &cms);
  assert_true(length < 0);
  assert_null(cms);

  length = crypto_sign_cms(data, data_length, cert, cert_length, key,
                           key_length, NULL, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);

  cms = NULL;
  length = crypto_sign_cms(data, data_length, cert, cert_length, key,
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

  length = crypto_sign_cms(data, data_length, cert, cert_length, key,
                           key_length, certs, &cms);
  assert_true(length > 0);
  assert_non_null(cms);
  sys_free(cms);
  sys_free(key);
  sys_free(cert);

  free_array_list(certs);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

struct BinaryArrayList *create_cert_list(void) {
  struct BinaryArrayList *certs = init_array_list();
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

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "cert_list_issuer.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN", "cert_list_subject.info");

  uint8_t *cert = NULL;
  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);
  assert_non_null(cert);

  push_array_list(certs, cert, cert_length, 0);

  sys_free(key);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);

  return certs;
}

static void test_crypto_verify_cms(void **state) {
  (void)state;

  struct BinaryArrayList *certs = create_cert_list();

  char *data = "{\"ietf-voucher:voucher\":{\"created-on\":\"1973-11-29T21:33:"
               "09Z\",\"domain-cert-revocation-checks\":false}}";
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

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "issuer.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "serialNumber", "1234567890");

  ssize_t cert_length = crypto_generate_eccert(&meta, key, key_length, &cert);

  ssize_t cms_length =
      crypto_sign_eccms((uint8_t *)data, data_length, cert, cert_length, key,
                        key_length, certs, &cms);

  assert_non_null(cms);

  uint8_t *extracted_data = NULL;
  ssize_t extracted_data_legth =
      crypto_verify_cms(cms, cms_length, NULL, NULL, &extracted_data, NULL);
  assert_int_equal(extracted_data_legth, data_length);
  assert_non_null(extracted_data);

  assert_memory_equal(extracted_data, data, extracted_data_legth);

  sys_free(cms);

  cms_length = crypto_sign_cms((uint8_t *)data, data_length, cert, cert_length,
                               key, key_length, certs, &cms);

  assert_non_null(cms);

  sys_free(extracted_data);

  struct BinaryArrayList *out_certs = NULL;
  extracted_data = NULL;
  extracted_data_legth = crypto_verify_cms(cms, cms_length, NULL, NULL,
                                           &extracted_data, &out_certs);
  assert_int_equal(extracted_data_legth, data_length);
  assert_non_null(extracted_data);

  assert_memory_equal(extracted_data, data, extracted_data_legth);

  assert_non_null(out_certs);
  assert_int_equal(dl_list_len(&out_certs->list), 1);
  assert_int_equal(certs->length, out_certs->length);
  assert_memory_equal(certs->arr, out_certs->arr, out_certs->length);

  free_array_list(out_certs);

  sys_free(cms);
  sys_free(extracted_data);
  sys_free(key);
  sys_free(cert);

  free_array_list(certs);
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
      cmocka_unit_test(test_crypto_generate_rsacert),
      cmocka_unit_test(test_crypto_sign_eccms),
      cmocka_unit_test(test_crypto_sign_rsacms),
      cmocka_unit_test(test_crypto_sign_cert),
      cmocka_unit_test(test_crypto_verify_cert),
      cmocka_unit_test(test_crypto_sign_cms),
      cmocka_unit_test(test_crypto_verify_cms)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}

/*
openssl cms -sign -in message.txt -text -out out-cms.msg -signer cert.pem -inkey
private.pem -nodetach openssl cms -verify -in out-cms.msg -certfile cert.pem
-out signedtext.txt -noverify openssl cms -verify -in out-cms.msg -out
signedtext.txt -noverify

*/
