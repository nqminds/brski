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
#include <unistd.h>

#include "utils/log.h"
#include "utils/os.h"

#include "voucher/crypto_defs.h"
#include "voucher/voucher.h"
#include "voucher/voucher_defs.h"
#include "voucher/voucher_request.h"

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

static struct crypto_cert_meta create_cert_meta(void) {
  struct crypto_cert_meta meta = {.serial_number = 1,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("pledge-voucher-issuer.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("pledge-voucher-subject.info"));

  return meta;
}

char *create_pledge_voucher_request(struct VoucherBinaryArray *nonce,
                                    struct VoucherBinaryArray *registrar_cert) {
  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};

  struct buffer_list *certs = create_cert_list();
  char *serial_number = "AA:BB:CC:DD:EE:FF";

  struct crypto_cert_meta pledge_sign_meta = create_cert_meta();
  struct VoucherBinaryArray pledge_sign_key = {};
  struct VoucherBinaryArray pledge_sign_cert = {};
  pledge_sign_key.length =
      (size_t)crypto_generate_eckey(&pledge_sign_key.array);
  pledge_sign_cert.length = (size_t)crypto_generate_eccert(
      &pledge_sign_meta, pledge_sign_key.array, pledge_sign_key.length,
      &pledge_sign_cert.array);

  char *cms = sign_pledge_voucher_request(&created_on, serial_number, nonce, registrar_cert,
                                          &pledge_sign_cert,
                                          &pledge_sign_key, certs);

  free_binary_array(&pledge_sign_key);
  free_binary_array(&pledge_sign_cert);
  free_keyvalue_list(pledge_sign_meta.issuer);
  free_keyvalue_list(pledge_sign_meta.subject);
  free_buffer_list(certs);
  return cms;
}
static void test_sign_pledge_voucher_request(void **state) {
  (void)state;

  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray nonce = {.array = nonce_array, .length = 5};

  struct VoucherBinaryArray registrar_tls_key = {};
  struct VoucherBinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);

  char *cms = create_pledge_voucher_request(&nonce, &registrar_tls_cert);
  assert_non_null(cms);
  sys_free(cms);

  cms = create_pledge_voucher_request(NULL, &registrar_tls_cert);
  assert_non_null(cms);
  sys_free(cms);

  free_binary_array(&registrar_tls_key);
  free_binary_array(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
}

char *
wcreate_pledge_voucher_request(struct VoucherBinaryArray *nonce,
                               struct VoucherBinaryArray *registrar_cert) {
  (void)nonce;
  char *serial_number = "AA:BB:CC:DD:EE:FF";
  struct Voucher *voucher_request = init_voucher();

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};

  set_attr_voucher(voucher_request, ATTR_CREATED_ON, &created_on);
  set_attr_voucher(voucher_request, ATTR_ASSERTION, VOUCHER_ASSERTION_VERIFIED);
  set_attr_voucher(voucher_request, ATTR_PROXIMITY_REGISTRAR_CERT,
                   registrar_cert);
  set_attr_voucher(voucher_request, ATTR_SERIAL_NUMBER, serial_number);

  struct crypto_cert_meta pledge_sign_meta = create_cert_meta();
  struct VoucherBinaryArray pledge_sign_key = {};
  struct VoucherBinaryArray pledge_sign_cert = {};
  pledge_sign_key.length =
      (size_t)crypto_generate_eckey(&pledge_sign_key.array);
  pledge_sign_cert.length = (size_t)crypto_generate_eccert(
      &pledge_sign_meta, pledge_sign_key.array, pledge_sign_key.length,
      &pledge_sign_cert.array);

  char *cms = sign_cms_voucher(voucher_request, &pledge_sign_cert,
                               &pledge_sign_key, NULL);

  free_binary_array(&pledge_sign_key);
  free_binary_array(&pledge_sign_cert);
  free_keyvalue_list(pledge_sign_meta.issuer);
  free_keyvalue_list(pledge_sign_meta.subject);
  free_voucher(voucher_request);
  return cms;
}

static void test_sign_voucher_request(void **state) {
  (void)state;

  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray nonce = {.array = nonce_array, .length = 5};
  struct VoucherBinaryArray registrar_tls_key = {};
  struct VoucherBinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);
  char *pledge_voucher_request =
      create_pledge_voucher_request(&nonce, &registrar_tls_cert);

  assert_non_null(pledge_voucher_request);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  char *serial_number = "AA:BB:CC:DD:EE:FF";
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct VoucherBinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                             .length = 6};

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct VoucherBinaryArray registrar_sign_key = {};
  struct VoucherBinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  char *cms = sign_voucher_request(pledge_voucher_request, &created_on,
                                   serial_number, &idevid_issuer,
                                   &registrar_tls_cert, &registrar_sign_cert,
                                   &registrar_sign_key, NULL, NULL, NULL);
  assert_non_null(cms);

  sys_free(cms);

  /* Test with the wrong serial number */
  char *wserial_number = "AA:BB:CC:DD:EE:EE";
  cms = sign_voucher_request(pledge_voucher_request, &created_on,
                             wserial_number, &idevid_issuer,
                             &registrar_tls_cert, &registrar_sign_cert,
                             &registrar_sign_key, NULL, NULL, NULL);
  assert_null(cms);

  /* Test with the wrong registrar certificate */
  struct VoucherBinaryArray wregistrar_tls_key = {};
  struct VoucherBinaryArray wregistrar_tls_cert = {};
  wregistrar_tls_key.length =
      (size_t)crypto_generate_eckey(&wregistrar_tls_key.array);
  wregistrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, wregistrar_tls_key.array, wregistrar_tls_key.length,
      &wregistrar_tls_cert.array);

  cms = sign_voucher_request(pledge_voucher_request, &created_on, serial_number,
                             &idevid_issuer, &wregistrar_tls_cert,
                             &registrar_sign_cert, &registrar_sign_key, NULL,
                             NULL, NULL);
  assert_null(cms);

  sys_free(pledge_voucher_request);
  pledge_voucher_request =
      wcreate_pledge_voucher_request(NULL, &registrar_tls_cert);
  cms = sign_voucher_request(pledge_voucher_request, &created_on, serial_number,
                             &idevid_issuer, &registrar_tls_cert,
                             &registrar_sign_cert, &registrar_sign_key, NULL,
                             NULL, NULL);
  assert_null(cms);

  sys_free(pledge_voucher_request);
  free_binary_array(&registrar_tls_key);
  free_binary_array(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
  free_binary_array(&wregistrar_tls_key);
  free_binary_array(&wregistrar_tls_cert);

  free_binary_array(&registrar_sign_key);
  free_binary_array(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);
}

static void test_sign_masa_pledge_voucher(void **state) {
  (void)state;
  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray nonce = {.array = nonce_array, .length = 5};
  struct VoucherBinaryArray registrar_key = {};
  struct VoucherBinaryArray registrar_cert = {};
  struct crypto_cert_meta registrar_meta = create_cert_meta();
  registrar_key.length = (size_t)crypto_generate_eckey(&registrar_key.array);
  registrar_cert.length = (size_t)crypto_generate_eccert(
      &registrar_meta, registrar_key.array, registrar_key.length,
      &registrar_cert.array);
  char *pledge_voucher_request =
      create_pledge_voucher_request(&nonce, &registrar_cert);

  assert_non_null(pledge_voucher_request);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  char *serial_number = "AA:BB:CC:DD:EE:FF";
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct VoucherBinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                             .length = 6};

  struct crypto_cert_meta meta = create_cert_meta();
  struct VoucherBinaryArray key = {};
  struct VoucherBinaryArray cert = {};
  key.length = (size_t)crypto_generate_eckey(&key.array);
  cert.length =
      (size_t)crypto_generate_eccert(&meta, key.array, key.length, &cert.array);

  char *cms = sign_voucher_request(
      pledge_voucher_request, &created_on, serial_number, &idevid_issuer,
      &registrar_cert, &cert, &key, NULL, NULL, NULL);
  assert_non_null(cms);

  sys_free(cms);
  sys_free(pledge_voucher_request);
  free_binary_array(&registrar_key);
  free_binary_array(&registrar_cert);
  free_keyvalue_list(registrar_meta.issuer);
  free_keyvalue_list(registrar_meta.subject);

  free_binary_array(&key);
  free_binary_array(&cert);
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_sign_pledge_voucher_request),
      cmocka_unit_test(test_sign_voucher_request),
      cmocka_unit_test(test_sign_masa_pledge_voucher)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
