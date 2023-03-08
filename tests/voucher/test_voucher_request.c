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

#include "voucher/serialize.h"
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

char *create_pledge_voucher_request(char *serial_number,
                                    struct VoucherBinaryArray *nonce,
                                    struct VoucherBinaryArray *registrar_tls_cert) {
  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};

  struct buffer_list *certs = create_cert_list();

  struct crypto_cert_meta pledge_sign_meta = create_cert_meta();
  struct VoucherBinaryArray pledge_sign_key = {};
  struct VoucherBinaryArray pledge_sign_cert = {};
  pledge_sign_key.length =
      (size_t)crypto_generate_eckey(&pledge_sign_key.array);
  pledge_sign_cert.length = (size_t)crypto_generate_eccert(
      &pledge_sign_meta, pledge_sign_key.array, pledge_sign_key.length,
      &pledge_sign_cert.array);

  char *cms = sign_pledge_voucher_request(&created_on, serial_number, nonce, registrar_tls_cert,
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

  char *cms = create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce, &registrar_tls_cert);
  assert_non_null(cms);
  sys_free(cms);

  cms = create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", NULL, &registrar_tls_cert);
  assert_non_null(cms);
  sys_free(cms);

  free_binary_array(&registrar_tls_key);
  free_binary_array(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
}

char *
faulty_create_pledge_voucher_request(char *serial_number,
                               struct VoucherBinaryArray *registrar_tls_cert) {
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
                   registrar_tls_cert);
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
  char *pledge_voucher_request_cms =
      create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce, &registrar_tls_cert);

  assert_non_null(pledge_voucher_request_cms);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
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

  char *cms = sign_voucher_request(pledge_voucher_request_cms, &created_on,
                                   "AA:BB:CC:DD:EE:FF", &idevid_issuer,
                                   &registrar_tls_cert, &registrar_sign_cert,
                                   &registrar_sign_key, NULL, NULL, NULL);
  assert_non_null(cms);

  sys_free(cms);

  /* Test with the wrong serial number */
  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on,
                             "AA:BB:CC:DD:EE:EE", &idevid_issuer,
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

  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF",
                             &idevid_issuer, &wregistrar_tls_cert,
                             &registrar_sign_cert, &registrar_sign_key, NULL,
                             NULL, NULL);
  assert_null(cms);

  sys_free(pledge_voucher_request_cms);
  pledge_voucher_request_cms =
      faulty_create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &registrar_tls_cert);
  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF",
                             &idevid_issuer, &registrar_tls_cert,
                             &registrar_sign_cert, &registrar_sign_key, NULL,
                             NULL, NULL);
  assert_null(cms);

  sys_free(pledge_voucher_request_cms);
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

int voucher_req_fun(const char *serial_number,
                              const struct buffer_list *additional_registrar_certs,
                              struct VoucherBinaryArray *pinned_domain_cert) {
  (void)serial_number;
  (void)additional_registrar_certs;

  struct crypto_cert_meta domain_meta = create_cert_meta();
  struct VoucherBinaryArray domain_key = {};
  domain_key.length =
      (size_t)crypto_generate_eckey(&domain_key.array);
  pinned_domain_cert->length = (size_t)crypto_generate_eccert(
      &domain_meta, domain_key.array, domain_key.length,
      &pinned_domain_cert->array);

  return 0;
}

char *
faulty_create_voucher_request(char *serial_number, struct VoucherBinaryArray *nonce, struct VoucherBinaryArray *prior_signed_voucher_request) {
  (void)nonce;
  struct Voucher *voucher_request = init_voucher();

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct VoucherBinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                             .length = 6};

  set_attr_voucher(voucher_request, ATTR_CREATED_ON, &created_on);
  set_attr_voucher(voucher_request, ATTR_NONCE, nonce);
  if (serial_number != NULL) {
    set_attr_voucher(voucher_request, ATTR_SERIAL_NUMBER, serial_number);
  }
  set_attr_voucher(voucher_request, ATTR_IDEVID_ISSUER, &idevid_issuer);
  if (prior_signed_voucher_request != NULL) {
    set_attr_voucher(voucher_request, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                       prior_signed_voucher_request);
  }

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct VoucherBinaryArray registrar_sign_key = {};
  struct VoucherBinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  char *cms = sign_cms_voucher(voucher_request, &registrar_sign_cert,
                               &registrar_sign_key, NULL);

  free_binary_array(&registrar_sign_key);
  free_binary_array(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);
  free_voucher(voucher_request);
  return cms;
}

static void test_sign_masa_pledge_voucher(void **state) {
  (void)state;
  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray nonce = {.array = nonce_array, .length = 5};
  struct VoucherBinaryArray registrar_tls_key = {};
  struct VoucherBinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length = (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);
  char *pledge_voucher_request_cms =
      create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce, &registrar_tls_cert);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct VoucherBinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                             .length = 6};

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct VoucherBinaryArray registrar_sign_key = {};
  struct VoucherBinaryArray registrar_sign_cert = {};
  registrar_sign_key.length = (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length =
      (size_t)crypto_generate_eccert(&registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length, &registrar_sign_cert.array);

  char *voucher_request_cms = sign_voucher_request(
      pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF", &idevid_issuer,
      &registrar_tls_cert, &registrar_sign_cert, &registrar_sign_key, NULL, NULL, NULL);

  struct tm expires_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 11};
  struct crypto_cert_meta masa_sign_meta = create_cert_meta();
  struct VoucherBinaryArray masa_sign_key = {};
  struct VoucherBinaryArray masa_sign_cert = {};
  masa_sign_key.length = (size_t)crypto_generate_eckey(&masa_sign_key.array);
  masa_sign_cert.length =
      (size_t)crypto_generate_eccert(&masa_sign_meta, masa_sign_key.array, masa_sign_key.length, &masa_sign_cert.array);

  char *cms = sign_masa_pledge_voucher(
    voucher_request_cms, &expires_on,
    voucher_req_fun,
    &masa_sign_cert,
    &masa_sign_key,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL);

  assert_non_null(cms);

  sys_free(cms);
  sys_free(voucher_request_cms);

  /* Missing prior signed voucher request */
  voucher_request_cms = faulty_create_voucher_request("AA:BB:CC:DD:EE:FF", &nonce, NULL);
  assert_non_null(voucher_request_cms);

  cms = sign_masa_pledge_voucher(
    voucher_request_cms, &expires_on,
    voucher_req_fun,
    &masa_sign_cert,
    &masa_sign_key,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL);
  assert_null(cms);
  sys_free(voucher_request_cms);

  struct VoucherBinaryArray prior_signed_voucher_request;
  prior_signed_voucher_request.length = serialize_base64str2array(
      (const uint8_t *)pledge_voucher_request_cms,
      strlen(pledge_voucher_request_cms), &prior_signed_voucher_request.array);

  /* Missing serial number */
  voucher_request_cms = faulty_create_voucher_request(NULL, &nonce, &prior_signed_voucher_request);
  assert_non_null(voucher_request_cms);
  cms = sign_masa_pledge_voucher(
    voucher_request_cms, &expires_on,
    voucher_req_fun,
    &masa_sign_cert,
    &masa_sign_key,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL);
  assert_null(cms);
  sys_free(voucher_request_cms);

  /* Wrong serial number */
  voucher_request_cms = faulty_create_voucher_request("AA:BB:CC:DD:EE:EE", &nonce, &prior_signed_voucher_request);
  assert_non_null(voucher_request_cms);
  cms = sign_masa_pledge_voucher(
    voucher_request_cms, &expires_on,
    voucher_req_fun,
    &masa_sign_cert,
    &masa_sign_key,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL);
  assert_null(cms);
  sys_free(voucher_request_cms);

  sys_free(pledge_voucher_request_cms);
  free_binary_array(&registrar_tls_key);
  free_binary_array(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);

  free_binary_array(&registrar_sign_key);
  free_binary_array(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);

  free_binary_array(&masa_sign_key);
  free_binary_array(&masa_sign_cert);
  free_keyvalue_list(masa_sign_meta.issuer);
  free_keyvalue_list(masa_sign_meta.subject);

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
