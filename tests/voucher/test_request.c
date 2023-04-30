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

#include "voucher/crypto.h"
#include "voucher/serialize.h"
#include "voucher/voucher.h"
#include "voucher/voucher_defs.h"

static struct BinaryArray test_pinned_domain_key = {};
static struct BinaryArray test_pinned_domain_cert = {};
static struct BinaryArray idevid_ca_key = {};
static struct BinaryArray idevid_ca_cert = {};
static struct BinaryArrayList *test_domain_store = NULL;
static struct BinaryArrayList *test_pinned_domain_certs = NULL;

struct BinaryArrayList *create_cert_list(void) {
  struct BinaryArrayList *certs = init_array_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 123456789,
                                  .issuer = NULL,
                                  .subject = NULL,
                                  .basic_constraints = NULL};
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

  sys_free(cert);
  sys_free(key);

  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);

  return certs;
}

static struct crypto_cert_meta create_cert_meta(void) {
  struct crypto_cert_meta meta = {.serial_number = 1,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL,
                                  .basic_constraints = "CA:false"};

  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, "C", "IE");
  push_keyvalue_list(meta.issuer, "CN", "pledge-voucher-issuer.info");

  push_keyvalue_list(meta.subject, "C", "IE");
  push_keyvalue_list(meta.subject, "CN", "pledge-voucher-subject.info");

  return meta;
}

struct BinaryArray *
create_pledge_voucher_request(char *serial_number, struct BinaryArray *nonce,
                              struct BinaryArray *registrar_tls_cert) {
  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};

  struct BinaryArrayList *certs = create_cert_list();

  struct crypto_cert_meta pledge_sign_meta = create_cert_meta();
  struct BinaryArray pledge_sign_key = {};
  struct BinaryArray pledge_sign_cert = {};
  pledge_sign_key.length =
      (size_t)crypto_generate_eckey(&pledge_sign_key.array);
  pledge_sign_cert.length = (size_t)crypto_generate_eccert(
      &pledge_sign_meta, pledge_sign_key.array, pledge_sign_key.length,
      &pledge_sign_cert.array);

  // Generate the test intermediate certificate
  struct crypto_cert_meta intermediate_meta = {.serial_number = 12345,
                                               .not_before = 0,
                                               .not_after = 1234567,
                                               .issuer = NULL,
                                               .subject = NULL,
                                               .basic_constraints = "CA:false"};

  intermediate_meta.issuer = init_keyvalue_list();
  intermediate_meta.subject = init_keyvalue_list();
  push_keyvalue_list(intermediate_meta.subject, "C", "IE");
  push_keyvalue_list(intermediate_meta.subject, "CN", "pinned-domain-cert");

  struct BinaryArray intermediate_key = {};
  struct BinaryArray intermediate_cert = {};

  intermediate_key.length =
      (size_t)crypto_generate_eckey(&intermediate_key.array);
  intermediate_cert.length = (size_t)crypto_generate_eccert(
      &intermediate_meta, intermediate_key.array, intermediate_key.length,
      &intermediate_cert.array);

  ssize_t length =
      crypto_sign_cert(intermediate_key.array, intermediate_key.length,
                       intermediate_cert.array, intermediate_cert.length,
                       pledge_sign_cert.length, &pledge_sign_cert.array);
  assert_true(length > 0);
  assert_non_null(pledge_sign_cert.array);
  pledge_sign_cert.length = length;

  push_array_list(certs, intermediate_cert.array, intermediate_cert.length, 0);

  struct BinaryArray *cms = sign_pledge_voucher_request(
      &created_on, serial_number, nonce, registrar_tls_cert, &pledge_sign_cert,
      &pledge_sign_key, certs);

  free_binary_array_content(&pledge_sign_key);
  free_binary_array_content(&pledge_sign_cert);
  free_keyvalue_list(pledge_sign_meta.issuer);
  free_keyvalue_list(pledge_sign_meta.subject);

  free_binary_array_content(&intermediate_key);
  free_binary_array_content(&intermediate_cert);
  free_keyvalue_list(intermediate_meta.issuer);
  free_keyvalue_list(intermediate_meta.subject);

  free_array_list(certs);
  return cms;
}
static void test_sign_pledge_voucher_request(void **state) {
  (void)state;

  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct BinaryArray nonce = {.array = nonce_array, .length = 5};

  struct BinaryArray registrar_tls_key = {};
  struct BinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);

  struct BinaryArray *cms = create_pledge_voucher_request(
      "AA:BB:CC:DD:EE:FF", &nonce, &registrar_tls_cert);
  assert_non_null(cms);
  free_binary_array(cms);

  cms = create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", NULL,
                                      &registrar_tls_cert);
  assert_non_null(cms);
  free_binary_array(cms);

  free_binary_array_content(&registrar_tls_key);
  free_binary_array_content(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
}

struct BinaryArray *
faulty_create_pledge_voucher_request(char *serial_number,
                                     struct BinaryArray *registrar_tls_cert) {
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
  struct BinaryArray pledge_sign_key = {};
  struct BinaryArray pledge_sign_cert = {};
  pledge_sign_key.length =
      (size_t)crypto_generate_eckey(&pledge_sign_key.array);
  pledge_sign_cert.length = (size_t)crypto_generate_eccert(
      &pledge_sign_meta, pledge_sign_key.array, pledge_sign_key.length,
      &pledge_sign_cert.array);

  struct BinaryArray *cms = sign_cms_voucher(voucher_request, &pledge_sign_cert,
                                             &pledge_sign_key, NULL);

  free_binary_array_content(&pledge_sign_key);
  free_binary_array_content(&pledge_sign_cert);
  free_keyvalue_list(pledge_sign_meta.issuer);
  free_keyvalue_list(pledge_sign_meta.subject);
  free_voucher(voucher_request);
  return cms;
}

static void test_sign_voucher_request(void **state) {
  (void)state;

  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct BinaryArray nonce = {.array = nonce_array, .length = 5};
  struct BinaryArray registrar_tls_key = {};
  struct BinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);
  struct BinaryArray *pledge_voucher_request_cms =
      create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce,
                                    &registrar_tls_cert);

  assert_non_null(pledge_voucher_request_cms);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct BinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                      .length = 6};

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct BinaryArray registrar_sign_key = {};
  struct BinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  struct BinaryArray *cms = sign_voucher_request(
      pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF",
      &idevid_issuer, &registrar_tls_cert, &registrar_sign_cert,
      &registrar_sign_key, NULL, NULL, NULL);
  assert_non_null(cms);

  free_binary_array(cms);

  // Test with the wrong serial number
  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on,
                             "AA:BB:CC:DD:EE:EE", &idevid_issuer,
                             &registrar_tls_cert, &registrar_sign_cert,
                             &registrar_sign_key, NULL, NULL, NULL);
  assert_null(cms);

  // Test with the wrong registrar certificate
  struct BinaryArray wregistrar_tls_key = {};
  struct BinaryArray wregistrar_tls_cert = {};
  wregistrar_tls_key.length =
      (size_t)crypto_generate_eckey(&wregistrar_tls_key.array);
  wregistrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, wregistrar_tls_key.array, wregistrar_tls_key.length,
      &wregistrar_tls_cert.array);

  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on,
                             "AA:BB:CC:DD:EE:FF", &idevid_issuer,
                             &wregistrar_tls_cert, &registrar_sign_cert,
                             &registrar_sign_key, NULL, NULL, NULL);
  assert_null(cms);

  free_binary_array(pledge_voucher_request_cms);
  pledge_voucher_request_cms = faulty_create_pledge_voucher_request(
      "AA:BB:CC:DD:EE:FF", &registrar_tls_cert);
  cms = sign_voucher_request(pledge_voucher_request_cms, &created_on,
                             "AA:BB:CC:DD:EE:FF", &idevid_issuer,
                             &registrar_tls_cert, &registrar_sign_cert,
                             &registrar_sign_key, NULL, NULL, NULL);
  assert_null(cms);

  free_binary_array(pledge_voucher_request_cms);
  free_binary_array_content(&registrar_tls_key);
  free_binary_array_content(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
  free_binary_array_content(&wregistrar_tls_key);
  free_binary_array_content(&wregistrar_tls_cert);

  free_binary_array_content(&registrar_sign_key);
  free_binary_array_content(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);
}

struct BinaryArray *faulty_create_voucher_request(
    char *serial_number, struct BinaryArray *nonce,
    struct BinaryArray *prior_signed_voucher_request) {
  (void)nonce;
  struct Voucher *voucher_request = init_voucher();

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 9};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct BinaryArray idevid_issuer = {.array = idevid_issuer_array,
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
  struct BinaryArray registrar_sign_key = {};
  struct BinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  struct BinaryArray *cms = sign_cms_voucher(
      voucher_request, &registrar_sign_cert, &registrar_sign_key, NULL);

  free_binary_array_content(&registrar_sign_key);
  free_binary_array_content(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);
  free_voucher(voucher_request);
  return cms;
}

int voucher_req_fun(const char *serial_number,
                    const struct BinaryArrayList *additional_registrar_certs,
                    const void *user_ctx,
                    struct BinaryArray *pinned_domain_cert) {
  (void)serial_number;
  (void)additional_registrar_certs;

  assert_string_equal(serial_number, (char *)user_ctx);

  copy_binary_array(pinned_domain_cert, &test_pinned_domain_cert);

  return 0;
}

static void test_sign_masa_pledge_voucher(void **state) {
  (void)state;

  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct BinaryArray nonce = {.array = nonce_array, .length = 5};
  struct BinaryArray registrar_tls_key = {};
  struct BinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = create_cert_meta();
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);
  struct BinaryArray *pledge_voucher_request_cms =
      create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce,
                                    &registrar_tls_cert);

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct BinaryArray registrar_sign_key = {};
  struct BinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct BinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                      .length = 6};

  struct BinaryArray *voucher_request_cms = sign_voucher_request(
      pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF",
      &idevid_issuer, &registrar_tls_cert, &registrar_sign_cert,
      &registrar_sign_key, NULL, NULL, NULL);

  struct crypto_cert_meta masa_sign_meta = create_cert_meta();
  struct BinaryArray masa_sign_key = {};
  struct BinaryArray masa_sign_cert = {};
  masa_sign_key.length = (size_t)crypto_generate_eckey(&masa_sign_key.array);
  masa_sign_cert.length = (size_t)crypto_generate_eccert(
      &masa_sign_meta, masa_sign_key.array, masa_sign_key.length,
      &masa_sign_cert.array);

  struct tm expires_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 11};

  // Pass in the user_ctx the serial number to compare with
  const void *user_ctx = (const void *)"AA:BB:CC:DD:EE:FF";
  struct BinaryArray *cms = sign_masa_pledge_voucher(
      voucher_request_cms, &expires_on, voucher_req_fun, user_ctx,
      &masa_sign_cert, &masa_sign_key, NULL, NULL, NULL, NULL, NULL);

  assert_non_null(cms);

  free_binary_array(cms);
  free_binary_array(voucher_request_cms);

  // Missing prior signed voucher request
  voucher_request_cms =
      faulty_create_voucher_request("AA:BB:CC:DD:EE:FF", &nonce, NULL);
  assert_non_null(voucher_request_cms);

  cms = sign_masa_pledge_voucher(voucher_request_cms, &expires_on,
                                 voucher_req_fun, user_ctx, &masa_sign_cert,
                                 &masa_sign_key, NULL, NULL, NULL, NULL, NULL);
  assert_null(cms);
  free_binary_array(voucher_request_cms);

  // Missing serial number
  voucher_request_cms =
      faulty_create_voucher_request(NULL, &nonce, pledge_voucher_request_cms);
  assert_non_null(voucher_request_cms);
  cms = sign_masa_pledge_voucher(voucher_request_cms, &expires_on,
                                 voucher_req_fun, user_ctx, &masa_sign_cert,
                                 &masa_sign_key, NULL, NULL, NULL, NULL, NULL);
  assert_null(cms);
  free_binary_array(voucher_request_cms);

  // Wrong serial number
  voucher_request_cms = faulty_create_voucher_request(
      "AA:BB:CC:DD:EE:EE", &nonce, pledge_voucher_request_cms);
  assert_non_null(voucher_request_cms);
  cms = sign_masa_pledge_voucher(voucher_request_cms, &expires_on,
                                 voucher_req_fun, user_ctx, &masa_sign_cert,
                                 &masa_sign_key, NULL, NULL, NULL, NULL, NULL);
  assert_null(cms);
  free_binary_array(voucher_request_cms);

  free_binary_array(pledge_voucher_request_cms);
  free_binary_array_content(&registrar_tls_key);
  free_binary_array_content(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);

  free_binary_array_content(&registrar_sign_key);
  free_binary_array_content(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);

  free_binary_array_content(&masa_sign_key);
  free_binary_array_content(&masa_sign_cert);
  free_keyvalue_list(masa_sign_meta.issuer);
  free_keyvalue_list(masa_sign_meta.subject);
}

static struct BinaryArray *
create_masa_pledge_voucher(struct BinaryArray *registrar_tls_cert) {
  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  struct BinaryArray nonce = {.array = nonce_array, .length = 5};
  struct BinaryArray *pledge_voucher_request_cms =
      create_pledge_voucher_request("AA:BB:CC:DD:EE:FF", &nonce,
                                    registrar_tls_cert);

  struct tm created_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 10};
  uint8_t idevid_issuer_array[] = {1, 2, 3, 4, 5, 6};
  struct BinaryArray idevid_issuer = {.array = idevid_issuer_array,
                                      .length = 6};

  struct crypto_cert_meta registrar_sign_meta = create_cert_meta();
  struct BinaryArray registrar_sign_key = {};
  struct BinaryArray registrar_sign_cert = {};
  registrar_sign_key.length =
      (size_t)crypto_generate_eckey(&registrar_sign_key.array);
  registrar_sign_cert.length = (size_t)crypto_generate_eccert(
      &registrar_sign_meta, registrar_sign_key.array, registrar_sign_key.length,
      &registrar_sign_cert.array);

  struct BinaryArray *voucher_request_cms = sign_voucher_request(
      pledge_voucher_request_cms, &created_on, "AA:BB:CC:DD:EE:FF",
      &idevid_issuer, registrar_tls_cert, &registrar_sign_cert,
      &registrar_sign_key, NULL, NULL, NULL);

  struct tm expires_on = {.tm_year = 73,
                          .tm_mon = 10,
                          .tm_mday = 29,
                          .tm_hour = 21,
                          .tm_min = 33,
                          .tm_sec = 11};
  struct crypto_cert_meta masa_sign_meta = create_cert_meta();
  struct BinaryArray masa_sign_key = {};
  struct BinaryArray masa_sign_cert = {};
  masa_sign_key.length = (size_t)crypto_generate_eckey(&masa_sign_key.array);
  masa_sign_cert.length = (size_t)crypto_generate_eccert(
      &masa_sign_meta, masa_sign_key.array, masa_sign_key.length,
      &masa_sign_cert.array);

  const void *user_ctx = (const void *)"AA:BB:CC:DD:EE:FF";
  struct BinaryArray *cms = sign_masa_pledge_voucher(
      voucher_request_cms, &expires_on, voucher_req_fun, user_ctx,
      &masa_sign_cert, &masa_sign_key, NULL, NULL, NULL, NULL, NULL);

  free_binary_array(voucher_request_cms);
  free_binary_array(pledge_voucher_request_cms);

  free_binary_array_content(&registrar_sign_key);
  free_binary_array_content(&registrar_sign_cert);
  free_keyvalue_list(registrar_sign_meta.issuer);
  free_keyvalue_list(registrar_sign_meta.subject);

  free_binary_array_content(&masa_sign_key);
  free_binary_array_content(&masa_sign_cert);
  free_keyvalue_list(masa_sign_meta.issuer);
  free_keyvalue_list(masa_sign_meta.subject);

  return cms;
}

static void test_verify_masa_pledge_voucher(void **state) {
  (void)state;
  struct BinaryArray registrar_tls_key = {};
  struct BinaryArray registrar_tls_cert = {};
  struct crypto_cert_meta registrar_tls_meta = {.serial_number = 12346,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};
  registrar_tls_meta.issuer = init_keyvalue_list();
  registrar_tls_meta.subject = init_keyvalue_list();
  push_keyvalue_list(registrar_tls_meta.subject, "C", "IE");
  push_keyvalue_list(registrar_tls_meta.subject, "CN", "registrar-tls-cert");

  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);

  // Sign the registrar TLS certificate with the pinned domain private key
  ssize_t signed_registrar_tls_cert_length = crypto_sign_cert(
      test_pinned_domain_key.array, test_pinned_domain_key.length,
      test_pinned_domain_cert.array, test_pinned_domain_cert.length,
      registrar_tls_cert.length, &registrar_tls_cert.array);
  assert_true(signed_registrar_tls_cert_length > 0);
  assert_non_null(registrar_tls_cert.array);
  registrar_tls_cert.length = signed_registrar_tls_cert_length;

  int verified =
      crypto_verify_cert(registrar_tls_cert.array, registrar_tls_cert.length,
                         test_pinned_domain_certs, test_domain_store);
  assert_int_equal(verified, 0);

  struct BinaryArray *masa_pledge_voucher_cms =
      create_masa_pledge_voucher(&registrar_tls_cert);

  assert_non_null(masa_pledge_voucher_cms);
  uint8_t nonce_array[] = {1, 2, 3, 4, 5};
  const struct BinaryArray nonce = {.array = nonce_array, .length = 5};
  struct BinaryArray pinned_domain_cert = {};

  verified = verify_masa_pledge_voucher(
      masa_pledge_voucher_cms, "AA:BB:CC:DD:EE:FF", &nonce, &registrar_tls_cert,
      test_domain_store, NULL, NULL, NULL, &pinned_domain_cert);

  assert_int_equal(verified, 0);
  assert_int_equal(
      compare_binary_array(&pinned_domain_cert, &test_pinned_domain_cert), 1);

  free_binary_array_content(&pinned_domain_cert);
  free_binary_array(masa_pledge_voucher_cms);
  free_binary_array_content(&registrar_tls_key);
  free_binary_array_content(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);
}

static int test_group_setup(void **state) {
  (void)state;

  // Generate ROOT CA for MASA
  idevid_ca_key.length = crypto_generate_eckey(&idevid_ca_key.array);

  struct crypto_cert_meta idevid_ca_meta = {.serial_number = 1,
                                     .not_before = 0,
                                     .not_after = 1234567,
                                     .issuer = NULL,
                                     .subject = NULL,
                                     .basic_constraints = "critical,CA:TRUE"};

  idevid_ca_meta.issuer = init_keyvalue_list();
  idevid_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(idevid_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.issuer, "CN", "catest");
  push_keyvalue_list(idevid_ca_meta.subject, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.subject, "CN", "catest");

  idevid_ca_cert.length = crypto_generate_eccert(
      &idevid_ca_meta, idevid_ca_key.array, idevid_ca_key.length, &idevid_ca_cert.array);

  // Generate the test pinned domain certificate
  struct crypto_cert_meta pinned_domain_meta = {.serial_number = 12345,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};
  pinned_domain_meta.issuer = init_keyvalue_list();
  pinned_domain_meta.subject = init_keyvalue_list();
  push_keyvalue_list(pinned_domain_meta.subject, "C", "IE");
  push_keyvalue_list(pinned_domain_meta.subject, "CN", "pinned-domain-cert");

  test_pinned_domain_key.length =
      (size_t)crypto_generate_eckey(&test_pinned_domain_key.array);
  test_pinned_domain_cert.length = (size_t)crypto_generate_eccert(
      &pinned_domain_meta, test_pinned_domain_key.array,
      test_pinned_domain_key.length, &test_pinned_domain_cert.array);

  ssize_t signed_pinned_domain_cert_length = crypto_sign_cert(
      idevid_ca_key.array, idevid_ca_key.length, idevid_ca_cert.array,
      idevid_ca_cert.length, test_pinned_domain_cert.length,
      &test_pinned_domain_cert.array);
  assert_true(signed_pinned_domain_cert_length > 0);
  assert_non_null(test_pinned_domain_cert.array);
  test_pinned_domain_cert.length = signed_pinned_domain_cert_length;

  test_domain_store = init_array_list();
  push_array_list(test_domain_store, idevid_ca_cert.array, idevid_ca_cert.length,
                  0);

  int verified = crypto_verify_cert(test_pinned_domain_cert.array,
                                    test_pinned_domain_cert.length,
                                    test_domain_store, NULL);
  assert_int_equal(verified, 0);

  test_pinned_domain_certs = init_array_list();
  push_array_list(test_pinned_domain_certs, test_pinned_domain_cert.array,
                  test_pinned_domain_cert.length, 0);

  free_keyvalue_list(pinned_domain_meta.issuer);
  free_keyvalue_list(pinned_domain_meta.subject);
  free_keyvalue_list(idevid_ca_meta.issuer);
  free_keyvalue_list(idevid_ca_meta.subject);

  return 0;
}

static int test_group_teardown(void **state) {
  (void)state;

  free_binary_array_content(&test_pinned_domain_key);
  free_binary_array_content(&test_pinned_domain_cert);
  free_binary_array_content(&idevid_ca_key);
  free_binary_array_content(&idevid_ca_cert);
  free_array_list(test_pinned_domain_certs);
  free_array_list(test_domain_store);
  return 0;
}

static void test_save_certs(void **state) {
  (void)state;

  struct crypto_cert_meta pledge_cms_meta = create_cert_meta();
  struct BinaryArray pledge_cms_key = {};
  struct BinaryArray pledge_cms_cert = {};
  pledge_cms_key.length = (size_t)crypto_generate_eckey(&pledge_cms_key.array);
  pledge_cms_cert.length = (size_t)crypto_generate_eccert(
      &pledge_cms_meta, pledge_cms_key.array, pledge_cms_key.length,
      &pledge_cms_cert.array);

  struct crypto_cert_meta idev_meta = {.serial_number = 12345,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};

  idev_meta.issuer = init_keyvalue_list();
  idev_meta.subject = init_keyvalue_list();
  push_keyvalue_list(idev_meta.subject, "C", "IE");
  push_keyvalue_list(idev_meta.subject, "CN", "idev-meta");
  push_keyvalue_list(idev_meta.subject, "serialNumber", "idev-serial12345");

  struct BinaryArray idevid_key = {};
  struct BinaryArray idevid_cert = {};
  idevid_key.length = (size_t)crypto_generate_eckey(&idevid_key.array);
  idevid_cert.length = (size_t)crypto_generate_eccert(
      &idev_meta, idevid_key.array, idevid_key.length,
      &idevid_cert.array);
  
  // Sign idevid_cert with idevid_ca
  ssize_t length =
      crypto_sign_cert(idevid_ca_key.array, idevid_ca_key.length,
                       idevid_ca_cert.array, idevid_ca_cert.length,
                       idevid_cert.length, &idevid_cert.array);
  assert_true(length > 0);
  idevid_cert.length = length;

  struct crypto_cert_meta intermediate1_meta = {.serial_number = 12345,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};

  intermediate1_meta.issuer = init_keyvalue_list();
  intermediate1_meta.subject = init_keyvalue_list();
  push_keyvalue_list(intermediate1_meta.subject, "C", "IE");
  push_keyvalue_list(intermediate1_meta.subject, "CN", "intermediate1-meta");

  struct BinaryArray intermediate1_key = {};
  struct BinaryArray intermediate1_cert = {};

  intermediate1_key.length =
      (size_t)crypto_generate_eckey(&intermediate1_key.array);
  intermediate1_cert.length = (size_t)crypto_generate_eccert(
      &intermediate1_meta, intermediate1_key.array, intermediate1_key.length,
      &intermediate1_cert.array);

  struct crypto_cert_meta intermediate2_meta = {.serial_number = 12345,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};

  intermediate2_meta.issuer = init_keyvalue_list();
  intermediate2_meta.subject = init_keyvalue_list();
  push_keyvalue_list(intermediate2_meta.subject, "C", "IE");
  push_keyvalue_list(intermediate2_meta.subject, "CN", "intermediate2-meta");

  struct BinaryArray intermediate2_key = {};
  struct BinaryArray intermediate2_cert = {};

  intermediate2_key.length =
      (size_t)crypto_generate_eckey(&intermediate2_key.array);
  intermediate2_cert.length = (size_t)crypto_generate_eccert(
      &intermediate2_meta, intermediate2_key.array, intermediate2_key.length,
      &intermediate2_cert.array);

  // Sign intermediate2 with idevid_ca
  length =
      crypto_sign_cert(idevid_ca_key.array, idevid_ca_key.length,
                       idevid_ca_cert.array, idevid_ca_cert.length,
                       intermediate2_cert.length, &intermediate2_cert.array);
  assert_true(length > 0);
  intermediate2_cert.length = length;
  
  // Sign intermediate2 with intermediate1
  length =
      crypto_sign_cert(intermediate2_key.array, intermediate2_key.length,
                       intermediate2_cert.array, intermediate2_cert.length,
                       intermediate1_cert.length, &intermediate1_cert.array);
  assert_true(length > 0);
  intermediate1_cert.length = length;

  // Sign pledge_cms with intermediate1
  length = crypto_sign_cert(intermediate1_key.array, intermediate1_key.length,
                            intermediate1_cert.array, intermediate1_cert.length,
                            pledge_cms_cert.length, &pledge_cms_cert.array);
  assert_true(length > 0);
  pledge_cms_cert.length = length;

  assert_int_equal(keybuf_to_file(&idevid_ca_key, "/tmp/idevid-ca.key"), 0);
  assert_int_equal(certbuf_to_file(&idevid_ca_cert, "/tmp/idevid-ca.crt"), 0);
  assert_int_equal(keybuf_to_file(&pledge_cms_key, "/tmp/pledge-cms.key"), 0);
  assert_int_equal(certbuf_to_file(&pledge_cms_cert, "/tmp/pledge-cms.crt"), 0);
  assert_int_equal(keybuf_to_file(&idevid_key, "/tmp/idevid.key"), 0);
  assert_int_equal(certbuf_to_file(&idevid_cert, "/tmp/idevid.crt"), 0);
  assert_int_equal(
      keybuf_to_file(&intermediate1_key, "/tmp/masa-intermediate1.key"), 0);
  assert_int_equal(
      certbuf_to_file(&intermediate1_cert, "/tmp/masa-intermediate1.crt"), 0);
  assert_int_equal(
      keybuf_to_file(&intermediate1_key, "/tmp/masa-intermediate2.key"), 0);
  assert_int_equal(
      certbuf_to_file(&intermediate1_cert, "/tmp/masa-intermediate2.crt"), 0);

  free_binary_array_content(&pledge_cms_key);
  free_binary_array_content(&pledge_cms_cert);
  free_keyvalue_list(pledge_cms_meta.issuer);
  free_keyvalue_list(pledge_cms_meta.subject);

  free_binary_array_content(&idevid_key);
  free_binary_array_content(&idevid_cert);
  free_keyvalue_list(idev_meta.issuer);
  free_keyvalue_list(idev_meta.subject);

  free_binary_array_content(&intermediate1_key);
  free_binary_array_content(&intermediate1_cert);
  free_keyvalue_list(intermediate1_meta.issuer);
  free_keyvalue_list(intermediate1_meta.subject);

  free_binary_array_content(&intermediate2_key);
  free_binary_array_content(&intermediate2_cert);
  free_keyvalue_list(intermediate2_meta.issuer);
  free_keyvalue_list(intermediate2_meta.subject);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_sign_pledge_voucher_request),
      cmocka_unit_test(test_sign_voucher_request),
      cmocka_unit_test(test_sign_masa_pledge_voucher),
      cmocka_unit_test(test_verify_masa_pledge_voucher),
      cmocka_unit_test(test_save_certs)};

  return cmocka_run_group_tests(tests, test_group_setup, test_group_teardown);
}
