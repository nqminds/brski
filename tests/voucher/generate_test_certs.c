#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "voucher/array.h"
#include "voucher/crypto.h"
#include "voucher/keyvalue.h"
#include "utils/log.h"

static void test_save_certs(void **state) {
  (void)state;

  static struct BinaryArray idevid_ca_key = {};
  static struct BinaryArray idevid_ca_cert = {};

  // Generate ROOT CA for MASA
  idevid_ca_key.length = crypto_generate_eckey(&idevid_ca_key.array);

  struct crypto_cert_meta idevid_ca_meta = {.serial_number = 1,
                                            .not_before = 0,
                                            .not_after = 1234567,
                                            .issuer = NULL,
                                            .subject = NULL,
                                            .basic_constraints =
                                                "critical,CA:TRUE"};

  idevid_ca_meta.issuer = init_keyvalue_list();
  idevid_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(idevid_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.issuer, "CN", "idevca");
  push_keyvalue_list(idevid_ca_meta.subject, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.subject, "CN", "idevca");

  idevid_ca_cert.length =
      crypto_generate_eccert(&idevid_ca_meta, idevid_ca_key.array,
                             idevid_ca_key.length, &idevid_ca_cert.array);

  struct crypto_cert_meta ldevid_ca_meta = {.serial_number = 1,
                                            .not_before = 0,
                                            .not_after = 1234567,
                                            .issuer = NULL,
                                            .subject = NULL,
                                            .basic_constraints =
                                                "critical,CA:TRUE"};

  ldevid_ca_meta.issuer = init_keyvalue_list();
  ldevid_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(ldevid_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(ldevid_ca_meta.issuer, "CN", "ldevid-ca");
  push_keyvalue_list(ldevid_ca_meta.subject, "C", "IE");
  push_keyvalue_list(ldevid_ca_meta.subject, "CN", "ldevid-ca");

  struct BinaryArray ldevid_ca_key = {};
  struct BinaryArray ldevid_ca_cert = {};
  ldevid_ca_key.length = (size_t)crypto_generate_eckey(&ldevid_ca_key.array);
  ldevid_ca_cert.length = (size_t)crypto_generate_eccert(
      &ldevid_ca_meta, ldevid_ca_key.array, ldevid_ca_key.length,
      &ldevid_ca_cert.array);

  struct crypto_cert_meta pledge_cms_meta = {.serial_number = 1,
                                             .not_before = 0,
                                             .not_after = 1234567,
                                             .issuer = NULL,
                                             .subject = NULL,
                                             .basic_constraints = "CA:false"};

  pledge_cms_meta.issuer = init_keyvalue_list();
  pledge_cms_meta.subject = init_keyvalue_list();
  push_keyvalue_list(pledge_cms_meta.subject, "C", "IE");
  push_keyvalue_list(pledge_cms_meta.subject, "CN", "pledge-cms-meta");

  struct BinaryArray pledge_cms_key = {};
  struct BinaryArray pledge_cms_cert = {};
  pledge_cms_key.length = (size_t)crypto_generate_eckey(&pledge_cms_key.array);
  pledge_cms_cert.length = (size_t)crypto_generate_eccert(
      &pledge_cms_meta, pledge_cms_key.array, pledge_cms_key.length,
      &pledge_cms_cert.array);

  struct crypto_cert_meta registrar_cms_meta = {.serial_number = 1,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};

  registrar_cms_meta.issuer = init_keyvalue_list();
  registrar_cms_meta.subject = init_keyvalue_list();
  push_keyvalue_list(registrar_cms_meta.subject, "C", "IE");
  push_keyvalue_list(registrar_cms_meta.subject, "CN", "registrar-cms-meta");

  struct BinaryArray registrar_cms_key = {};
  struct BinaryArray registrar_cms_cert = {};
  registrar_cms_key.length =
      (size_t)crypto_generate_eckey(&registrar_cms_key.array);
  registrar_cms_cert.length = (size_t)crypto_generate_eccert(
      &registrar_cms_meta, registrar_cms_key.array, registrar_cms_key.length,
      &registrar_cms_cert.array);

  struct crypto_cert_meta masa_cms_meta = {.serial_number = 1,
                                           .not_before = 0,
                                           .not_after = 1234567,
                                           .issuer = NULL,
                                           .subject = NULL,
                                           .basic_constraints = "CA:false"};

  masa_cms_meta.issuer = init_keyvalue_list();
  masa_cms_meta.subject = init_keyvalue_list();
  push_keyvalue_list(masa_cms_meta.subject, "C", "IE");
  push_keyvalue_list(masa_cms_meta.subject, "CN", "masa-cms-meta");

  struct BinaryArray masa_cms_key = {};
  struct BinaryArray masa_cms_cert = {};
  masa_cms_key.length = (size_t)crypto_generate_eckey(&masa_cms_key.array);
  masa_cms_cert.length =
      (size_t)crypto_generate_eccert(&masa_cms_meta, masa_cms_key.array,
                                     masa_cms_key.length, &masa_cms_cert.array);

  struct crypto_cert_meta masa_tls_ca_meta = {.serial_number = 1,
                                              .not_before = 0,
                                              .not_after = 1234567,
                                              .issuer = NULL,
                                              .subject = NULL,
                                              .basic_constraints =
                                                  "critical,CA:TRUE"};

  masa_tls_ca_meta.issuer = init_keyvalue_list();
  masa_tls_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(masa_tls_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(masa_tls_ca_meta.issuer, "CN", "masa-tls-ca");
  push_keyvalue_list(masa_tls_ca_meta.subject, "C", "IE");
  push_keyvalue_list(masa_tls_ca_meta.subject, "CN", "masa-tls-ca");

  struct BinaryArray masa_tls_ca_key = {};
  struct BinaryArray masa_tls_ca_cert = {};
  masa_tls_ca_key.length =
      (size_t)crypto_generate_eckey(&masa_tls_ca_key.array);
  masa_tls_ca_cert.length = (size_t)crypto_generate_eccert(
      &masa_tls_ca_meta, masa_tls_ca_key.array, masa_tls_ca_key.length,
      &masa_tls_ca_cert.array);

  struct crypto_cert_meta registrar_tls_ca_meta = {.serial_number = 1,
                                                   .not_before = 0,
                                                   .not_after = 1234567,
                                                   .issuer = NULL,
                                                   .subject = NULL,
                                                   .basic_constraints =
                                                       "critical,CA:TRUE"};

  registrar_tls_ca_meta.issuer = init_keyvalue_list();
  registrar_tls_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(registrar_tls_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(registrar_tls_ca_meta.issuer, "CN", "registrar-tls-ca");
  push_keyvalue_list(registrar_tls_ca_meta.subject, "C", "IE");
  push_keyvalue_list(registrar_tls_ca_meta.subject, "CN", "registrar-tls-ca");

  struct BinaryArray registrar_tls_ca_key = {};
  struct BinaryArray registrar_tls_ca_cert = {};
  registrar_tls_ca_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_ca_key.array);
  registrar_tls_ca_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_ca_meta, registrar_tls_ca_key.array,
      registrar_tls_ca_key.length, &registrar_tls_ca_cert.array);

  struct crypto_cert_meta registrar_tls_meta = {.serial_number = 12345,
                                                .not_before = 0,
                                                .not_after = 1234567,
                                                .issuer = NULL,
                                                .subject = NULL,
                                                .basic_constraints =
                                                    "CA:false"};

  registrar_tls_meta.issuer = init_keyvalue_list();
  registrar_tls_meta.subject = init_keyvalue_list();
  push_keyvalue_list(registrar_tls_meta.subject, "C", "IE");
  push_keyvalue_list(registrar_tls_meta.subject, "CN", "registrar-tls-meta");

  struct BinaryArray registrar_tls_key = {};
  struct BinaryArray registrar_tls_cert = {};
  registrar_tls_key.length =
      (size_t)crypto_generate_eckey(&registrar_tls_key.array);
  registrar_tls_cert.length = (size_t)crypto_generate_eccert(
      &registrar_tls_meta, registrar_tls_key.array, registrar_tls_key.length,
      &registrar_tls_cert.array);

  // Sign registrar_tls with tls_ca
  ssize_t length = crypto_sign_cert(
      registrar_tls_ca_key.array, registrar_tls_ca_key.length,
      registrar_tls_ca_cert.array, registrar_tls_ca_cert.length,
      registrar_tls_cert.length, &registrar_tls_cert.array);
  assert_true(length > 0);
  registrar_tls_cert.length = length;

  struct crypto_cert_meta masa_tls_meta = {.serial_number = 12345,
                                           .not_before = 0,
                                           .not_after = 1234567,
                                           .issuer = NULL,
                                           .subject = NULL,
                                           .basic_constraints = "CA:false"};

  masa_tls_meta.issuer = init_keyvalue_list();
  masa_tls_meta.subject = init_keyvalue_list();
  push_keyvalue_list(masa_tls_meta.subject, "C", "IE");
  push_keyvalue_list(masa_tls_meta.subject, "CN", "masa-tls-meta");

  struct BinaryArray masa_tls_key = {};
  struct BinaryArray masa_tls_cert = {};
  masa_tls_key.length = (size_t)crypto_generate_eckey(&masa_tls_key.array);
  masa_tls_cert.length =
      (size_t)crypto_generate_eccert(&masa_tls_meta, masa_tls_key.array,
                                     masa_tls_key.length, &masa_tls_cert.array);

  // Sign masa_tls with tls_ca
  length = crypto_sign_cert(masa_tls_ca_key.array, masa_tls_ca_key.length,
                            masa_tls_ca_cert.array, masa_tls_ca_cert.length,
                            masa_tls_cert.length, &masa_tls_cert.array);
  assert_true(length > 0);
  masa_tls_cert.length = length;

  struct crypto_cert_meta cms_ca_meta = {.serial_number = 1,
                                         .not_before = 0,
                                         .not_after = 1234567,
                                         .issuer = NULL,
                                         .subject = NULL,
                                         .basic_constraints =
                                             "critical,CA:TRUE"};

  cms_ca_meta.issuer = init_keyvalue_list();
  cms_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(cms_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(cms_ca_meta.issuer, "CN", "cms-ca");
  push_keyvalue_list(cms_ca_meta.subject, "C", "IE");
  push_keyvalue_list(cms_ca_meta.subject, "CN", "cms-ca");

  struct BinaryArray cms_ca_key = {};
  struct BinaryArray cms_ca_cert = {};
  cms_ca_key.length = (size_t)crypto_generate_eckey(&cms_ca_key.array);
  cms_ca_cert.length = (size_t)crypto_generate_eccert(
      &cms_ca_meta, cms_ca_key.array, cms_ca_key.length, &cms_ca_cert.array);

  struct crypto_cert_meta idev_meta = {.serial_number = 12345,
                                       .not_before = 0,
                                       .not_after = 1234567,
                                       .issuer = NULL,
                                       .subject = NULL,
                                       .basic_constraints = "CA:false"};

  idev_meta.issuer = init_keyvalue_list();
  idev_meta.subject = init_keyvalue_list();
  push_keyvalue_list(idev_meta.subject, "C", "IE");
  push_keyvalue_list(idev_meta.subject, "CN", "idev-meta");
  push_keyvalue_list(idev_meta.subject, "serialNumber", "idev-serial12345");

  struct BinaryArray idevid_key = {};
  struct BinaryArray idevid_cert = {};
  idevid_key.length = (size_t)crypto_generate_eckey(&idevid_key.array);
  idevid_cert.length = (size_t)crypto_generate_eccert(
      &idev_meta, idevid_key.array, idevid_key.length, &idevid_cert.array);

  // Sign idevid_cert with idevid_ca
  length = crypto_sign_cert(idevid_ca_key.array, idevid_ca_key.length,
                            idevid_ca_cert.array, idevid_ca_cert.length,
                            idevid_cert.length, &idevid_cert.array);
  assert_true(length > 0);
  idevid_cert.length = length;

  struct crypto_cert_meta int1_cms_meta = {.serial_number = 12345,
                                           .not_before = 0,
                                           .not_after = 1234567,
                                           .issuer = NULL,
                                           .subject = NULL,
                                           .basic_constraints = "CA:false"};

  int1_cms_meta.issuer = init_keyvalue_list();
  int1_cms_meta.subject = init_keyvalue_list();
  push_keyvalue_list(int1_cms_meta.subject, "C", "IE");
  push_keyvalue_list(int1_cms_meta.subject, "CN", "int1-cms");

  struct BinaryArray int1_cms_key = {};
  struct BinaryArray int1_cms_cert = {};

  int1_cms_key.length = (size_t)crypto_generate_eckey(&int1_cms_key.array);
  int1_cms_cert.length =
      (size_t)crypto_generate_eccert(&int1_cms_meta, int1_cms_key.array,
                                     int1_cms_key.length, &int1_cms_cert.array);

  struct crypto_cert_meta int2_cms_meta = {.serial_number = 12345,
                                           .not_before = 0,
                                           .not_after = 1234567,
                                           .issuer = NULL,
                                           .subject = NULL,
                                           .basic_constraints = "CA:false"};

  int2_cms_meta.issuer = init_keyvalue_list();
  int2_cms_meta.subject = init_keyvalue_list();
  push_keyvalue_list(int2_cms_meta.subject, "C", "IE");
  push_keyvalue_list(int2_cms_meta.subject, "CN", "int2-cms");

  struct BinaryArray int2_cms_key = {};
  struct BinaryArray int2_cms_cert = {};

  int2_cms_key.length = (size_t)crypto_generate_eckey(&int2_cms_key.array);
  int2_cms_cert.length =
      (size_t)crypto_generate_eccert(&int2_cms_meta, int2_cms_key.array,
                                     int2_cms_key.length, &int2_cms_cert.array);

  // Sign int2_cms with cms_ca
  length = crypto_sign_cert(cms_ca_key.array, cms_ca_key.length,
                            cms_ca_cert.array, cms_ca_cert.length,
                            int2_cms_cert.length, &int2_cms_cert.array);
  assert_true(length > 0);
  int2_cms_cert.length = length;

  // Sign int2_cms with int1_cms
  length = crypto_sign_cert(int2_cms_key.array, int2_cms_key.length,
                            int2_cms_cert.array, int2_cms_cert.length,
                            int1_cms_cert.length, &int1_cms_cert.array);
  assert_true(length > 0);
  int1_cms_cert.length = length;

  // Sign pledge_cms with int1_cms
  length = crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                            int1_cms_cert.array, int1_cms_cert.length,
                            pledge_cms_cert.length, &pledge_cms_cert.array);
  assert_true(length > 0);
  pledge_cms_cert.length = length;

  // Sign registrar_cms with int1_cms
  length =
      crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                       int1_cms_cert.array, int1_cms_cert.length,
                       registrar_cms_cert.length, &registrar_cms_cert.array);
  assert_true(length > 0);
  registrar_cms_cert.length = length;

  // Sign masa_cms with int1_cms
  length = crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                            int1_cms_cert.array, int1_cms_cert.length,
                            masa_cms_cert.length, &masa_cms_cert.array);
  assert_true(length > 0);
  masa_cms_cert.length = length;

  assert_int_equal(keybuf_to_file(&masa_tls_ca_key, "/tmp/masa-tls-ca.key"), 0);
  assert_int_equal(certbuf_to_file(&masa_tls_ca_cert, "/tmp/masa-tls-ca.crt"),
                   0);
  assert_int_equal(
      keybuf_to_file(&registrar_tls_ca_key, "/tmp/registrar-tls-ca.key"), 0);
  assert_int_equal(
      certbuf_to_file(&registrar_tls_ca_cert, "/tmp/registrar-tls-ca.crt"), 0);
  assert_int_equal(keybuf_to_file(&registrar_tls_key, "/tmp/registrar-tls.key"),
                   0);
  assert_int_equal(
      certbuf_to_file(&registrar_tls_cert, "/tmp/registrar-tls.crt"), 0);
  assert_int_equal(keybuf_to_file(&masa_tls_key, "/tmp/masa-tls.key"), 0);
  assert_int_equal(certbuf_to_file(&masa_tls_cert, "/tmp/masa-tls.crt"), 0);
  assert_int_equal(keybuf_to_file(&cms_ca_key, "/tmp/cms-ca.key"), 0);
  assert_int_equal(certbuf_to_file(&cms_ca_cert, "/tmp/cms-ca.crt"), 0);
  assert_int_equal(keybuf_to_file(&idevid_ca_key, "/tmp/idevid-ca.key"), 0);
  assert_int_equal(certbuf_to_file(&idevid_ca_cert, "/tmp/idevid-ca.crt"), 0);
  assert_int_equal(keybuf_to_file(&ldevid_ca_key, "/tmp/ldevid-ca.key"), 0);
  assert_int_equal(certbuf_to_file(&ldevid_ca_cert, "/tmp/ldevid-ca.crt"), 0);
  assert_int_equal(keybuf_to_file(&pledge_cms_key, "/tmp/pledge-cms.key"), 0);
  assert_int_equal(certbuf_to_file(&pledge_cms_cert, "/tmp/pledge-cms.crt"), 0);
  assert_int_equal(keybuf_to_file(&registrar_cms_key, "/tmp/registrar-cms.key"),
                   0);
  assert_int_equal(
      certbuf_to_file(&registrar_cms_cert, "/tmp/registrar-cms.crt"), 0);
  assert_int_equal(keybuf_to_file(&masa_cms_key, "/tmp/masa-cms.key"), 0);
  assert_int_equal(certbuf_to_file(&masa_cms_cert, "/tmp/masa-cms.crt"), 0);
  assert_int_equal(keybuf_to_file(&idevid_key, "/tmp/idevid.key"), 0);
  assert_int_equal(certbuf_to_file(&idevid_cert, "/tmp/idevid.crt"), 0);
  assert_int_equal(keybuf_to_file(&int1_cms_key, "/tmp/int1-cms.key"), 0);
  assert_int_equal(certbuf_to_file(&int1_cms_cert, "/tmp/int1-cms.crt"), 0);
  assert_int_equal(keybuf_to_file(&int2_cms_key, "/tmp/int2-cms.key"), 0);
  assert_int_equal(certbuf_to_file(&int2_cms_cert, "/tmp/int2-cms.crt"), 0);

  free_binary_array_content(&idevid_ca_key);
  free_binary_array_content(&idevid_ca_cert);
  free_keyvalue_list(idevid_ca_meta.issuer);
  free_keyvalue_list(idevid_ca_meta.subject);

  free_binary_array_content(&ldevid_ca_key);
  free_binary_array_content(&ldevid_ca_cert);
  free_keyvalue_list(ldevid_ca_meta.issuer);
  free_keyvalue_list(ldevid_ca_meta.subject);

  free_binary_array_content(&masa_tls_ca_key);
  free_binary_array_content(&masa_tls_ca_cert);
  free_keyvalue_list(masa_tls_ca_meta.issuer);
  free_keyvalue_list(masa_tls_ca_meta.subject);

  free_binary_array_content(&registrar_tls_ca_key);
  free_binary_array_content(&registrar_tls_ca_cert);
  free_keyvalue_list(registrar_tls_ca_meta.issuer);
  free_keyvalue_list(registrar_tls_ca_meta.subject);

  free_binary_array_content(&registrar_tls_key);
  free_binary_array_content(&registrar_tls_cert);
  free_keyvalue_list(registrar_tls_meta.issuer);
  free_keyvalue_list(registrar_tls_meta.subject);

  free_binary_array_content(&masa_tls_key);
  free_binary_array_content(&masa_tls_cert);
  free_keyvalue_list(masa_tls_meta.issuer);
  free_keyvalue_list(masa_tls_meta.subject);

  free_binary_array_content(&cms_ca_key);
  free_binary_array_content(&cms_ca_cert);
  free_keyvalue_list(cms_ca_meta.issuer);
  free_keyvalue_list(cms_ca_meta.subject);

  free_binary_array_content(&pledge_cms_key);
  free_binary_array_content(&pledge_cms_cert);
  free_keyvalue_list(pledge_cms_meta.issuer);
  free_keyvalue_list(pledge_cms_meta.subject);

  free_binary_array_content(&registrar_cms_key);
  free_binary_array_content(&registrar_cms_cert);
  free_keyvalue_list(registrar_cms_meta.issuer);
  free_keyvalue_list(registrar_cms_meta.subject);

  free_binary_array_content(&masa_cms_key);
  free_binary_array_content(&masa_cms_cert);
  free_keyvalue_list(masa_cms_meta.issuer);
  free_keyvalue_list(masa_cms_meta.subject);

  free_binary_array_content(&idevid_key);
  free_binary_array_content(&idevid_cert);
  free_keyvalue_list(idev_meta.issuer);
  free_keyvalue_list(idev_meta.subject);

  free_binary_array_content(&int1_cms_key);
  free_binary_array_content(&int1_cms_cert);
  free_keyvalue_list(int1_cms_meta.issuer);
  free_keyvalue_list(int1_cms_meta.subject);

  free_binary_array_content(&int2_cms_key);
  free_binary_array_content(&int2_cms_cert);
  free_keyvalue_list(int2_cms_meta.issuer);
  free_keyvalue_list(int2_cms_meta.subject);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_save_certs)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
