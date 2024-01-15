/**
 * Generates some example certificates that can be used in the BRSKI tests.
 */

#define _POSIX_C_SOURCE 1

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include <errno.h>

#include <limits.h> // required for PATH_MAX

#include "utils/log.h"
#include "voucher/array.h"
#include "voucher/crypto.h"
#include "voucher/keyvalue.h"

const long SECONDS_IN_YEAR = 10 * 60 * 60 * 24 * 365;

// Default Root CA certificate "Not After" validity offset
const long CA_NOT_AFTER = 10 * SECONDS_IN_YEAR;
// Default Subordinate 1 CA certificate "Not After" validity offset
const long CA1_NOT_AFTER = 5 * SECONDS_IN_YEAR;
// Default Subordinate 2 CA certificate "Not After" validity offset
const long CA2_NOT_AFTER = 2 * SECONDS_IN_YEAR;
// Default end-entity certificate "Not After" validity offset
const long END_ENTITY_NOT_AFTER = 13 * SECONDS_IN_YEAR / 12; // 13 months

struct context {
  /** The folder to store the certs and keys in */
  const char *output_dir;
};

/**
 * Saves the given cert as `<output_dir>/<cert_name>.crt` and
 * `<output_dir>/<cert_name>.key`.
 *
 * @param cert_name - The basename of the cert, without a file extension.
 * @param context - Contains the output directory to store the certs in.
 * @param keybuf - Key buffer.
 * @param certbuf - Certificate buffer.
 * @retval  0 On success.
 * @retval -1 On error.
 */
static int save_cert(const char *cert_name, const struct context *context,
                     const struct BinaryArray *keybuf,
                     const struct BinaryArray *certbuf) {
  char path[PATH_MAX];
  int path_len =
      snprintf(path, PATH_MAX, "%s/%s.key", context->output_dir, cert_name);
  if (path_len < 0 || path_len >= PATH_MAX) {
    log_error("Failed to create path to store cert %s", cert_name);
    return -1;
  }

  log_trace("Saving certificate key\t\t%s", path);
  if (keybuf_to_file(keybuf, path) < 0) {
    log_error("Failed to save key for cert %s at %s", cert_name, path);
    return -1;
  }

  log_trace("Saving certificate\t\t%s", path);
  strcpy(&path[path_len - 3], "crt");
  if (certbuf_to_file(certbuf, path) < 0) {
    log_error("Failed to save cert %s at %s", cert_name, path);
    return -1;
  }

  return 0;
}

static void generate_idevid_certs(void **state) {
  struct context *context = *state;

  static struct BinaryArray idevid_ca_key = {};
  static struct BinaryArray idevid_ca_cert = {};

  // Generate ROOT CA for MASA
  idevid_ca_key.length = crypto_generate_eckey(&idevid_ca_key.array);

  struct crypto_cert_meta idevid_ca_meta = {
      .serial_number = 1,
      .not_before = 0,
      // Long-lived pledge CA cert
      .not_after_absolute = "99991231235959Z",
      .issuer = NULL,
      .subject = NULL,
      .basic_constraints = "critical,CA:TRUE"};

  idevid_ca_meta.issuer = init_keyvalue_list();
  idevid_ca_meta.subject = init_keyvalue_list();
  push_keyvalue_list(idevid_ca_meta.issuer, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.issuer, "CN", "idevca");
  push_keyvalue_list(idevid_ca_meta.subject, "C", "IE");
  push_keyvalue_list(idevid_ca_meta.subject, "CN", "idevca");

  idevid_ca_cert.length =
      crypto_generate_eccert(&idevid_ca_meta, idevid_ca_key.array,
                             idevid_ca_key.length, &idevid_ca_cert.array);

  assert_return_code(
      save_cert("idevid-ca", context, &idevid_ca_key, &idevid_ca_cert), errno);

  {
    struct crypto_cert_meta idev_meta = {.serial_number = 12345,
                                         .not_before = 0,
                                         // Long-lived pledge certificate
                                         .not_after_absolute =
                                             "99991231235959Z",
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
    ssize_t length = crypto_sign_cert(
        idevid_ca_key.array, idevid_ca_key.length, idevid_ca_cert.array,
        idevid_ca_cert.length, idevid_cert.length, &idevid_cert.array);
    assert_true(length > 0);
    idevid_cert.length = length;

    assert_return_code(save_cert("idevid", context, &idevid_key, &idevid_cert),
                       errno);

    free_binary_array_content(&idevid_key);
    free_binary_array_content(&idevid_cert);
    free_keyvalue_list(idev_meta.issuer);
    free_keyvalue_list(idev_meta.subject);
  }

  free_binary_array_content(&idevid_ca_key);
  free_binary_array_content(&idevid_ca_cert);
  free_keyvalue_list(idevid_ca_meta.issuer);
  free_keyvalue_list(idevid_ca_meta.subject);
}

static void generate_ldevid_ca_cert(void **state) {
  struct context *context = *state;

  struct crypto_cert_meta ldevid_ca_meta = {.serial_number = 1,
                                            .not_before = 0,
                                            .not_after = CA_NOT_AFTER,
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

  assert_return_code(
      save_cert("ldevid-ca", context, &ldevid_ca_key, &ldevid_ca_cert), errno);

  free_binary_array_content(&ldevid_ca_key);
  free_binary_array_content(&ldevid_ca_cert);
  free_keyvalue_list(ldevid_ca_meta.issuer);
  free_keyvalue_list(ldevid_ca_meta.subject);
}

static void generate_masa_tls_certs(void **state) {
  struct context *context = *state;

  struct crypto_cert_meta masa_tls_ca_meta = {.serial_number = 1,
                                              .not_before = 0,
                                              .not_after = CA_NOT_AFTER,
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

  assert_return_code(
      save_cert("masa-tls-ca", context, &masa_tls_ca_key, &masa_tls_ca_cert),
      errno);

  {
    struct crypto_cert_meta masa_tls_meta = {.serial_number = 12345,
                                             .not_before = 0,
                                             .not_after = END_ENTITY_NOT_AFTER,
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
    masa_tls_cert.length = (size_t)crypto_generate_eccert(
        &masa_tls_meta, masa_tls_key.array, masa_tls_key.length,
        &masa_tls_cert.array);

    // Sign masa_tls with tls_ca
    ssize_t length = crypto_sign_cert(
        masa_tls_ca_key.array, masa_tls_ca_key.length, masa_tls_ca_cert.array,
        masa_tls_ca_cert.length, masa_tls_cert.length, &masa_tls_cert.array);
    assert_true(length > 0);
    masa_tls_cert.length = length;

    assert_return_code(
        save_cert("masa-tls", context, &masa_tls_key, &masa_tls_cert), errno);

    free_binary_array_content(&masa_tls_key);
    free_binary_array_content(&masa_tls_cert);
    free_keyvalue_list(masa_tls_meta.issuer);
    free_keyvalue_list(masa_tls_meta.subject);
  }

  free_binary_array_content(&masa_tls_ca_key);
  free_binary_array_content(&masa_tls_ca_cert);
  free_keyvalue_list(masa_tls_ca_meta.issuer);
  free_keyvalue_list(masa_tls_ca_meta.subject);
}

static void generate_registrar_tls_certs(void **state) {
  struct context *context = *state;

  struct crypto_cert_meta registrar_tls_ca_meta = {.serial_number = 1,
                                                   .not_before = 0,
                                                   .not_after = CA_NOT_AFTER,
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

  struct crypto_cert_meta registrar_tls_meta = {
      .serial_number = 12345,
      .not_before = 0,
      .not_after = END_ENTITY_NOT_AFTER,
      .issuer = NULL,
      .subject = NULL,
      .basic_constraints = "CA:false"};

  registrar_tls_meta.issuer = init_keyvalue_list();
  registrar_tls_meta.subject = init_keyvalue_list();
  push_keyvalue_list(registrar_tls_meta.subject, "C", "IE");
  push_keyvalue_list(registrar_tls_meta.subject, "CN", "registrar-tls-meta");

  assert_return_code(save_cert("registrar-tls-ca", context,
                               &registrar_tls_ca_key, &registrar_tls_ca_cert),
                     errno);

  {
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

    assert_return_code(save_cert("registrar-tls", context, &registrar_tls_key,
                                 &registrar_tls_cert),
                       errno);

    free_binary_array_content(&registrar_tls_key);
    free_binary_array_content(&registrar_tls_cert);
    free_keyvalue_list(registrar_tls_meta.issuer);
    free_keyvalue_list(registrar_tls_meta.subject);
  }

  free_binary_array_content(&registrar_tls_ca_key);
  free_binary_array_content(&registrar_tls_ca_cert);
  free_keyvalue_list(registrar_tls_ca_meta.issuer);
  free_keyvalue_list(registrar_tls_ca_meta.subject);
}

/**
 * Generates the following CMS certs:
 *
 * -`cms-ca`, which signs:
 *     - `int2-cms`, which signs:
 *         - `int1-cms`, which signs:
 *             - `pledge-cms`
 *             - `registrar-cms`
 *             - `masa-cms`
 *
 *                 ┌──────┐
 *                 │cms-ca│
 *                 └───▲──┘
 *                     │
 *                ┌────┴───┐
 *                │int2-cms│
 *                └────▲───┘
 *                     │
 *                ┌────┴───┐
 *      ┌────────►│int1-cms│◄────────┐
 *      │         └────▲───┘         │
 *      │              │             │
 * ┌────┴─────┐ ┌──────┴──────┐ ┌────┴───┐
 * │pledge-cms│ │registrar-cms│ │masa-cms│
 * └──────────┘ └─────────────┘ └────────┘
 */
static void generate_cms_certs(void **state) {
  struct context *context = *state;

  struct crypto_cert_meta cms_ca_meta = {.serial_number = 1,
                                         .not_before = 0,
                                         .not_after = CA_NOT_AFTER,
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

  assert_return_code(save_cert("cms-ca", context, &cms_ca_key, &cms_ca_cert),
                     errno);

  {
    struct crypto_cert_meta int2_cms_meta = {.serial_number = 12345,
                                             .not_before = 0,
                                             .not_after = CA1_NOT_AFTER,
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
    int2_cms_cert.length = (size_t)crypto_generate_eccert(
        &int2_cms_meta, int2_cms_key.array, int2_cms_key.length,
        &int2_cms_cert.array);

    // Sign int2_cms with cms_ca
    ssize_t length = crypto_sign_cert(
        cms_ca_key.array, cms_ca_key.length, cms_ca_cert.array,
        cms_ca_cert.length, int2_cms_cert.length, &int2_cms_cert.array);
    assert_true(length > 0);
    int2_cms_cert.length = length;

    assert_return_code(
        save_cert("int2-cms", context, &int2_cms_key, &int2_cms_cert), errno);

    {
      struct crypto_cert_meta int1_cms_meta = {.serial_number = 12345,
                                               .not_before = 0,
                                               .not_after = CA2_NOT_AFTER,
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
      int1_cms_cert.length = (size_t)crypto_generate_eccert(
          &int1_cms_meta, int1_cms_key.array, int1_cms_key.length,
          &int1_cms_cert.array);

      // Sign int1_cms with int2_cms
      length = crypto_sign_cert(int2_cms_key.array, int2_cms_key.length,
                                int2_cms_cert.array, int2_cms_cert.length,
                                int1_cms_cert.length, &int1_cms_cert.array);
      assert_true(length > 0);
      int1_cms_cert.length = length;

      assert_return_code(
          save_cert("int1-cms", context, &int1_cms_key, &int1_cms_cert), errno);

      {
        struct crypto_cert_meta pledge_cms_meta = {
            .serial_number = 1,
            .not_before = 0,
            .not_after = END_ENTITY_NOT_AFTER,
            .issuer = NULL,
            .subject = NULL,
            .basic_constraints = "CA:false"};

        pledge_cms_meta.issuer = init_keyvalue_list();
        pledge_cms_meta.subject = init_keyvalue_list();
        push_keyvalue_list(pledge_cms_meta.subject, "C", "IE");
        push_keyvalue_list(pledge_cms_meta.subject, "CN", "pledge-cms-meta");

        struct BinaryArray pledge_cms_key = {};
        struct BinaryArray pledge_cms_cert = {};
        pledge_cms_key.length =
            (size_t)crypto_generate_eckey(&pledge_cms_key.array);
        pledge_cms_cert.length = (size_t)crypto_generate_eccert(
            &pledge_cms_meta, pledge_cms_key.array, pledge_cms_key.length,
            &pledge_cms_cert.array);

        // Sign pledge_cms with int1_cms
        length =
            crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                             int1_cms_cert.array, int1_cms_cert.length,
                             pledge_cms_cert.length, &pledge_cms_cert.array);
        assert_true(length > 0);
        pledge_cms_cert.length = length;

        assert_return_code(
            save_cert("pledge-cms", context, &pledge_cms_key, &pledge_cms_cert),
            errno);

        free_binary_array_content(&pledge_cms_key);
        free_binary_array_content(&pledge_cms_cert);
        free_keyvalue_list(pledge_cms_meta.issuer);
        free_keyvalue_list(pledge_cms_meta.subject);
      }

      {
        struct crypto_cert_meta registrar_cms_meta = {
            .serial_number = 1,
            .not_before = 0,
            .not_after = END_ENTITY_NOT_AFTER,
            .issuer = NULL,
            .subject = NULL,
            .basic_constraints = "CA:false"};

        registrar_cms_meta.issuer = init_keyvalue_list();
        registrar_cms_meta.subject = init_keyvalue_list();
        push_keyvalue_list(registrar_cms_meta.subject, "C", "IE");
        push_keyvalue_list(registrar_cms_meta.subject, "CN",
                           "registrar-cms-meta");

        struct BinaryArray registrar_cms_key = {};
        struct BinaryArray registrar_cms_cert = {};
        registrar_cms_key.length =
            (size_t)crypto_generate_eckey(&registrar_cms_key.array);
        registrar_cms_cert.length = (size_t)crypto_generate_eccert(
            &registrar_cms_meta, registrar_cms_key.array,
            registrar_cms_key.length, &registrar_cms_cert.array);

        // Sign registrar_cms with int1_cms
        length = crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                                  int1_cms_cert.array, int1_cms_cert.length,
                                  registrar_cms_cert.length,
                                  &registrar_cms_cert.array);
        assert_true(length > 0);
        registrar_cms_cert.length = length;

        assert_return_code(save_cert("registrar-cms", context,
                                     &registrar_cms_key, &registrar_cms_cert),
                           errno);

        free_binary_array_content(&registrar_cms_key);
        free_binary_array_content(&registrar_cms_cert);
        free_keyvalue_list(registrar_cms_meta.issuer);
        free_keyvalue_list(registrar_cms_meta.subject);
      }

      {
        struct crypto_cert_meta masa_cms_meta = {
            .serial_number = 1,
            .not_before = 0,
            .not_after = END_ENTITY_NOT_AFTER,
            .issuer = NULL,
            .subject = NULL,
            .basic_constraints = "CA:false"};

        masa_cms_meta.issuer = init_keyvalue_list();
        masa_cms_meta.subject = init_keyvalue_list();
        push_keyvalue_list(masa_cms_meta.subject, "C", "IE");
        push_keyvalue_list(masa_cms_meta.subject, "CN", "masa-cms-meta");

        struct BinaryArray masa_cms_key = {};
        struct BinaryArray masa_cms_cert = {};
        masa_cms_key.length =
            (size_t)crypto_generate_eckey(&masa_cms_key.array);
        masa_cms_cert.length = (size_t)crypto_generate_eccert(
            &masa_cms_meta, masa_cms_key.array, masa_cms_key.length,
            &masa_cms_cert.array);

        // Sign masa_cms with int1_cms
        length = crypto_sign_cert(int1_cms_key.array, int1_cms_key.length,
                                  int1_cms_cert.array, int1_cms_cert.length,
                                  masa_cms_cert.length, &masa_cms_cert.array);
        assert_true(length > 0);
        masa_cms_cert.length = length;

        assert_return_code(
            save_cert("masa-cms", context, &masa_cms_key, &masa_cms_cert),
            errno);

        free_binary_array_content(&masa_cms_key);
        free_binary_array_content(&masa_cms_cert);
        free_keyvalue_list(masa_cms_meta.issuer);
        free_keyvalue_list(masa_cms_meta.subject);
      }

      free_binary_array_content(&int1_cms_key);
      free_binary_array_content(&int1_cms_cert);
      free_keyvalue_list(int1_cms_meta.issuer);
      free_keyvalue_list(int1_cms_meta.subject);
    }

    free_binary_array_content(&int2_cms_key);
    free_binary_array_content(&int2_cms_cert);
    free_keyvalue_list(int2_cms_meta.issuer);
    free_keyvalue_list(int2_cms_meta.subject);
  }

  free_binary_array_content(&cms_ca_key);
  free_binary_array_content(&cms_ca_cert);
  free_keyvalue_list(cms_ca_meta.issuer);
  free_keyvalue_list(cms_ca_meta.subject);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  if (argc != 2) {
    log_error("generate_test_certs expects a CLI arg for the output folder, "
              "e.g. generate_test_certs OUTPUT_DIR");
    return -1;
  }

  struct context context = {
      .output_dir = argv[1],
  };

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_prestate(generate_idevid_certs, &context),
      cmocka_unit_test_prestate(generate_ldevid_ca_cert, &context),
      cmocka_unit_test_prestate(generate_masa_tls_certs, &context),
      cmocka_unit_test_prestate(generate_registrar_tls_certs, &context),
      cmocka_unit_test_prestate(generate_cms_certs, &context)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
