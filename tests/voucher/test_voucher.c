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
#include "voucher/voucher.h"

#define SERIALNAME_LONG                                                        \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"

static void test_init_voucher(void **state) {
  (void)state;

  struct Voucher *voucher = init_voucher();

  assert_non_null(voucher);
  free_voucher(voucher);
}

static void test_set_attr_bool_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_bool_voucher(NULL, 0, true), -1);
  assert_int_equal(set_attr_bool_voucher(voucher, -1, true), -1);
  assert_int_equal(
      set_attr_bool_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, true),
      0);

  free_voucher(voucher);
}

static void test_set_attr_time_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_time_voucher(NULL, ATTR_CREATED_ON, 0), -1);
  assert_int_equal(set_attr_time_voucher(voucher, -1, true), -1);
  assert_int_equal(set_attr_time_voucher(voucher, ATTR_CREATED_ON, 12345), 0);
  assert_int_equal(set_attr_time_voucher(voucher, ATTR_EXPIRES_ON, 12345), 0);
  assert_int_equal(
      set_attr_time_voucher(voucher, ATTR_LAST_RENEWAL_DATE, 12345), 0);

  free_voucher(voucher);
}

static void test_set_attr_enum_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_enum_voucher(NULL, ATTR_ASSERTION, 0), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, -1, true), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ATTR_ASSERTION, 12345), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ATTR_ASSERTION,
                                         VOUCHER_ASSERTION_VERIFIED),
                   0);
  assert_int_equal(
      set_attr_enum_voucher(voucher, ATTR_ASSERTION, VOUCHER_ASSERTION_LOGGED),
      0);
  assert_int_equal(set_attr_enum_voucher(voucher, ATTR_ASSERTION,
                                         VOUCHER_ASSERTION_PROXIMITY),
                   0);

  free_voucher(voucher);
}

static void test_set_attr_str_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_str_voucher(NULL, ATTR_SERIAL_NUMBER, NULL), -1);
  assert_int_equal(set_attr_str_voucher(voucher, -1, NULL), -1);
  assert_int_equal(
      set_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER, SERIALNAME_LONG), -1);
  assert_int_equal(set_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER, "test"),
                   0);

  free_voucher(voucher);
}

static void test_set_attr_array_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_array_voucher(NULL, ATTR_NONCE, NULL), -1);
  assert_int_equal(set_attr_array_voucher(voucher, -1, NULL), -1);

  struct VoucherBinaryArray arr1 = {.array = NULL, .length = 10};

  assert_int_equal(set_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER, &arr1),
                   -1);

  uint8_t array2[] = {1, 2, 3, 4};
  struct VoucherBinaryArray arr2 = {.array = array2, .length = 0};

  assert_int_equal(set_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER, &arr2),
                   -1);

  struct VoucherBinaryArray arr3 = {.array = array2, .length = 4};

  assert_int_equal(set_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER, &arr3),
                   0);
  assert_memory_equal(voucher->idevid_issuer.array, arr3.array, arr3.length);

  assert_int_equal(
      set_attr_array_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &arr3), 0);
  assert_memory_equal(voucher->pinned_domain_cert.array, arr3.array,
                      arr3.length);

  assert_int_equal(set_attr_array_voucher(voucher, ATTR_NONCE, &arr3), 0);
  assert_memory_equal(voucher->nonce.array, arr3.array, arr3.length);

  free_voucher(voucher);
}

static void test_set_attr_voucher(void **state) {
  (void)state;

  time_t time_value = 12345;
  enum VoucherAssertions enum_value = VOUCHER_ASSERTION_LOGGED;
  char *str_value = "12345";
  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};
  bool bool_value = true;

  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_voucher(voucher, ATTR_CREATED_ON, time_value), 0);
  assert_int_equal(voucher->created_on, time_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_EXPIRES_ON, time_value), 0);
  assert_int_equal(voucher->expires_on, time_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_ASSERTION, enum_value), 0);
  assert_int_equal(voucher->assertion, enum_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_SERIAL_NUMBER, str_value), 0);
  assert_string_equal(voucher->serial_number, str_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_IDEVID_ISSUER, &array_value),
                   0);
  assert_int_equal(voucher->idevid_issuer.length, array_value.length);
  assert_memory_equal(voucher->idevid_issuer.array, array_value.array,
                      array_value.length);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &array_value), 0);
  assert_int_equal(voucher->pinned_domain_cert.length, array_value.length);
  assert_memory_equal(voucher->pinned_domain_cert.array, array_value.array,
                      array_value.length);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, bool_value),
      0);
  assert_int_equal(voucher->domain_cert_revocation_checks, bool_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_NONCE, &array_value), 0);
  assert_int_equal(voucher->nonce.length, array_value.length);
  assert_memory_equal(voucher->nonce.array, array_value.array,
                      array_value.length);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, time_value), 0);
  assert_int_equal(voucher->last_renewal_date, time_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                                    &array_value),
                   0);
  assert_int_equal(voucher->prior_signed_voucher_request.length,
                   array_value.length);
  assert_memory_equal(voucher->prior_signed_voucher_request.array,
                      array_value.array, array_value.length);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, &array_value),
      0);
  assert_int_equal(voucher->proximity_registrar_cert.length,
                   array_value.length);
  assert_memory_equal(voucher->proximity_registrar_cert.array,
                      array_value.array, array_value.length);

  free_voucher(voucher);
}

static void test_serialize_voucher(void **state) {
  (void)state;

  time_t time_value = 12345;
  enum VoucherAssertions enum_value = VOUCHER_ASSERTION_LOGGED;
  char *str_array_value = "12345";
  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};
  bool bool_value = true;

  struct Voucher *voucher = init_voucher();
  char *serialized_json = serialize_voucher(voucher);
  char *json =
      "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":false}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);

  voucher = init_voucher();
  set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, bool_value);
  serialized_json = serialize_voucher(voucher);
  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":true}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);

  voucher = init_voucher();
  set_attr_voucher(voucher, ATTR_ASSERTION, enum_value);
  set_attr_voucher(voucher, ATTR_SERIAL_NUMBER, str_array_value);
  serialized_json = serialize_voucher(voucher);
  json = "{\"ietf-voucher:voucher\":{\"assertion\":\"logged\",\"serial-"
         "number\":\"12345\",\"domain-cert-revocation-checks\":false}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);

  voucher = init_voucher();
  set_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST, &array_value);
  serialized_json = serialize_voucher(voucher);
  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":false,"
         "\"prior-signed-voucher-request\":\"AQIDBAU=\"}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);

  voucher = init_voucher();
  set_attr_voucher(voucher, ATTR_CREATED_ON, time_value);
  serialized_json = serialize_voucher(voucher);
  json = "{\"ietf-voucher:voucher\":{\"created-on\":\"1970-01-01T03:25:45Z\","
         "\"domain-cert-revocation-checks\":false}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_voucher),
      cmocka_unit_test(test_set_attr_bool_voucher),
      cmocka_unit_test(test_set_attr_time_voucher),
      cmocka_unit_test(test_set_attr_enum_voucher),
      cmocka_unit_test(test_set_attr_str_voucher),
      cmocka_unit_test(test_set_attr_array_voucher),
      cmocka_unit_test(test_set_attr_voucher),
      cmocka_unit_test(test_serialize_voucher)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
