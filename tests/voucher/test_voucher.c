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

  struct tm tm;
  assert_int_equal(set_attr_time_voucher(NULL, ATTR_CREATED_ON, 0), -1);
  assert_int_equal(set_attr_time_voucher(voucher, -1, NULL), -1);
  assert_int_equal(set_attr_time_voucher(voucher, ATTR_CREATED_ON, &tm), 0);
  assert_int_equal(set_attr_time_voucher(voucher, ATTR_EXPIRES_ON, &tm), 0);
  assert_int_equal(set_attr_time_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm),
                   0);

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
  struct VoucherBinaryArray arr2 = {.array = NULL, .length = 0};

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

void test_compare_time(const struct tm *tm1, const struct tm *tm2) {
  assert_int_equal(tm1->tm_year, tm2->tm_year);
  assert_int_equal(tm1->tm_mon, tm2->tm_mon);
  assert_int_equal(tm1->tm_mday, tm2->tm_mday);
  assert_int_equal(tm1->tm_hour, tm2->tm_hour);
  assert_int_equal(tm1->tm_min, tm2->tm_min);
  assert_int_equal(tm1->tm_sec, tm2->tm_sec);
}

static void test_set_attr_voucher(void **state) {
  (void)state;

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
  enum VoucherAssertions enum_value = VOUCHER_ASSERTION_LOGGED;
  char *str_value = "12345";
  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};
  bool bool_value = true;

  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_voucher(voucher, ATTR_CREATED_ON, &tm), 0);
  test_compare_time(&tm, &voucher->created_on);

  assert_int_equal(set_attr_voucher(voucher, ATTR_EXPIRES_ON, &tm), 0);
  test_compare_time(&tm, &voucher->expires_on);

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

  assert_int_equal(set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm), 0);
  test_compare_time(&tm, &voucher->last_renewal_date);

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

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
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
  set_attr_voucher(voucher, ATTR_CREATED_ON, &tm);
  serialized_json = serialize_voucher(voucher);
  json = "{\"ietf-voucher:voucher\":{\"created-on\":\"1973-11-29T21:33:09Z\","
         "\"domain-cert-revocation-checks\":false}}";
  assert_string_equal(serialized_json, json);
  sys_free(serialized_json);
  free_voucher(voucher);
}

static void test_deserialize_voucher(void **state) {
  (void)state;

  struct tm tm_null = {.tm_year = 0,
                       .tm_mon = 0,
                       .tm_mday = 0,
                       .tm_hour = 0,
                       .tm_min = 0,
                       .tm_sec = 0};

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};

  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};

  char *json = "{\"ietf-voucher:voucher\":";
  struct Voucher *voucher = deserialize_voucher(json);
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":}";
  voucher = deserialize_voucher(json);
  assert_null(voucher);

  json = "{\"-voucher:voucher\":{}}";
  voucher = deserialize_voucher(json);
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_non_null(voucher);
  test_compare_time(&tm_null, &voucher->created_on);
  test_compare_time(&tm_null, &voucher->expires_on);

  assert_int_equal(voucher->assertion, VOUCHER_ASSERTION_NONE);
  assert_null(voucher->serial_number);
  assert_null(voucher->idevid_issuer.array);
  assert_int_equal(voucher->idevid_issuer.length, 0);
  assert_null(voucher->pinned_domain_cert.array);
  assert_int_equal(voucher->pinned_domain_cert.length, 0);
  assert_false(voucher->domain_cert_revocation_checks);
  assert_null(voucher->nonce.array);
  assert_int_equal(voucher->nonce.length, 0);
  test_compare_time(&tm_null, &voucher->last_renewal_date);
  assert_null(voucher->prior_signed_voucher_request.array);
  assert_int_equal(voucher->prior_signed_voucher_request.length, 0);
  assert_null(voucher->proximity_registrar_cert.array);
  assert_int_equal(voucher->proximity_registrar_cert.length, 0);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"created-on\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->created_on);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"expires-on\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->expires_on);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"assertion\":\"logged\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->assertion, VOUCHER_ASSERTION_LOGGED);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"assertion\":\"logg\"}}";
  voucher = deserialize_voucher(json);
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{\"serial-number\":\"12345\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_string_equal(voucher->serial_number, "12345");
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"idevid-issuer\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->idevid_issuer.length, array_value.length);
  assert_memory_equal(voucher->idevid_issuer.array, array_value.array,
                      array_value.length);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"pinned-domain-cert\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->pinned_domain_cert.length, array_value.length);
  assert_memory_equal(voucher->pinned_domain_cert.array, array_value.array,
                      array_value.length);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":true}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_true(voucher->domain_cert_revocation_checks);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"nonce\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->nonce.length, array_value.length);
  assert_memory_equal(voucher->nonce.array, array_value.array,
                      array_value.length);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"last-renewal-date\":\"1973-11-29T21:33:"
         "09Z\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->last_renewal_date);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"prior-signed-voucher-request\":"
         "\"AQIDBAU=\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->prior_signed_voucher_request.length,
                   array_value.length);
  assert_memory_equal(voucher->prior_signed_voucher_request.array,
                      array_value.array, array_value.length);
  free_voucher(voucher);

  json =
      "{\"ietf-voucher:voucher\":{\"proximity-registrar-cert\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_int_equal(voucher->proximity_registrar_cert.length,
                   array_value.length);
  assert_memory_equal(voucher->proximity_registrar_cert.array,
                      array_value.array, array_value.length);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-c\":true}}";
  voucher = deserialize_voucher(json);
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":true,"
         "\"prior-signed-voucher-request\":\"AQIDBAU=\", "
         "\"last-renewal-date\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher(json);
  assert_non_null(voucher);
  assert_true(voucher->domain_cert_revocation_checks);
  assert_int_equal(voucher->prior_signed_voucher_request.length,
                   array_value.length);
  assert_memory_equal(voucher->prior_signed_voucher_request.array,
                      array_value.array, array_value.length);
  test_compare_time(&tm, &voucher->last_renewal_date);
  free_voucher(voucher);
}

static void test_clear_attr_voucher(void **state) {
  (void)state;

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
  struct tm tm_zero = {.tm_year = 0,
                       .tm_mon = 0,
                       .tm_mday = 0,
                       .tm_hour = 0,
                       .tm_min = 0,
                       .tm_sec = 0};

  enum VoucherAssertions enum_value = VOUCHER_ASSERTION_LOGGED;
  char *str_value = "12345";
  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};
  bool bool_value = true;

  struct Voucher *voucher = init_voucher();

  set_attr_voucher(voucher, ATTR_CREATED_ON, &tm);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_CREATED_ON), 0);
  test_compare_time(&tm_zero, &voucher->created_on);

  set_attr_voucher(voucher, ATTR_EXPIRES_ON, &tm);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_EXPIRES_ON), 0);
  test_compare_time(&tm_zero, &voucher->expires_on);

  set_attr_voucher(voucher, ATTR_ASSERTION, enum_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_ASSERTION), 0);
  assert_int_equal(voucher->assertion, VOUCHER_ASSERTION_NONE);

  set_attr_voucher(voucher, ATTR_SERIAL_NUMBER, str_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_SERIAL_NUMBER), 0);
  assert_null(voucher->serial_number);

  set_attr_voucher(voucher, ATTR_IDEVID_ISSUER, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_IDEVID_ISSUER), 0);
  assert_int_equal(voucher->idevid_issuer.length, 0);
  assert_null(voucher->idevid_issuer.array);

  set_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT), 0);
  assert_int_equal(voucher->pinned_domain_cert.length, 0);
  assert_null(voucher->pinned_domain_cert.array);

  set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, bool_value);
  assert_int_equal(
      clear_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS), 0);
  assert_false(voucher->domain_cert_revocation_checks);

  set_attr_voucher(voucher, ATTR_NONCE, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_NONCE), 0);
  assert_int_equal(voucher->nonce.length, 0);
  assert_null(voucher->nonce.array);

  set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE), 0);
  test_compare_time(&tm_zero, &voucher->last_renewal_date);

  set_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST, &array_value);
  assert_int_equal(
      clear_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST), 0);
  assert_int_equal(voucher->prior_signed_voucher_request.length, 0);
  assert_null(voucher->prior_signed_voucher_request.array);

  set_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT),
                   0);
  assert_int_equal(voucher->proximity_registrar_cert.length, 0);
  assert_null(voucher->proximity_registrar_cert.array);

  free_voucher(voucher);
}

static void test_get_attr_bool_voucher(void **state) {
  (void)state;

  struct Voucher *voucher = init_voucher();
  const bool* value = get_attr_bool_voucher(voucher,
                          ATTR_DOMAIN_CERT_REVOCATION_CHECKS);
  assert_non_null(value);
  assert_false(*value);

  set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, true);
  value = get_attr_bool_voucher(voucher,
                          ATTR_DOMAIN_CERT_REVOCATION_CHECKS);
  assert_non_null(value);
  assert_true(*value);

  assert_null(get_attr_bool_voucher(voucher, -1));
  
  free_voucher(voucher);
}

static void test_get_attr_time_voucher(void **state) {
  (void)state;

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
  struct tm tm_zero = {.tm_year = 0,
                       .tm_mon = 0,
                       .tm_mday = 0,
                       .tm_hour = 0,
                       .tm_min = 0,
                       .tm_sec = 0};

  struct Voucher *voucher = init_voucher();
  const struct tm* tm_value = get_attr_time_voucher(voucher, ATTR_CREATED_ON);
  assert_non_null(tm_value);
  test_compare_time(&tm_zero, tm_value);

  tm_value = get_attr_time_voucher(voucher, ATTR_EXPIRES_ON);
  assert_non_null(tm_value);
  test_compare_time(&tm_zero, tm_value);

  tm_value = get_attr_time_voucher(voucher, ATTR_LAST_RENEWAL_DATE);
  assert_non_null(tm_value);
  test_compare_time(&tm_zero, tm_value);

  tm_value = get_attr_time_voucher(voucher, -1);
  assert_null(tm_value);

  set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm);
  tm_value = get_attr_time_voucher(voucher, ATTR_LAST_RENEWAL_DATE);
  assert_non_null(tm_value);
  test_compare_time(&tm, tm_value);

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
      cmocka_unit_test(test_serialize_voucher),
      cmocka_unit_test(test_deserialize_voucher),
      cmocka_unit_test(test_clear_attr_voucher),
      cmocka_unit_test(test_get_attr_bool_voucher),
      cmocka_unit_test(test_get_attr_time_voucher)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
