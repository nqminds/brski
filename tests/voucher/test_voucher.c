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
#include "voucher/voucher.h"
#include "voucher/voucher_defs.h"

#define SERIALNAME_LONG                                                        \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"                                           \
  "abcdabcdabcdabcdabcdabcdabcdabcd"

void test_compare_time(const struct tm *tm1, const struct tm *tm2) {
  assert_int_equal(tm1->tm_year, tm2->tm_year);
  assert_int_equal(tm1->tm_mon, tm2->tm_mon);
  assert_int_equal(tm1->tm_mday, tm2->tm_mday);
  assert_int_equal(tm1->tm_hour, tm2->tm_hour);
  assert_int_equal(tm1->tm_min, tm2->tm_min);
  assert_int_equal(tm1->tm_sec, tm2->tm_sec);
}

void test_compare_array(const struct VoucherBinaryArray *src,
                        const struct VoucherBinaryArray *dst) {
  assert_int_equal(src->length, dst->length);
  assert_memory_equal(src->array, dst->array, src->length);
}

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
  test_compare_array(&arr3, &voucher->idevid_issuer);

  assert_int_equal(
      set_attr_array_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &arr3), 0);
  test_compare_array(&arr3, &voucher->pinned_domain_cert);

  assert_int_equal(set_attr_array_voucher(voucher, ATTR_NONCE, &arr3), 0);
  test_compare_array(&arr3, &voucher->nonce);

  free_voucher(voucher);
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
  test_compare_array(&array_value, &voucher->idevid_issuer);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &array_value), 0);
  test_compare_array(&array_value, &voucher->pinned_domain_cert);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, bool_value),
      0);
  assert_int_equal(voucher->domain_cert_revocation_checks, bool_value);

  assert_int_equal(set_attr_voucher(voucher, ATTR_NONCE, &array_value), 0);
  test_compare_array(&array_value, &voucher->nonce);

  assert_int_equal(set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm), 0);
  test_compare_time(&tm, &voucher->last_renewal_date);

  assert_int_equal(set_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                                    &array_value),
                   0);
  test_compare_array(&array_value, &voucher->prior_signed_voucher_request);

  assert_int_equal(
      set_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, &array_value),
      0);
  test_compare_array(&array_value, &voucher->proximity_registrar_cert);

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

__attribute__((no_sanitize_address)) static void
test_deserialize_voucher(void **state) {
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
  struct VoucherBinaryArray array_zero = {.array = NULL, .length = 0};
  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};

  char *json = "{\"ietf-voucher:voucher\":";
  struct Voucher *voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_null(voucher);

  json = "{\"-voucher:voucher\":{}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  assert_non_null(voucher);
  test_compare_time(&tm_null, &voucher->created_on);
  test_compare_time(&tm_null, &voucher->expires_on);

  assert_int_equal(voucher->assertion, VOUCHER_ASSERTION_NONE);
  assert_null(voucher->serial_number);
  test_compare_array(&array_zero, &voucher->idevid_issuer);
  test_compare_array(&array_zero, &voucher->pinned_domain_cert);
  assert_false(voucher->domain_cert_revocation_checks);
  test_compare_array(&array_zero, &voucher->nonce);
  test_compare_time(&tm_null, &voucher->last_renewal_date);
  test_compare_array(&array_zero, &voucher->prior_signed_voucher_request);
  test_compare_array(&array_zero, &voucher->proximity_registrar_cert);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"created-on\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->created_on);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"expires-on\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->expires_on);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"assertion\":\"logged\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  assert_int_equal(voucher->assertion, VOUCHER_ASSERTION_LOGGED);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"assertion\":\"logg\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{\"serial-number\":\"12345\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  assert_string_equal(voucher->serial_number, "12345");
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"idevid-issuer\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_array(&array_value, &voucher->idevid_issuer);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"pinned-domain-cert\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_array(&array_value, &voucher->pinned_domain_cert);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":true}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  assert_true(voucher->domain_cert_revocation_checks);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"nonce\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_array(&array_value, &voucher->nonce);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"last-renewal-date\":\"1973-11-29T21:33:"
         "09Z\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_time(&tm, &voucher->last_renewal_date);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"prior-signed-voucher-request\":"
         "\"AQIDBAU=\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_array(&array_value, &voucher->prior_signed_voucher_request);
  free_voucher(voucher);

  json =
      "{\"ietf-voucher:voucher\":{\"proximity-registrar-cert\":\"AQIDBAU=\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  test_compare_array(&array_value, &voucher->proximity_registrar_cert);
  free_voucher(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-c\":true}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_null(voucher);

  json = "{\"ietf-voucher:voucher\":{\"domain-cert-revocation-checks\":true,"
         "\"prior-signed-voucher-request\":\"AQIDBAU=\", "
         "\"last-renewal-date\":\"1973-11-29T21:33:09Z\"}}";
  voucher = deserialize_voucher((uint8_t *)json, strlen(json));
  assert_non_null(voucher);
  assert_true(voucher->domain_cert_revocation_checks);
  test_compare_array(&array_value, &voucher->prior_signed_voucher_request);
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
  struct VoucherBinaryArray array_zero = {.array = NULL, .length = 0};
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
  test_compare_array(&array_zero, &voucher->idevid_issuer);

  set_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_PINNED_DOMAIN_CERT), 0);
  test_compare_array(&array_zero, &voucher->pinned_domain_cert);

  set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, bool_value);
  assert_int_equal(
      clear_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS), 0);
  assert_false(voucher->domain_cert_revocation_checks);

  set_attr_voucher(voucher, ATTR_NONCE, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_NONCE), 0);
  test_compare_array(&array_zero, &voucher->nonce);

  set_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE, &tm);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_LAST_RENEWAL_DATE), 0);
  test_compare_time(&tm_zero, &voucher->last_renewal_date);

  set_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST, &array_value);
  assert_int_equal(
      clear_attr_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST), 0);
  test_compare_array(&array_zero, &voucher->prior_signed_voucher_request);

  set_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, &array_value);
  assert_int_equal(clear_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT),
                   0);
  test_compare_array(&array_zero, &voucher->proximity_registrar_cert);

  free_voucher(voucher);
}

static void test_get_attr_bool_voucher(void **state) {
  (void)state;

  struct Voucher *voucher = init_voucher();
  const bool *value =
      get_attr_bool_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS);
  assert_non_null(value);
  assert_false(*value);

  set_attr_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS, true);
  value = get_attr_bool_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS);
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
  const struct tm *tm_value = get_attr_time_voucher(voucher, ATTR_CREATED_ON);
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

static void test_get_attr_enum_voucher(void **state) {
  (void)state;

  struct Voucher *voucher = init_voucher();
  const enum VoucherAssertions *enum_value =
      (const enum VoucherAssertions *)get_attr_enum_voucher(voucher,
                                                            ATTR_ASSERTION);
  assert_non_null(enum_value);
  assert_int_equal(*enum_value, VOUCHER_ASSERTION_NONE);

  enum_value =
      (const enum VoucherAssertions *)get_attr_enum_voucher(voucher, -1);
  assert_null(enum_value);

  set_attr_enum_voucher(voucher, ATTR_ASSERTION, VOUCHER_ASSERTION_LOGGED);
  enum_value = (const enum VoucherAssertions *)get_attr_enum_voucher(
      voucher, ATTR_ASSERTION);
  assert_non_null(enum_value);
  assert_int_equal(*enum_value, VOUCHER_ASSERTION_LOGGED);

  free_voucher(voucher);
}

static void test_get_attr_str_voucher(void **state) {
  (void)state;

  struct Voucher *voucher = init_voucher();
  const char *const *value = get_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER);
  assert_non_null(value);
  assert_null(*value);

  value = get_attr_str_voucher(voucher, -1);
  assert_null(value);

  set_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER, "test");
  value = get_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER);
  assert_non_null(value);
  assert_string_equal(*value, "test");

  free_voucher(voucher);
}

static void test_get_attr_array_voucher(void **state) {
  (void)state;

  uint8_t array[] = {1, 2, 3, 4, 5};
  struct VoucherBinaryArray array_value = {.array = array, .length = 5};
  struct VoucherBinaryArray array_zero = {.array = NULL, .length = 0};

  struct Voucher *voucher = init_voucher();
  const struct VoucherBinaryArray *value =
      get_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER);
  assert_non_null(value);
  test_compare_array(&array_zero, value);

  value = get_attr_array_voucher(voucher, -1);
  assert_null(value);

  value = get_attr_array_voucher(voucher, ATTR_PINNED_DOMAIN_CERT);
  assert_non_null(value);
  test_compare_array(&array_zero, value);

  value = get_attr_array_voucher(voucher, ATTR_NONCE);
  assert_non_null(value);
  test_compare_array(&array_zero, value);

  value = get_attr_array_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST);
  assert_non_null(value);
  test_compare_array(&array_zero, value);

  value = get_attr_array_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT);
  assert_non_null(value);
  test_compare_array(&array_zero, value);

  set_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER, &array_value);
  value = get_attr_array_voucher(voucher, ATTR_IDEVID_ISSUER);
  assert_non_null(value);
  test_compare_array(&array_value, value);

  set_attr_array_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, &array_value);
  value = get_attr_array_voucher(voucher, ATTR_PINNED_DOMAIN_CERT);
  assert_non_null(value);
  test_compare_array(&array_value, value);

  set_attr_array_voucher(voucher, ATTR_NONCE, &array_value);
  value = get_attr_array_voucher(voucher, ATTR_NONCE);
  assert_non_null(value);
  test_compare_array(&array_value, value);

  set_attr_array_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                         &array_value);
  value = get_attr_array_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST);
  assert_non_null(value);
  test_compare_array(&array_value, value);

  set_attr_array_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, &array_value);
  value = get_attr_array_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT);
  assert_non_null(value);
  test_compare_array(&array_value, value);

  free_voucher(voucher);
}

static void test_sign_cms_voucher(void **state) {
  (void)state;

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
  struct VoucherBinaryArray cert = {}, key = {};

  struct Voucher *voucher = init_voucher();

  set_attr_voucher(voucher, ATTR_CREATED_ON, &tm);

  struct buffer_list *certs = init_buffer_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  key.length = crypto_generate_eckey(&key.array);
  assert_non_null(key.array);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"),
                     sys_strdup("issuertest.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subjecttest.info"));

  cert.length =
      crypto_generate_eccert(&meta, key.array, key.length, &cert.array);

  uint8_t *key_in_list = NULL;
  ssize_t key_in_list_length = crypto_generate_eckey(&key_in_list);
  uint8_t *cert_in_list = NULL;
  ssize_t cert_in_list_length = crypto_generate_eccert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  push_buffer_list(certs, cert_in_list, cert_in_list_length, 0);

  sys_free(key_in_list);

  struct VoucherBinaryArray *signed_voucher =
      sign_eccms_voucher(voucher, &cert, &key, certs);
  assert_non_null(signed_voucher);
  free_binary_array(signed_voucher);

  signed_voucher = sign_rsacms_voucher(voucher, &cert, &key, certs);
  assert_null(signed_voucher);

  free_binary_array_content(&key);
  free_binary_array_content(&cert);
  free_buffer_list(certs);

  key.length = crypto_generate_rsakey(2048, &key.array);
  assert_non_null(key.array);

  cert.length =
      crypto_generate_rsacert(&meta, key.array, key.length, &cert.array);

  key_in_list_length = crypto_generate_rsakey(2048, &key_in_list);
  cert_in_list_length = crypto_generate_rsacert(
      &meta, key_in_list, key_in_list_length, &cert_in_list);

  certs = init_buffer_list();
  push_buffer_list(certs, cert_in_list, cert_in_list_length, 0);

  sys_free(key_in_list);

  signed_voucher = sign_rsacms_voucher(voucher, &cert, &key, certs);
  assert_non_null(signed_voucher);
  free_binary_array(signed_voucher);

  signed_voucher = sign_eccms_voucher(voucher, &cert, &key, certs);
  assert_null(signed_voucher);

  free_binary_array_content(&key);
  free_binary_array_content(&cert);
  free_buffer_list(certs);

  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);

  free_voucher(voucher);
}

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
  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);

  return certs;
}

static void test_verify_cms_voucher(void **state) {
  (void)state;

  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};
  struct VoucherBinaryArray cert = {}, key = {};

  struct Voucher *voucher = init_voucher();

  set_attr_voucher(voucher, ATTR_CREATED_ON, &tm);

  struct buffer_list *certs = create_cert_list();
  struct crypto_cert_meta meta = {.serial_number = 12345,
                                  .not_before = 0,
                                  .not_after = 1234567,
                                  .issuer = NULL,
                                  .subject = NULL};

  key.length = crypto_generate_eckey(&key.array);
  assert_non_null(key.array);
  meta.issuer = init_keyvalue_list();
  meta.subject = init_keyvalue_list();

  push_keyvalue_list(meta.issuer, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.issuer, sys_strdup("CN"), sys_strdup("issuer.info"));

  push_keyvalue_list(meta.subject, sys_strdup("C"), sys_strdup("IE"));
  push_keyvalue_list(meta.subject, sys_strdup("CN"),
                     sys_strdup("subject.info"));

  cert.length =
      crypto_generate_eccert(&meta, key.array, key.length, &cert.array);

  struct VoucherBinaryArray *signed_voucher =
      sign_eccms_voucher(voucher, &cert, &key, certs);
  assert_non_null(signed_voucher);

  struct Voucher *decoded_voucher =
      verify_cms_voucher(signed_voucher, NULL, NULL, NULL);
  assert_non_null(decoded_voucher);
  test_compare_time(&voucher->created_on, &decoded_voucher->created_on);

  free_voucher(decoded_voucher);
  free_binary_array(signed_voucher);

  signed_voucher = sign_cms_voucher(voucher, &cert, &key, certs);
  assert_non_null(signed_voucher);

  decoded_voucher = verify_cms_voucher(signed_voucher, NULL, NULL, NULL);
  assert_non_null(decoded_voucher);
  test_compare_time(&voucher->created_on, &decoded_voucher->created_on);

  free_voucher(voucher);
  free_voucher(decoded_voucher);
  free_binary_array(signed_voucher);

  free_binary_array_content(&key);
  free_binary_array_content(&cert);
  free_buffer_list(certs);

  free_keyvalue_list(meta.issuer);
  free_keyvalue_list(meta.subject);
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
      cmocka_unit_test(test_get_attr_time_voucher),
      cmocka_unit_test(test_get_attr_enum_voucher),
      cmocka_unit_test(test_get_attr_str_voucher),
      cmocka_unit_test(test_get_attr_array_voucher),
      cmocka_unit_test(test_sign_cms_voucher),
      cmocka_unit_test(test_verify_cms_voucher)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
