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
#include "voucher/voucher.h"

#define SERIALNAME_LONG "abcdabcdabcdabcdabcdabcdabcdabcd" \
                        "abcdabcdabcdabcdabcdabcdabcdabcd" \
                        "abcdabcdabcdabcdabcdabcdabcdabcd" \
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

  assert_int_equal(set_attr_bool_voucher(NULL, NULL, true), -1);
  assert_int_equal(set_attr_bool_voucher(voucher, "some-attribute", true), -1);
  assert_int_equal(
      set_attr_bool_voucher(voucher, DOMAIN_CERT_REVOCATION_CHECKS_NAME, true),
      0);

  free_voucher(voucher);
}

static void test_set_attr_time_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_time_voucher(NULL, NULL, 0), -1);
  assert_int_equal(set_attr_time_voucher(voucher, "some-attribute", true), -1);
  assert_int_equal(set_attr_time_voucher(voucher, CREATED_ON_NAME, 12345), 0);
  assert_int_equal(set_attr_time_voucher(voucher, EXPIRES_ON_NAME, 12345), 0);
  assert_int_equal(set_attr_time_voucher(voucher, LAST_RENEWAL_DATE_NAME, 12345), 0);

  free_voucher(voucher);
}

static void test_set_attr_enum_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_enum_voucher(NULL, NULL, 0), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, "some-attribute", true), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, 12345), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_VERIFIED), 0);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_LOGGED), 0);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_PROXIMITY), 0);

  free_voucher(voucher);
}

static void test_set_attr_str_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_str_voucher(NULL, NULL, NULL), -1);
  assert_int_equal(set_attr_str_voucher(voucher, "some-attribute", NULL), -1);
  assert_int_equal(set_attr_str_voucher(voucher, SERIAL_NUMBER_NAME, SERIALNAME_LONG), -1);
  assert_int_equal(set_attr_str_voucher(voucher, SERIAL_NUMBER_NAME, "test"), 0);

  free_voucher(voucher);
}

static void test_set_attr_array_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_array_voucher(NULL, NULL, NULL), -1);
  assert_int_equal(set_attr_array_voucher(voucher, "some-attribute", NULL), -1);

  struct VoucherBinaryArray arr1 = {
    .array = NULL,
    .length = 10
  };

  assert_int_equal(set_attr_array_voucher(voucher, IDEVID_ISSUER_NAME, &arr1), -1);

  uint8_t array2[] = {1, 2, 3, 4};
  struct VoucherBinaryArray arr2 = {
    .array = array2,
    .length = 0
  };

  assert_int_equal(set_attr_array_voucher(voucher, IDEVID_ISSUER_NAME, &arr2), -1);

  struct VoucherBinaryArray arr3 = {
    .array = array2,
    .length = 4
  };

  assert_int_equal(set_attr_array_voucher(voucher, IDEVID_ISSUER_NAME, &arr3), 0);
  assert_memory_equal(voucher->idevid_issuer.array, arr3.array, arr3.length);

  assert_int_equal(set_attr_array_voucher(voucher, PINNED_DOMAIN_CERT_NAME, &arr3), 0);
  assert_memory_equal(voucher->pinned_domain_cert.array, arr3.array, arr3.length);

  assert_int_equal(set_attr_array_voucher(voucher, NONCE_NAME, &arr3), 0);
  assert_memory_equal(voucher->nonce.array, arr3.array, arr3.length);

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
    cmocka_unit_test(test_set_attr_array_voucher)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
