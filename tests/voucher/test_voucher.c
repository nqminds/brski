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

  assert_int_equal(set_attr_time_voucher(NULL, NULL, true), -1);
  assert_int_equal(set_attr_time_voucher(voucher, "some-attribute", true), -1);
  assert_int_equal(set_attr_time_voucher(voucher, CREATED_ON_NAME, 12345), 0);
  assert_int_equal(set_attr_time_voucher(voucher, EXPIRES_ON_NAME, 12345), 0);
  assert_int_equal(set_attr_time_voucher(voucher, LAST_RENEWAL_DATE_NAME, 12345), 0);

  free_voucher(voucher);
}

static void test_set_attr_enum_voucher(void **state) {
  (void)state;
  struct Voucher *voucher = init_voucher();

  assert_int_equal(set_attr_enum_voucher(NULL, NULL, true), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, "some-attribute", true), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, 12345), -1);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_VERIFIED), 0);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_LOGGED), 0);
  assert_int_equal(set_attr_enum_voucher(voucher, ASSERTION_NAME, VOUCHER_ASSERTION_PROXIMITY), 0);

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
      cmocka_unit_test(test_set_attr_enum_voucher)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
