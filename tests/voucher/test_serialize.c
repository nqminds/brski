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
#include "voucher/serialize.h"

#define STR_TO_BASE64 "QlJTS0kgcHJvdG9jb2wgc2VydmVyL2NsaWVudCBpbXBsZW1lbnRhdGlvbi4="
#define STR_FROM_BASE64 "BRSKI protocol server/client implementation."

static void test_serialize_to_base64(void **state) {
  (void)state;
  char *str = STR_FROM_BASE64;
  size_t out_len;
  char *out = (char *)serialize_to_base64((const uint8_t *)str, strlen(str), &out_len);
  assert_non_null(out);
  assert_string_equal(out, STR_TO_BASE64);
}

static void test_deserialize_from_base64(void **state) {
  (void)state;
  char *str = STR_TO_BASE64;
  size_t out_len;
  char *out = (char *)deserialize_from_base64((const uint8_t *)str, strlen(str), &out_len);
  assert_non_null(out);
  assert_string_equal(out, STR_FROM_BASE64);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_serialize_to_base64),
    cmocka_unit_test(test_deserialize_from_base64)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
