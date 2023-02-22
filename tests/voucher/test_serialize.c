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
#include <time.h>
#include <unistd.h>

#include "utils/log.h"
#include "utils/os.h"
#include "voucher/serialize.h"

#define STR_TO_BASE64                                                          \
  "QlJTS0kgcHJvdG9jb2wgc2VydmVyL2NsaWVudCBpbXBsZW1lbnRhdGlvbi4="
#define STR_FROM_BASE64 "BRSKI protocol server/client implementation."

static void test_serialize_array2base64str(void **state) {
  (void)state;
  char *str = STR_FROM_BASE64;
  size_t out_len;
  char *out = (char *)serialize_array2base64str((const uint8_t *)str,
                                                strlen(str), &out_len);
  assert_non_null(out);
  assert_string_equal(out, STR_TO_BASE64);
}

static void test_serialize_base64str2array(void **state) {
  (void)state;
  char *str = STR_TO_BASE64;
  size_t out_len;
  char *out = (char *)serialize_base64str2array((const uint8_t *)str,
                                                strlen(str), &out_len);
  assert_non_null(out);
  assert_string_equal(out, STR_FROM_BASE64);
}

static void test_serialize_bool2str(void **state) {
  (void)state;

  char *out = serialize_bool2str(true);
  assert_non_null(out);
  assert_string_equal(out, "true");
  sys_free(out);

  out = serialize_bool2str(false);
  assert_non_null(out);
  assert_string_equal(out, "false");
  sys_free(out);
}

static void test_serialize_str2bool(void **state) {
  (void)state;

  char *str = "true";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 1);
  str = "false";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 0);

  str = "tRue";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 1);

  str = "False";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 0);

  str = "0";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 0);

  str = "1";
  assert_int_equal(serialize_str2bool(str, strlen(str)), 1);

  str = "truu";
  assert_int_equal(serialize_str2bool(str, strlen(str)), -1);

  str = "11";
  assert_int_equal(serialize_str2bool(str, strlen(str)), -1);
}

static void test_serialize_time2str(void **state) {
  (void)state;
  struct tm tm = {.tm_year = 73,
                  .tm_mon = 10,
                  .tm_mday = 29,
                  .tm_hour = 21,
                  .tm_min = 33,
                  .tm_sec = 9};

  char *out = serialize_time2str(&tm);
  assert_non_null(out);
  assert_string_equal(out, "1973-11-29T21:33:09Z");

  sys_free(out);
}

static void test_serialize_str2time(void **state) {
  (void)state;

  const struct tm tm = {};
  char *str = "1973-11-29T21:33:09Z";

  assert_int_equal(serialize_str2time(str, &tm), 0);
  assert_int_equal(tm.tm_year, 73);
  assert_int_equal(tm.tm_mon, 10);
  assert_int_equal(tm.tm_mday, 29);
  assert_int_equal(tm.tm_hour, 21);
  assert_int_equal(tm.tm_min, 33);
  assert_int_equal(tm.tm_sec, 9);
}

static void test_init_keyvalue_list(void **state) {
  (void)state;

  struct keyvalue_list *kv_list = init_keyvalue_list();

  assert_non_null(kv_list);

  free_keyvalue_list(kv_list);
}

static void test_push_keyvalue_list(void **state) {
  (void)state;

  struct keyvalue_list *kv_list = init_keyvalue_list();

  push_keyvalue_list(kv_list, sys_strdup("key1"), sys_strdup("value1"));
  push_keyvalue_list(kv_list, sys_strdup("key2"), sys_strdup("value2"));
  push_keyvalue_list(kv_list, sys_strdup("key3"), sys_strdup("value3"));

  assert_int_equal(dl_list_len(&kv_list->list), 3);

  struct keyvalue_list *kv_list_last =
      dl_list_last(&kv_list->list, struct keyvalue_list, list);
  assert_string_equal(kv_list_last->key, "key3");
  assert_string_equal(kv_list_last->value, "value3");
  free_keyvalue_list(kv_list);
}

static void test_serialize_escapestr(void **state) {
  (void)state;
  char *out = serialize_escapestr("test");
  assert_string_equal(out, "\"test\"");
  sys_free(out);

  out = serialize_escapestr(NULL);
  assert_null(out);
}

static void test_serialize_keyvalue2json(void **state) {
  (void)state;

  struct keyvalue_list *kv_list = init_keyvalue_list();

  push_keyvalue_list(kv_list, sys_strdup("key1"), sys_strdup("value1"));
  push_keyvalue_list(kv_list, sys_strdup("key2"), sys_strdup("value2"));
  push_keyvalue_list(kv_list, sys_strdup("key3"), sys_strdup("value3"));

  char *json = serialize_keyvalue2json(kv_list);
  assert_non_null(json);

  assert_string_equal(json, "{key1:value1,key2:value2,key3:value3}");

  sys_free(json);
  free_keyvalue_list(kv_list);

  kv_list = init_keyvalue_list();

  push_keyvalue_list(kv_list, sys_strdup("key1"), sys_strdup("value1"));

  json = serialize_keyvalue2json(kv_list);
  assert_non_null(json);

  assert_string_equal(json, "{key1:value1}");

  sys_free(json);
  free_keyvalue_list(kv_list);

  kv_list = init_keyvalue_list();

  json = serialize_keyvalue2json(kv_list);
  assert_null(json);

  free_keyvalue_list(kv_list);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_serialize_array2base64str),
      cmocka_unit_test(test_serialize_base64str2array),
      cmocka_unit_test(test_serialize_bool2str),
      cmocka_unit_test(test_serialize_str2bool),
      cmocka_unit_test(test_serialize_time2str),
      cmocka_unit_test(test_serialize_str2time),
      cmocka_unit_test(test_init_keyvalue_list),
      cmocka_unit_test(test_push_keyvalue_list),
      cmocka_unit_test(test_serialize_escapestr),
      cmocka_unit_test(test_serialize_keyvalue2json)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
