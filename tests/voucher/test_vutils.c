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

#include "voucher/vutils.h"

static void test_init_keyvalue_list(void **state) {
  (void)state;

  struct keyvalue_list *ll = init_keyvalue_list();
  assert_non_null(ll);
  free_keyvalue_list(ll);
}

static void test_push_keyvalue_list(void **state) {
  (void)state;

  struct keyvalue_list *ll = init_keyvalue_list();
  assert_non_null(ll);

  assert_int_equal(
      push_keyvalue_list(ll, sys_strdup("key1"), sys_strdup("value1")), 0);
  assert_int_equal(
      push_keyvalue_list(ll, sys_strdup("key2"), sys_strdup("value2")), 0);

  struct keyvalue_list *item =
      dl_list_entry((&ll->list)->next, struct keyvalue_list, list);
  assert_string_equal(item->key, "key1");
  assert_string_equal(item->value, "value1");
  item = dl_list_entry(item->list.next, struct keyvalue_list, list);
  assert_string_equal(item->key, "key2");
  assert_string_equal(item->value, "value2");
  free_keyvalue_list(ll);
}

static void test_init_buffer_list(void **state) {
  (void)state;
  struct BinaryArrayList *ll = init_array_list();
  assert_non_null(ll);
  free_array_list(ll);
}

static void test_push_buffer_list(void **state) {
  (void)state;

  struct BinaryArrayList *ll = init_array_list();
  assert_non_null(ll);

  uint8_t buf1[3] = {1, 2, 3};
  uint8_t buf2[4] = {4, 5, 6, 7};
  assert_int_equal(push_array_list(ll, sys_memdup(buf1, 3), 3, 0xAA), 0);
  assert_int_equal(push_array_list(ll, sys_memdup(buf2, 4), 4, 0xBB), 0);

  struct BinaryArrayList *item =
      dl_list_entry((&ll->list)->next, struct BinaryArrayList, list);
  assert_int_equal(item->length, 3);
  assert_memory_equal(item->arr, buf1, 3);
  assert_int_equal(item->flags, 0xAA);
  item = dl_list_entry(item->list.next, struct BinaryArrayList, list);
  assert_int_equal(item->length, 4);
  assert_memory_equal(item->arr, buf2, 4);
  assert_int_equal(item->flags, 0xBB);
  free_array_list(ll);
}

void ptr_free_fun(void *ptr, const int flag) {
  (void)flag;

  sys_free(ptr);
}

static void test_init_ptr_list(void **state) {
  (void)state;

  struct ptr_list *ll = init_ptr_list();
  assert_non_null(ll);
  free_ptr_list(ll, ptr_free_fun);
}

static void test_push_ptr_list(void **state) {
  (void)state;

  struct ptr_list *ll = init_ptr_list();
  assert_non_null(ll);

  assert_int_equal(push_ptr_list(ll, sys_strdup("key1"), 0xAA), 0);
  assert_int_equal(push_ptr_list(ll, sys_strdup("key2"), 0xBB), 0);

  struct ptr_list *item =
      dl_list_entry((&ll->list)->next, struct ptr_list, list);
  assert_int_equal(item->flags, 0xAA);
  assert_string_equal((char *)item->ptr, "key1");
  item = dl_list_entry(item->list.next, struct ptr_list, list);
  assert_int_equal(item->flags, 0xBB);
  assert_string_equal((char *)item->ptr, "key2");

  free_ptr_list(ll, ptr_free_fun);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_init_keyvalue_list),
                                     cmocka_unit_test(test_push_keyvalue_list),
                                     cmocka_unit_test(test_init_buffer_list),
                                     cmocka_unit_test(test_push_buffer_list),
                                     cmocka_unit_test(test_init_ptr_list),
                                     cmocka_unit_test(test_push_ptr_list)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
