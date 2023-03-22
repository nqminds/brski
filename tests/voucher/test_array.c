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

#include "voucher/array.h"

static void test_init_array_list(void **state) {
  (void)state;
  struct BinaryArrayList *ll = init_array_list();
  assert_non_null(ll);
  free_array_list(ll);
}

static void test_push_array_list(void **state) {
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

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_array_list),
      cmocka_unit_test(test_push_array_list),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
