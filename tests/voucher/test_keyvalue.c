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
#include "voucher/keyvalue.h"

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

  assert_int_equal(push_keyvalue_list(ll, "key1", "value1"), 0);
  assert_int_equal(push_keyvalue_list(ll, "key2", "value2"), 0);

  struct keyvalue_list *item =
      dl_list_entry((&ll->list)->next, struct keyvalue_list, list);
  assert_string_equal(item->key, "key1");
  assert_string_equal(item->value, "value1");
  item = dl_list_entry(item->list.next, struct keyvalue_list, list);
  assert_string_equal(item->key, "key2");
  assert_string_equal(item->value, "value2");
  free_keyvalue_list(ll);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_keyvalue_list),
      cmocka_unit_test(test_push_keyvalue_list),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
