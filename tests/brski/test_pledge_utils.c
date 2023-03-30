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

#include "brski/pledge/pledge_utils.h"
#include "brski/config.h"

#define TEST_CMS_OUT_PATH "/tmp/test_out.cms"

static void test_voucher_pledge_request_to_smimefile(void **state) {
  (void)state;
  struct brski_config config = {0};

  load_brski_config(TEST_CONFIG_INI_PATH, &config);
  int res = voucher_pledge_request_to_smimefile(&config.pconf, config.rconf.tls_cert_path, TEST_CMS_OUT_PATH);
  assert_int_equal(res, 0);
}

static void test_voucher_pledge_request_to_smimefile_add(void **state) {
  (void)state;
  struct brski_config config = {0};

  load_brski_config(TEST_CONFIG_ADD_INI_PATH, &config);
  int res = voucher_pledge_request_to_smimefile(&config.pconf, config.rconf.tls_cert_path, TEST_CMS_OUT_PATH);
  assert_int_equal(res, 0);
}

static int teardown(void **state) {
  (void)state;

  unlink(TEST_CMS_OUT_PATH);
  return 0;
}
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_voucher_pledge_request_to_smimefile, NULL, teardown),
      cmocka_unit_test_setup_teardown(test_voucher_pledge_request_to_smimefile_add, NULL, teardown)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
