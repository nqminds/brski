#include <stdlib.h>

#include "utils/https_server.h"

extern "C" {
#include "utils/log.h"
}

int main(void) {
  struct https_server_context *context = NULL;
  if (https_start(&context) < 0) {
    log_error("https_start fail");
    return EXIT_FAILURE;
  }

  https_stop(context);

  return EXIT_SUCCESS;
}