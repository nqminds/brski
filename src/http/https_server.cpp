/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the https server.
 */
#include "http.h"
#include "https_server.h"

extern "C" {
#include "../utils/log.h"
#include "../utils/allocs.h"
}

#ifdef WITH_CPPHTTPLIB_LIB
#include "httplib_wrapper.h"
#endif

int https_start(struct https_server_context **context) {
  *context = (struct https_server_context *) sys_zalloc(sizeof(struct https_server_context));
  if (*context == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_start(*context);
#else
  log_error("No https server defined");
  return -1;
#endif
}

void https_stop(struct https_server_context *context) {
  if (context != NULL) {
#ifdef WITH_CPPHTTPLIB_LIB
  httplib_stop(context);
#endif
    sys_free(context);
  }
}