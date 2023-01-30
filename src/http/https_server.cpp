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
#include "../utils/os.h"
}

#ifdef WITH_CPPHTTPLIB_LIB
#include "httplib_wrapper.h"
#endif

void https_free_context(struct https_server_context *context) {
  if (context != nullptr) {
    delete context;
  }
}

int https_start(struct https_server_context **context) {
  *context = new https_server_context();//(struct https_server_context *) sys_zalloc(sizeof(struct https_server_context));
  if (*context == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

  log_info("Starting the HTTPS server...");
#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_start(*context);
#else
  log_error("No https server defined");
  https_free_context(*context);
  return -1;
#endif
}

void https_stop(struct https_server_context *context) {
#ifdef WITH_CPPHTTPLIB_LIB
  httplib_stop(context);
#endif

  https_free_context(context);
}