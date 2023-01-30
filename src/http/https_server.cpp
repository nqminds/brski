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

int https_start(struct http_config *config, struct https_server_context **context) {
  try {
    *context = new https_server_context();
  } catch(...) {
    log_error("failed to allocate https_server_context");
    return -1;
  }

  log_info("Starting the HTTPS server at %s:%d", config->bindAddress, config->port);
#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_start(config, *context);
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