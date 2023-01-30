/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the http library wrapper.
 */

#include <httplib.h>

extern "C" {
#include "../utils/log.h"
#include "../utils/allocs.h"
}

#include "http.h"

int httplib_start(struct https_server_context *context) {
  if (context == nullptr) {
    log_error("context param is NULL");
    return -1;
  }

  try {
    const char *cert_path = "";
    const char *private_key_path = "";
    httplib::SSLServer *server = new httplib::SSLServer(cert_path, private_key_path);
    context->server = static_cast<void*>(server);
  } catch (...) {
    log_error("httplib::SSLServer() fail");
    return -1;
  }

  return 0;
}

void httplib_stop(struct https_server_context *context) {
  if (context != nullptr) {
    if (context->server != nullptr) {
      httplib::SSLServer *server = static_cast<httplib::SSLServer *>(context->server);
    }
  }
}
