/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the https server.
 */

#ifdef WITH_CPPHTTPLIB_LIB
#include <httplib.h>
#endif

extern "C" {
#include "log.h"
#include "allocs.h"
}

#include "https_server.h"

#ifdef WITH_CPPHTTPLIB_LIB
int cpphttp_start(struct https_server_context *context) {
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

void cpphttp_stop(struct https_server_context *context) {
  if (context != nullptr) {
    if (context->server != nullptr) {
      httplib::SSLServer *server = static_cast<httplib::SSLServer *>(context->server);
    }
  }
}
#endif

int https_start(struct https_server_context **context) {
  *context = (struct https_server_context *) sys_zalloc(sizeof(struct https_server_context));
  if (*context == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

#ifdef WITH_CPPHTTPLIB_LIB
  return cpphttp_start(*context);
#else
  log_error("No https server defined");
  return -1;
#endif
}

void https_stop(struct https_server_context *context) {
  if (context != NULL) {
#ifdef WITH_CPPHTTPLIB_LIB
  cpphttp_stop(context);
#endif
    sys_free(context);
  }
}