/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar server.
 */
#include "../http/http.h"
#include "../http/https_server.h"

extern "C" {
#include "../utils/log.h"
}

#include "registrar_server.h"
#include "registrar_routes.h"

int registrar_start(struct http_config *config, struct https_server_context **context) {
  std::vector<struct RouteTuple> routes;

  if (setup_registrar_routes(routes) < 0) {
    log_error("setup_registrar_routes fail");
    return -1;
  }

  return https_start(config, routes, context);
}

void registrar_stop(struct https_server_context *context) {
  https_stop(context);
}