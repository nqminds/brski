/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar server.
 */
#include "../http/http.hpp"
#include "../http/https_server.hpp"

extern "C" {
#include "../../utils/log.h"
}

#include "../masa/masa_api.hpp"
#include "../masa/masa_config.h"
#include "../pledge/pledge_config.h"
#include "registrar_api.hpp"
#include "registrar_config.h"
#include "registrar_server.hpp"

#define LOG_PATH "/var/log/brski-registrar.log"

void setup_registrar_routes(std::vector<struct RouteTuple> &routes) {
  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTVOUCHER),
                    .method = HTTP_METHOD_POST,
                    .handle = registrar_requestvoucher});

  routes.push_back({.path = std::string(PATH_BRSKI_VOUCHER_STATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = registrar_voucher_status});

  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTAUDITLOG),
                    .method = HTTP_METHOD_POST,
                    .handle = registrar_requestauditlog});

  routes.push_back({.path = std::string(PATH_BRSKI_ENROLLSTATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = registrar_enrollstatus});

  routes.push_back({.path = std::string(PATH_EST_SIMPLEENROLL),
                    .method = HTTP_METHOD_POST,
                    .handle = registrar_est_simpleenroll});
}

int registrar_start(struct registrar_config *rconf, struct masa_config *mconf,
                    struct RegistrarContext **context) {
  std::vector<struct RouteTuple> routes;

  *context = nullptr;

  try {
    *context = new RegistrarContext();
    (*context)->rconf = rconf;
    (*context)->mconf = mconf;
    sys_strlcpy((*context)->log_path, LOG_PATH, 255);
  } catch (...) {
    log_error("failed to allocate RegistrarContext");
    return -1;
  }

  setup_registrar_routes(routes);
  struct http_config hconf = {.bind_address = rconf->bind_address,
                              .port = rconf->port,
                              .tls_cert_path = rconf->tls_cert_path,
                              .tls_key_path = rconf->tls_key_path,
                              .client_ca_cert_path = nullptr};

  return https_start(&hconf, routes, static_cast<void *>(*context),
                     &(*context)->srv_ctx);
}

void registrar_stop(struct RegistrarContext *context) {
  if (context != nullptr) {
    https_stop(context->srv_ctx);
    delete context;
  }
}
