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
#include "../../utils/log.h"
}

#include "../masa/masa_config.h"
#include "../masa/masa_api.h"
#include "../pledge/pledge_config.h"
#include "registrar_api.h"
#include "registrar_config.h"
#include "registrar_server.h"

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
}

int registrar_start(struct registrar_config *rconf, struct masa_config *mconf,
                    struct pledge_config *pconf,
                    struct RegistrarContext **context) {
  std::vector<struct RouteTuple> routes;

  *context = nullptr;

  try {
    *context = new RegistrarContext();
    (*context)->rconf = rconf;
    (*context)->mconf = mconf;
  } catch (...) {
    log_error("failed to allocate RegistrarContext");
    return -1;
  }

  setup_registrar_routes(routes);
  struct http_config hconf = {.bind_address = rconf->bind_address,
                              .port = rconf->port,
                              .tls_cert_path = rconf->tls_cert_path,
                              .tls_key_path = rconf->tls_key_path,
                              .client_ca_cert_path =
                                  pconf->idevid_ca_cert_path};

  return https_start(&hconf, routes, static_cast<void *>(*context),
                     &(*context)->srv_ctx);
}

void registrar_stop(struct RegistrarContext *context) {
  if (context != nullptr) {
    https_stop(context->srv_ctx);
    delete context;
  }
}
