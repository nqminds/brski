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

#include "registrar_api.h"
#include "registrar_server.h"
#include "registrar_config.h"

void setup_registrar_routes(std::vector<struct RouteTuple> &routes) {
  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTVOUCHER),
                    .method = HTTP_METHOD_POST,
                    .handle = post_brski_requestvoucher});

  routes.push_back({.path = std::string(PATH_BRSKI_VOUCHER_STATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = post_brski_voucher_status});

  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTAUDITLOG),
                    .method = HTTP_METHOD_POST,
                    .handle = post_brski_requestauditlog});

  routes.push_back({.path = std::string(PATH_BRSKI_ENROLLSTATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = post_brski_enrollstatus});

  routes.push_back({.path = std::string(PATH_EST_CACERTS),
                    .method = HTTP_METHOD_GET,
                    .handle = get_est_cacerts});

  routes.push_back({.path = std::string(PATH_EST_SIMPLEENROLL),
                    .method = HTTP_METHOD_POST,
                    .handle = post_est_simpleenroll});

  routes.push_back({.path = std::string(PATH_EST_SIMPLEREENROLL),
                    .method = HTTP_METHOD_POST,
                    .handle = post_est_simplereenroll});

  routes.push_back({.path = std::string(PATH_EST_FULLCMC),
                    .method = HTTP_METHOD_POST,
                    .handle = post_est_fullcmc});

  routes.push_back({.path = std::string(PATH_EST_SERVERKEYGEN),
                    .method = HTTP_METHOD_POST,
                    .handle = post_est_serverkeygen});

  routes.push_back({.path = std::string(PATH_EST_CSRATTRS),
                    .method = HTTP_METHOD_GET,
                    .handle = get_est_csrattrs});
}

int registrar_start(struct registrar_config *rconf,
                    struct RegistrarContext **context) {
  std::vector<struct RouteTuple> routes;

  *context = nullptr;

  try {
    *context = new RegistrarContext();
  } catch (...) {
    log_error("failed to allocate RegistrarContext");
    return -1;
  }

  setup_registrar_routes(routes);

  return https_start(&rconf->http, routes, static_cast<void *>(*context),
                     &(*context)->srv_ctx);
}

void registrar_stop(struct RegistrarContext *context) {
  if (context != nullptr) {
    https_stop(context->srv_ctx);
    delete context;
  }
}
