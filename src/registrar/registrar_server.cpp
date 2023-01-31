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
#include "registrar.h"

void setup_registrar_routes(std::vector<struct RouteTuple> &routes) {
  routes.push_back({
    .path = std::string(PATH_BRSKI_REQUESTVOUCHER),
    .method = HTTP_METHOD_POST,
    .handle = post_brski_requestvoucher
  });

  routes.push_back({
    .path = std::string(PATH_BRSKI_VOUCHER_STATUS),
    .method = HTTP_METHOD_POST,
    .handle = post_brski_voucher_status
  });

  routes.push_back({
    .path = std::string(PATH_BRSKI_REQUESTAUDITLOG),
    .method = HTTP_METHOD_POST,
    .handle = post_brski_requestauditlog
  });

  routes.push_back({
    .path = std::string(PATH_BRSKI_ENROLLSTATUS),
    .method = HTTP_METHOD_POST,
    .handle = post_brski_enrollstatus
  });

  routes.push_back({
    .path = std::string(PATH_EST_CACERTS),
    .method = HTTP_METHOD_GET,
    .handle = get_est_cacerts
  });

  routes.push_back({
    .path = std::string(PATH_EST_SIMPLEENROLL),
    .method = HTTP_METHOD_POST,
    .handle = post_est_simpleenroll
  });

  routes.push_back({
    .path = std::string(PATH_EST_SIMPLEREENROLL),
    .method = HTTP_METHOD_POST,
    .handle = post_est_simplereenroll
  });

  routes.push_back({
    .path = std::string(PATH_EST_FULLCMC),
    .method = HTTP_METHOD_POST,
    .handle = post_est_fullcmc
  });

  routes.push_back({
    .path = std::string(PATH_EST_SERVERKEYGEN),
    .method = HTTP_METHOD_POST,
    .handle = post_est_serverkeygen
  });

  routes.push_back({
    .path = std::string(PATH_EST_CSRATTRS),
    .method = HTTP_METHOD_GET,
    .handle = get_est_csrattrs
  });
}

int registrar_start(struct http_config *config, struct https_server_context **context) {
  std::vector<struct RouteTuple> routes;

  setup_registrar_routes(routes);

  return https_start(config, routes, context);
}

void registrar_stop(struct https_server_context *context) {
  https_stop(context);
}