/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the masa server.
 */
#include "../http/http.h"
#include "../http/https_server.h"

#include "masa_api.h"
#include "masa_config.h"
#include "masa_server.h"

extern "C" {
#include "../../utils/log.h"
}

#include "../pledge/pledge_config.h"
#include "../registrar/registrar_config.h"

void setup_masa_routes(std::vector<struct RouteTuple> &routes) {
  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTVOUCHER),
                    .method = HTTP_METHOD_POST,
                    .handle = masa_requestvoucher});

  routes.push_back({.path = std::string(PATH_BRSKI_VOUCHER_STATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = masa_voucher_status});

  routes.push_back({.path = std::string(PATH_BRSKI_REQUESTAUDITLOG),
                    .method = HTTP_METHOD_POST,
                    .handle = masa_requestauditlog});

  routes.push_back({.path = std::string(PATH_BRSKI_ENROLLSTATUS),
                    .method = HTTP_METHOD_POST,
                    .handle = masa_enrollstatus});

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

int masa_start(struct registrar_config *rconf, struct masa_config *mconf,
                    struct pledge_config *pconf,
                    struct MasaContext **context) {
  std::vector<struct RouteTuple> routes;

  *context = nullptr;

  try {
    *context = new MasaContext();
    (*context)->rconf = rconf;
    (*context)->mconf = mconf;
  } catch (...) {
    log_error("failed to allocate MasaContext");
    return -1;
  }

  setup_masa_routes(routes);
  struct http_config hconf = {.bind_address = rconf->bind_address,
                              .port = rconf->port,
                              .tls_cert_path = rconf->tls_cert_path,
                              .tls_key_path = rconf->tls_key_path,
                              .client_ca_cert_file_path =
                                  pconf->idevid_ca_path};

  return https_start(&hconf, routes, static_cast<void *>(*context),
                     &(*context)->srv_ctx);
}

void masa_stop(struct MasaContext *context) {
  if (context != nullptr) {
    https_stop(context->srv_ctx);
    delete context;
  }
}
