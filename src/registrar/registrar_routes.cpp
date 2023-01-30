/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar routes.
 */
#include <vector>

#include "../http/http.h"

int post_brski_requestvoucher(void) {
  return 0;
}

int post_brski_voucher_status(void) {
  return 0;
}

int post_brski_requestauditlog(void) {
  return 0;
}

int post_brski_enrollstatus(void) {
  return 0;
}

int get_est_cacerts(void) {
  return 0;
}

int post_est_simpleenroll(void) {
  return 0;
}

int post_est_simplereenroll(void) {
  return 0;
}

int post_est_fullcmc(void) {
  return 0;
}

int post_est_serverkeygen(void) {
  return 0;
}

int get_est_csrattrs(void) {
  return 0;
}

int setup_registrar_routes(std::vector<struct RouteTuple> &routes) {
  (void) routes;

  routes.push_back({
    .path = std::string("test"),
    .method = HTTP_METHOD_POST,
    .handle = post_brski_requestvoucher
  });

  return 0;
}