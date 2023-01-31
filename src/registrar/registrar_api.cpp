/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar routes.
 */
#include <string>

extern "C" {
#include "../utils/log.h"
}

int post_brski_requestvoucher(std::string &content, std::string &content_type) {
  content.assign("post_brski_requestvoucher");
  content_type.assign("text/plain");
  return 200;
}

int post_brski_voucher_status(std::string &content, std::string &content_type) {
  content.assign("post_brski_voucher_status");
  content_type.assign("text/plain");
  return 200;
}

int post_brski_requestauditlog(std::string &content, std::string &content_type) {
  content.assign("post_brski_requestauditlog");
  content_type.assign("text/plain");
  return 200;
}

int post_brski_enrollstatus(std::string &content, std::string &content_type) {
  content.assign("post_brski_enrollstatus");
  content_type.assign("text/plain");
  return 200;
}

int get_est_cacerts(std::string &content, std::string &content_type) {
  content.assign("get_est_cacerts");
  content_type.assign("text/plain");
  return 503;
}

int post_est_simpleenroll(std::string &content, std::string &content_type) {
  content.assign("post_est_simpleenroll");
  content_type.assign("text/plain");
  return 503;
}

int post_est_simplereenroll(std::string &content, std::string &content_type) {
  content.assign("post_est_simplereenroll");
  content_type.assign("text/plain");
  return 503;
}

int post_est_fullcmc(std::string &content, std::string &content_type) {
  content.assign("post_est_fullcmc");
  content_type.assign("text/plain");
  return 503;
}

int post_est_serverkeygen(std::string &content, std::string &content_type) {
  content.assign("post_est_serverkeygen");
  content_type.assign("text/plain");
  return 503;
}

int get_est_csrattrs(std::string &content, std::string &content_type) {
  content.assign("get_est_csrattrs");
  content_type.assign("text/plain");
  return 503;
}
