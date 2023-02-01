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

#include "../http/http.h"

extern "C" {
#include "../utils/log.h"
}

int post_brski_requestvoucher(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_brski_requestvoucher");
  // reply_header.assign("text/plain");
  return 200;
}

int post_brski_voucher_status(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_brski_voucher_status");
  // reply_header.assign("text/plain");
  return 200;
}

int post_brski_requestauditlog(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_brski_requestauditlog");
  // reply_header.assign("text/plain");
  return 200;
}

int post_brski_enrollstatus(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_brski_enrollstatus");
  // reply_header.assign("text/plain");
  return 200;
}

int get_est_cacerts(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("get_est_cacerts");
  // reply_header.assign("text/plain");
  return 503;
}

int post_est_simpleenroll(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_est_simpleenroll");
  // reply_header.assign("text/plain");
  return 503;
}

int post_est_simplereenroll(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_est_simplereenroll");
  // reply_header.assign("text/plain");
  return 503;
}

int post_est_fullcmc(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_est_fullcmc");
  // reply_header.assign("text/plain");
  return 503;
}

int post_est_serverkeygen(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("post_est_serverkeygen");
  // reply_header.assign("text/plain");
  return 503;
}

int get_est_csrattrs(ReplyHeader &reply_header, std::string &reply) {
  reply.assign("get_est_csrattrs");
  // reply_header.assign("text/plain");
  return 503;
}
