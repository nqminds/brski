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
#include "../../utils/log.h"
}

int post_brski_requestvoucher(const RequestHeader &request_header,
                              const std::string &request_body,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_brski_requestvoucher");
  response_header["Content-Type"] = "application/voucher-cms+json";
  return 200;
}

int post_brski_voucher_status(const RequestHeader &request_header,
                              const std::string &request_body,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_brski_voucher_status");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int post_brski_requestauditlog(const RequestHeader &request_header,
                               const std::string &request_body,
                               ResponseHeader &response_header,
                               std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_brski_requestauditlog");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int post_brski_enrollstatus(const RequestHeader &request_header,
                            const std::string &request_body,
                            ResponseHeader &response_header,
                            std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_brski_enrollstatus");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int get_est_cacerts(const RequestHeader &request_header, const std::string &request_body,
                    ResponseHeader &response_header, std::string &response,
                    void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("get_est_cacerts");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_simpleenroll(const RequestHeader &request_header,
                          const std::string &request_body,
                          ResponseHeader &response_header,
                          std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_est_simpleenroll");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_simplereenroll(const RequestHeader &request_header,
                            const std::string &request_body,
                            ResponseHeader &response_header,
                            std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_est_simplereenroll");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_fullcmc(const RequestHeader &request_header, const std::string &request_body,
                     ResponseHeader &response_header, std::string &response,
                     void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_est_fullcmc");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_serverkeygen(const RequestHeader &request_header,
                          const std::string &request_body,
                          ResponseHeader &response_header,
                          std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("post_est_serverkeygen");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int get_est_csrattrs(const RequestHeader &request_header, const std::string &request_body,
                     ResponseHeader &response_header, std::string &response,
                     void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("%s", request_body.c_str());

  response.assign("get_est_csrattrs");
  response_header["Content-Type"] = "text/plain";
  return 503;
}
