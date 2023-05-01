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
#include "../../voucher/crypto.h"
#include "../../voucher/keyvalue.h"
}

char* get_cert_serial(struct crypto_cert_meta *meta) {
  struct keyvalue_list *el = NULL, *next = NULL;
  dl_list_for_each_safe(el, next, &(meta->subject)->list, struct keyvalue_list, list) {
    if (strcmp(el->key, "serialNumber") == 0) {
      return el->value;      
    }
  }

  return NULL;
}

int post_brski_requestvoucher(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  response.assign("post_brski_requestvoucher");
  response_header["Content-Type"] = "application/voucher-cms+json";

  log_trace("post_brski_requestvoucher:");
  log_trace("%s", request_body.c_str());

  struct crypto_cert_meta idev_meta = {};
  idev_meta.issuer = init_keyvalue_list();
  idev_meta.subject = init_keyvalue_list();

  if (crypto_getcert_meta(peer_certificate, &idev_meta) < 0) {
    log_error("crypto_getcert_meta");
    free_keyvalue_list(idev_meta.issuer);
    free_keyvalue_list(idev_meta.subject);
    return 400;
  }

  char *serial_number = get_cert_serial(&idev_meta);
  log_trace(">>>>>>>> %s", serial_number);
// __must_free_binary_array struct BinaryArray *
// sign_voucher_request(const struct BinaryArray *pledge_voucher_request_cms,
//                      const struct tm *created_on, const char *serial_number,
//                      const struct BinaryArray *idevid_issuer,
//                      const struct BinaryArray *registrar_tls_cert,
//                      const struct BinaryArray *registrar_sign_cert,
//                      const struct BinaryArray *registrar_sign_key,
//                      const struct BinaryArrayList *pledge_verify_certs,
//                      const struct BinaryArrayList *pledge_verify_store,
//                      const struct BinaryArrayList *additional_registrar_certs);

  free_keyvalue_list(idev_meta.issuer);
  free_keyvalue_list(idev_meta.subject);

  return 200;
}

int post_brski_voucher_status(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_brski_voucher_status:");
  log_trace("%s", request_body.c_str());

  response.assign("post_brski_voucher_status");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int post_brski_requestauditlog(const RequestHeader &request_header,
                               const std::string &request_body,
                               CRYPTO_CERT peer_certificate,
                               ResponseHeader &response_header,
                               std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_brski_requestauditlog:");
  log_trace("%s", request_body.c_str());

  response.assign("post_brski_requestauditlog");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int post_brski_enrollstatus(const RequestHeader &request_header,
                            const std::string &request_body,
                            CRYPTO_CERT peer_certificate,
                            ResponseHeader &response_header,
                            std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_brski_enrollstatus:");
  log_trace("%s", request_body.c_str());

  response.assign("post_brski_enrollstatus");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int get_est_cacerts(const RequestHeader &request_header,
                    const std::string &request_body,
                    CRYPTO_CERT peer_certificate,
                    ResponseHeader &response_header, std::string &response,
                    void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("get_est_cacerts:");
  log_trace("%s", request_body.c_str());

  response.assign("get_est_cacerts");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_simpleenroll(const RequestHeader &request_header,
                          const std::string &request_body,
                          CRYPTO_CERT peer_certificate,
                          ResponseHeader &response_header,
                          std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_est_simpleenroll:");
  log_trace("%s", request_body.c_str());

  response.assign("post_est_simpleenroll");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_simplereenroll(const RequestHeader &request_header,
                            const std::string &request_body,
                            CRYPTO_CERT peer_certificate,
                            ResponseHeader &response_header,
                            std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_est_simplereenroll:");
  log_trace("%s", request_body.c_str());

  response.assign("post_est_simplereenroll");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_fullcmc(const RequestHeader &request_header,
                     const std::string &request_body,
                     CRYPTO_CERT peer_certificate,
                     ResponseHeader &response_header,
                     std::string &response,
                     void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_est_fullcmc:");
  log_trace("%s", request_body.c_str());

  response.assign("post_est_fullcmc");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int post_est_serverkeygen(const RequestHeader &request_header,
                          const std::string &request_body,
                          CRYPTO_CERT peer_certificate,
                          ResponseHeader &response_header,
                          std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("post_est_serverkeygen:");
  log_trace("%s", request_body.c_str());

  response.assign("post_est_serverkeygen");
  response_header["Content-Type"] = "text/plain";
  return 503;
}

int get_est_csrattrs(const RequestHeader &request_header,
                     const std::string &request_body,
                     CRYPTO_CERT peer_certificate,
                     ResponseHeader &response_header, std::string &response,
                     void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("get_est_csrattrs:");
  log_trace("%s", request_body.c_str());

  response.assign("get_est_csrattrs");
  response_header["Content-Type"] = "text/plain";
  return 503;
}
