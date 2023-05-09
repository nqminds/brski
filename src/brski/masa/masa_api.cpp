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

#include "../http/https_client.h"
#include "../http/http.h"

#include "masa_config.h"

extern "C" {
#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/keyvalue.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
#include "../config.h"
}

int voucher_req_cb(
    const char *serial_number,
    const struct BinaryArrayList *additional_registrar_certs,
    void *user_ctx, struct BinaryArray *pinned_domain_cert) {
  struct MasaContext *context =
      static_cast<struct MasaContext *>(user_ctx);

  /* Need to verify serial_number */
  /* Need to verify additional_registrar_certs */

  return 0;
}

int masa_requestvoucher(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                             std::string &response, void *user_ctx) {
  struct MasaContext *context =
      static_cast<struct MasaContext *>(user_ctx);
  struct registrar_config *rconf = context->rconf;
  struct masa_config *mconf = context->mconf;

  struct BinaryArray *masa_sign_cert = NULL;
  struct BinaryArray *masa_sign_key = NULL;
  struct BinaryArrayList *registrar_verify_certs = NULL;
  struct BinaryArrayList *registrar_store_certs = NULL;
  struct BinaryArrayList *pledge_verify_certs = NULL;
  struct BinaryArrayList *pledge_store_certs = NULL;
  struct BinaryArrayList *additional_registrar_certs = NULL;

  log_trace("masa_requestvoucher:");
  // log_trace("%s", request_body.c_str());
  response.assign("masa_requestvoucher");
  response_header["Content-Type"] = "text/plain";

  if ((masa_sign_cert = file_to_x509buf(mconf->cms_sign_cert_path)) ==
      NULL) {
    log_error("file_to_x509buf fail");
    goto masa_requestvoucher_fail;
  }

  if ((masa_sign_key = file_to_keybuf(mconf->cms_sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto masa_requestvoucher_fail;
  }

  if (load_cert_files(mconf->cms_verify_certs_paths, &registrar_verify_certs) <
      0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  if (load_cert_files(mconf->cms_verify_store_paths, &registrar_store_certs) < 0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_certs_paths, &pledge_verify_certs) <
      0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_store_paths, &pledge_store_certs) < 0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  if (load_cert_files(mconf->cms_add_certs_paths, &additional_registrar_certs) <
      0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  // struct BinaryArray *
  // sign_masa_pledge_voucher(const struct BinaryArray *voucher_request_cms,
  //                        const struct tm *expires_on, voucher_req_cb,
  //                        user_ctx,
  //                        const struct BinaryArray *masa_sign_cert,
  //                        const struct BinaryArray *masa_sign_key,
  //                        const struct BinaryArrayList *registrar_verify_certs,
  //                        const struct BinaryArrayList *registrar_verify_store,
  //                        const struct BinaryArrayList *pledge_verify_certs,
  //                        const struct BinaryArrayList *pledge_verify_store,
  //                        const struct BinaryArrayList *additional_masa_certs);
  free_binary_array(masa_sign_cert);
  free_binary_array(masa_sign_key);
  free_array_list(registrar_verify_certs);
  free_array_list(registrar_store_certs);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_registrar_certs);
  return 200;

masa_requestvoucher_fail:
  free_binary_array(masa_sign_cert);
  free_binary_array(masa_sign_key);
  free_array_list(registrar_verify_certs);
  free_array_list(registrar_store_certs);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_registrar_certs);
  return 400;
}

int masa_voucher_status(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("masa_voucher_status:");
  log_trace("%s", request_body.c_str());

  response.assign("masa_voucher_status");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int masa_requestauditlog(const RequestHeader &request_header,
                               const std::string &request_body,
                               CRYPTO_CERT peer_certificate,
                               ResponseHeader &response_header,
                               std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("masa_requestauditlog:");
  log_trace("%s", request_body.c_str());

  response.assign("masa_requestauditlog");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int masa_enrollstatus(const RequestHeader &request_header,
                            const std::string &request_body,
                            CRYPTO_CERT peer_certificate,
                            ResponseHeader &response_header,
                            std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("masa_enrollstatus:");
  log_trace("%s", request_body.c_str());

  response.assign("masa_enrollstatus");
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
                     ResponseHeader &response_header, std::string &response,
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
