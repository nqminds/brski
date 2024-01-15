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

#include "../http/http.hpp"
#include "../http/https_client.hpp"

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

int voucher_req_cb(const char *serial_number,
                   const struct BinaryArrayList *additional_registrar_certs,
                   void *user_ctx, struct BinaryArray *pinned_domain_cert) {
  struct MasaContext *context = static_cast<struct MasaContext *>(user_ctx);

  if (context->ldevid_ca_cert == NULL) {
    log_error("ldevid_ca_cert is NULL");
    return -1;
  }

  log_info("Pledge cert serial number: %s", serial_number);
  /* Need to verify serial_number using a DB*/
  /* ... */

  /* Need to verify additional_registrar_certs using a DB*/
  /* ... */

  /* Need to choose the parameters of the pinned domain
     using a DB.
  */

  /* For now copy only the ldevid certificate */
  if (copy_binary_array(pinned_domain_cert, context->ldevid_ca_cert) < 0) {
    log_error("copy_binary_array fail");
    return -1;
  }

  return 0;
}

int masa_requestvoucher(const RequestHeader &request_header,
                        const std::string &request_body,
                        CRYPTO_CERT peer_certificate,
                        ResponseHeader &response_header, std::string &response,
                        void *user_ctx) {
  struct MasaContext *context = static_cast<struct MasaContext *>(user_ctx);
  struct registrar_config *rconf = context->rconf;
  struct masa_config *mconf = context->mconf;

  struct BinaryArray voucher_request_cms = {};
  struct BinaryArray *masa_sign_cert = NULL;
  struct BinaryArray *masa_sign_key = NULL;
  struct BinaryArrayList *registrar_verify_certs = NULL;
  struct BinaryArrayList *registrar_store_certs = NULL;
  struct BinaryArrayList *pledge_verify_certs = NULL;
  struct BinaryArrayList *pledge_store_certs = NULL;
  struct BinaryArrayList *additional_masa_certs = NULL;
  struct BinaryArray *masa_pledge_voucher = NULL;
  char *base64 = NULL;
  const char *cms_str = request_body.c_str();

  log_trace("masa_requestvoucher:");
  response_header["Content-Type"] = "text/plain";

  struct tm expires_on = {0};
  if (serialize_str2time(mconf->expires_on, &expires_on) < 0) {
    log_error("serialize_str2time fail");
    goto masa_requestvoucher_fail;
  }

  if ((voucher_request_cms.length =
           serialize_base64str2array((const uint8_t *)cms_str, strlen(cms_str),
                                     &voucher_request_cms.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto masa_requestvoucher_fail;
  }

  if ((context->ldevid_ca_cert = file_to_x509buf(mconf->ldevid_ca_cert_path)) ==
      NULL) {
    log_error("file_to_x509buf fail");
    goto masa_requestvoucher_fail;
  }

  if ((masa_sign_cert = file_to_x509buf(mconf->cms_sign_cert_path)) == NULL) {
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

  if (load_cert_files(mconf->cms_verify_store_paths, &registrar_store_certs) <
      0) {
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

  if (load_cert_files(mconf->cms_add_certs_paths, &additional_masa_certs) < 0) {
    log_error("load_cert_files");
    goto masa_requestvoucher_fail;
  }

  masa_pledge_voucher = sign_masa_pledge_voucher(
      &voucher_request_cms, &expires_on, voucher_req_cb, user_ctx,
      masa_sign_cert, masa_sign_key, registrar_verify_certs,
      registrar_store_certs, pledge_verify_certs, pledge_store_certs,
      additional_masa_certs);

  if (masa_pledge_voucher == NULL) {
    log_error("sign_masa_pledge_voucher fail");
    goto masa_requestvoucher_fail;
  }

  if (serialize_array2base64str(masa_pledge_voucher->array,
                                masa_pledge_voucher->length,
                                (uint8_t **)&base64) < 0) {
    log_error("serialize_array2base64str fail");
    goto masa_requestvoucher_fail;
  }

  response.assign((char *)base64);

  sys_free(base64);
  free_binary_array(context->ldevid_ca_cert);
  free_binary_array(masa_sign_key);
  free_binary_array(masa_sign_cert);
  free_array_list(registrar_verify_certs);
  free_array_list(registrar_store_certs);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_masa_certs);
  free_binary_array_content(&voucher_request_cms);
  free_binary_array(masa_pledge_voucher);
  return 200;

masa_requestvoucher_fail:
  free_binary_array(context->ldevid_ca_cert);
  free_binary_array(masa_sign_cert);
  free_binary_array(masa_sign_key);
  free_array_list(registrar_verify_certs);
  free_array_list(registrar_store_certs);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_masa_certs);
  free_binary_array_content(&voucher_request_cms);
  free_binary_array(masa_pledge_voucher);
  return 400;
}

int masa_voucher_status(const RequestHeader &request_header,
                        const std::string &request_body,
                        CRYPTO_CERT peer_certificate,
                        ResponseHeader &response_header, std::string &response,
                        void *user_ctx) {
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
                         ResponseHeader &response_header, std::string &response,
                         void *user_ctx) {
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
                      ResponseHeader &response_header, std::string &response,
                      void *user_ctx) {
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
