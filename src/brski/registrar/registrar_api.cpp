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
#include "registrar_config.h"

extern "C" {
#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/keyvalue.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
#include "../config.h"
}

char *get_cert_serial(struct crypto_cert_meta *meta) {
  struct keyvalue_list *el = NULL, *next = NULL;
  dl_list_for_each_safe(el, next, &(meta->subject)->list, struct keyvalue_list,
                        list) {
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
  struct registrar_config *rconf = context->rconf;
  struct BinaryArray pledge_voucher_request_cms = {};
  struct BinaryArray *idevid_issuer = NULL;
  struct BinaryArray *registrar_tls_cert = NULL;
  struct BinaryArray *registrar_sign_cert = NULL;
  struct BinaryArray *registrar_sign_key = NULL;
  struct BinaryArrayList *pledge_verify_certs = NULL;
  struct BinaryArrayList *pledge_store_certs = NULL;
  struct BinaryArrayList *additional_registrar_certs = NULL;
  struct BinaryArray *voucher_request_cms = NULL;
  struct tm created_on = {0};
  char *serial_number = NULL;
  const char *cms_str = request_body.c_str();

  response.assign("post_brski_requestvoucher");
  response_header["Content-Type"] = "application/voucher-cms+json";

  struct crypto_cert_meta idev_meta = {};
  idev_meta.issuer = init_keyvalue_list();
  idev_meta.subject = init_keyvalue_list();

  if (crypto_getcert_meta(peer_certificate, &idev_meta) < 0) {
    log_error("crypto_getcert_meta");
    goto post_brski_requestvoucher_fail;
  }

  serial_number = get_cert_serial(&idev_meta);

  if ((idevid_issuer = crypto_getcert_issuer(peer_certificate)) == NULL) {
    log_error("crypto_getcert_issuer fail");
    goto post_brski_requestvoucher_fail;
  }

  log_trace("post_brski_requestvoucher: %s %.*s", serial_number,
            (int)idevid_issuer->length, idevid_issuer->array);

  if ((pledge_voucher_request_cms.length =
           serialize_base64str2array((const uint8_t *)cms_str, strlen(cms_str),
                                     &pledge_voucher_request_cms.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto post_brski_requestvoucher_fail;
  }

  if (get_localtime(&created_on) < 0) {
    log_error("get_localtime fail");
    goto post_brski_requestvoucher_fail;
  }

  if ((registrar_tls_cert = file_to_x509buf(rconf->tls_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto post_brski_requestvoucher_fail;
  }

  if ((registrar_sign_cert = file_to_x509buf(rconf->cms_sign_cert_path)) ==
      NULL) {
    log_error("file_to_x509buf fail");
    goto post_brski_requestvoucher_fail;
  }

  if ((registrar_sign_key = file_to_keybuf(rconf->cms_sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto post_brski_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_certs_paths, &pledge_verify_certs) <
      0) {
    log_error("load_cert_files");
    goto post_brski_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_store_paths, &pledge_store_certs) < 0) {
    log_error("load_cert_files");
    goto post_brski_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_add_certs_paths, &additional_registrar_certs) <
      0) {
    log_error("load_cert_files");
    goto post_brski_requestvoucher_fail;
  }

  voucher_request_cms = sign_voucher_request(
      &pledge_voucher_request_cms, &created_on, serial_number, idevid_issuer,
      registrar_tls_cert, registrar_sign_cert, registrar_sign_key,
      pledge_verify_certs, pledge_store_certs, additional_registrar_certs);

  if (voucher_request_cms == NULL) {
    log_error("sign_voucher_request fail");
    goto post_brski_requestvoucher_fail;
  }

  free_binary_array(registrar_tls_cert);
  free_binary_array(registrar_sign_cert);
  free_binary_array(registrar_sign_key);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_registrar_certs);
  free_binary_array(voucher_request_cms);
  free_binary_array(idevid_issuer);
  free_keyvalue_list(idev_meta.issuer);
  free_keyvalue_list(idev_meta.subject);
  free_binary_array_content(&pledge_voucher_request_cms);
  return 200;

post_brski_requestvoucher_fail:
  free_binary_array(registrar_tls_cert);
  free_binary_array(registrar_sign_cert);
  free_binary_array(registrar_sign_key);
  free_array_list(pledge_verify_certs);
  free_array_list(pledge_store_certs);
  free_array_list(additional_registrar_certs);
  free_binary_array(voucher_request_cms);
  free_binary_array(idevid_issuer);
  free_keyvalue_list(idev_meta.issuer);
  free_keyvalue_list(idev_meta.subject);
  free_binary_array_content(&pledge_voucher_request_cms);
  return 400;
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
