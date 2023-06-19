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
#include "../http/https_client.h"
#include "../masa/masa_api.h"
#include "registrar_api.h"
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

int post_voucher_request(struct BinaryArray *voucher_request_cms,
                         struct masa_config *mconf,
                         struct registrar_config *rconf,
                         std::string &response) {
  char *voucher_request_cms_base64 = NULL;

  if (serialize_array2base64str(voucher_request_cms->array,
                                voucher_request_cms->length,
                                (uint8_t **)&voucher_request_cms_base64) < 0) {
    log_error("serialize_array2base64str fail");
    return -1;
  }

  std::string path = PATH_BRSKI_REQUESTVOUCHER;
  std::string content_type = "application/voucher-cms+json";
  std::string body = voucher_request_cms_base64;

  sys_free(voucher_request_cms_base64);

  log_info("Request voucher from MASA %s", path.c_str());

  int status = https_post_request(rconf->tls_key_path, rconf->tls_cert_path,
                                  mconf->bind_address, mconf->port, path, false,
                                  body, content_type, response);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  return 0;
}

int registrar_requestvoucher(const RequestHeader &request_header,
                             const std::string &request_body,
                             CRYPTO_CERT peer_certificate,
                             ResponseHeader &response_header,
                             std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);
  struct registrar_config *rconf = context->rconf;
  struct masa_config *mconf = context->mconf;

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

  log_trace("registrar_requestvoucher:");
  response_header["Content-Type"] = "application/voucher-cms+json";

  struct crypto_cert_meta idev_meta = {};
  idev_meta.issuer = init_keyvalue_list();
  idev_meta.subject = init_keyvalue_list();

  // The status_code to return
  int status_code = 400;

  if (crypto_getcert_meta(peer_certificate, &idev_meta) < 0) {
    log_error("crypto_getcert_meta");
    goto registrar_requestvoucher_fail;
  }

  serial_number = get_cert_serial(&idev_meta);

  if ((idevid_issuer = crypto_getcert_issuer(peer_certificate)) == NULL) {
    log_error("crypto_getcert_issuer fail");
    goto registrar_requestvoucher_fail;
  }

  if ((pledge_voucher_request_cms.length =
           serialize_base64str2array((const uint8_t *)cms_str, strlen(cms_str),
                                     &pledge_voucher_request_cms.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto registrar_requestvoucher_fail;
  }

  if (get_localtime(&created_on) < 0) {
    log_error("get_localtime fail");
    goto registrar_requestvoucher_fail;
  }

  if ((registrar_tls_cert = file_to_x509buf(rconf->tls_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto registrar_requestvoucher_fail;
  }

  if ((registrar_sign_cert = file_to_x509buf(rconf->cms_sign_cert_path)) ==
      NULL) {
    log_error("file_to_x509buf fail");
    goto registrar_requestvoucher_fail;
  }

  if ((registrar_sign_key = file_to_keybuf(rconf->cms_sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto registrar_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_certs_paths, &pledge_verify_certs) <
      0) {
    log_error("load_cert_files");
    goto registrar_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_verify_store_paths, &pledge_store_certs) < 0) {
    log_error("load_cert_files");
    goto registrar_requestvoucher_fail;
  }

  if (load_cert_files(rconf->cms_add_certs_paths, &additional_registrar_certs) <
      0) {
    log_error("load_cert_files");
    goto registrar_requestvoucher_fail;
  }

  voucher_request_cms = sign_voucher_request(
      &pledge_voucher_request_cms, &created_on, serial_number, idevid_issuer,
      registrar_tls_cert, registrar_sign_cert, registrar_sign_key,
      pledge_verify_certs, pledge_store_certs, additional_registrar_certs);

  if (voucher_request_cms == NULL) {
    log_error("sign_voucher_request fail");
    goto registrar_requestvoucher_fail;
  }

  if (post_voucher_request(voucher_request_cms, mconf, rconf, response) < 0) {
    log_error("post_voucher_request fail");
    goto registrar_requestvoucher_fail;
  }

  status_code = 200;

registrar_requestvoucher_fail:
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
  return status_code;
}

int registrar_voucher_status(const RequestHeader &request_header,
                             const std::string &request_body,
                             CRYPTO_CERT peer_certificate,
                             ResponseHeader &response_header,
                             std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("registrar_voucher_status:");
  log_trace("%s", request_body.c_str());

  response.assign("registrar_voucher_status");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int registrar_requestauditlog(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                              std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("registrar_requestauditlog:");
  log_trace("%s", request_body.c_str());

  response.assign("registrar_requestauditlog");
  response_header["Content-Type"] = "text/plain";
  return 200;
}

int registrar_enrollstatus(const RequestHeader &request_header,
                           const std::string &request_body,
                           CRYPTO_CERT peer_certificate,
                           ResponseHeader &response_header,
                           std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);

  log_trace("registrar_enrollstatus:");
  log_trace("%s", request_body.c_str());

  response.assign("registrar_enrollstatus");
  response_header["Content-Type"] = "text/plain";
  return 200;
}
