/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar routes.
 */
#include <functional>
#include <memory>
#include <new>
#include <string>

#include "../http/http.hpp"
#include "../http/https_client.hpp"
#include "../masa/masa_api.hpp"
#include "registrar_api.hpp"
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

  struct HttpResponse http_res;
  int status = https_post_request(rconf->tls_key_path, rconf->tls_cert_path,
                                  mconf->bind_address, mconf->port, path, false,
                                  body, content_type, http_res);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  if (status >= 400) {
    log_error("https_post_request failed with HTTP code %d and "
              "response: '%s'",
              status, http_res.response.c_str());
    crypto_free_certcontext(http_res.peer_certificate);
    return 400;
  }

  crypto_free_certcontext(http_res.peer_certificate);
  response = http_res.response;

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

  struct tm created_on = {0};
  char *serial_number = NULL;
  const char *cms_str = request_body.c_str();

  log_trace("registrar_requestvoucher:");
  response_header["Content-Type"] = "application/voucher-cms+json";

  struct CrypoCertMeta : public crypto_cert_meta {
    CrypoCertMeta() {
      this->issuer = init_keyvalue_list();
      this->subject = init_keyvalue_list();
      if (this->issuer == nullptr || this->subject == nullptr) {
        throw std::bad_alloc();
      }
    }
    ~CrypoCertMeta() {
      free_keyvalue_list(this->issuer);
      free_keyvalue_list(this->subject);
    }
  } idev_meta;

  if (crypto_getcert_meta(peer_certificate, &idev_meta) < 0) {
    log_error("crypto_getcert_meta");
    return 400;
  }

  serial_number = get_cert_serial(&idev_meta);

  if (serial_number == NULL) {
    log_error("Empty serial number");
    return 400;
  }

  log_info("Pledge cert serial number: %s", serial_number);

  auto idevid_issuer = std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
      crypto_getcert_issuer(peer_certificate),
      [](BinaryArray *b) { free_binary_array(b); },
  };
  if (idevid_issuer == nullptr) {
    log_error("crypto_getcert_issuer fail");
    return 400;
  }

  auto pledge_voucher_request_cms =
      std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
          static_cast<BinaryArray *>(std::malloc(sizeof(BinaryArray))),
          [](BinaryArray *b) { free_binary_array(b); },
      };
  if ((pledge_voucher_request_cms->length =
           serialize_base64str2array((const uint8_t *)cms_str, strlen(cms_str),
                                     &pledge_voucher_request_cms->array)) < 0) {
    log_errno("serialize_base64str2array fail");
    return 400;
  }

  if (get_localtime(&created_on) < 0) {
    log_error("get_localtime fail");
    return 500;
  }

  auto registrar_tls_cert =
      std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
          file_to_x509buf(rconf->tls_cert_path),
          [](BinaryArray *b) { free_binary_array(b); },
      };
  if (registrar_tls_cert == nullptr) {
    log_error("file_to_x509buf fail");
    return 500;
  }

  auto registrar_sign_cert =
      std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
          file_to_x509buf(rconf->cms_sign_cert_path),
          [](BinaryArray *b) { free_binary_array(b); },
      };
  if (registrar_sign_cert == nullptr) {
    log_error("file_to_x509buf fail");
    return 500;
  }

  auto registrar_sign_key =
      std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
          file_to_keybuf(rconf->cms_sign_key_path),
          [](BinaryArray *b) { free_binary_array(b); },
      };
  if (registrar_sign_key == nullptr) {
    log_error("file_to_keybuf fail");
    return 500;
  }

  auto pledge_verify_certs =
      std::unique_ptr<BinaryArrayList, void (*)(BinaryArrayList *)>{
          nullptr,
          [](BinaryArrayList *list) { free_array_list(list); },
      };
  {
    BinaryArrayList *ptr = nullptr;
    if (load_cert_files(rconf->cms_verify_certs_paths, &ptr) < 0) {
      log_error("load_cert_files");
      return 500;
    }
    pledge_verify_certs.reset(ptr);
  }

  auto pledge_store_certs =
      std::unique_ptr<BinaryArrayList, void (*)(BinaryArrayList *)>{
          nullptr,
          [](BinaryArrayList *list) { free_array_list(list); },
      };
  {
    BinaryArrayList *ptr = nullptr;
    if (load_cert_files(rconf->cms_verify_store_paths, &ptr) < 0) {
      log_error("load_cert_files");
      return 500;
    }
    pledge_store_certs.reset(ptr);
  }

  auto additional_registrar_certs =
      std::unique_ptr<BinaryArrayList, void (*)(BinaryArrayList *)>{
          nullptr,
          [](BinaryArrayList *list) { free_array_list(list); },
      };
  {
    BinaryArrayList *ptr = nullptr;
    if (load_cert_files(rconf->cms_add_certs_paths, &ptr) < 0) {
      log_error("load_cert_files");
      return 500;
    }
    additional_registrar_certs.reset(ptr);
  }

  auto voucher_request_cms =
      std::unique_ptr<BinaryArray, void (*)(BinaryArray *)>{
          sign_voucher_request(
              pledge_voucher_request_cms.get(), &created_on, serial_number,
              idevid_issuer.get(), registrar_tls_cert.get(),
              registrar_sign_cert.get(), registrar_sign_key.get(),
              pledge_verify_certs.get(), pledge_store_certs.get(),
              additional_registrar_certs.get()),
          [](BinaryArray *b) { free_binary_array(b); },
      };

  if (voucher_request_cms == nullptr) {
    log_error("sign_voucher_request fail");
    return 400;
  }

  if (post_voucher_request(voucher_request_cms.get(), mconf, rconf, response) <
      0) {
    log_error("post_voucher_request fail");
    response.assign(
        "Voucher request to the MASA server failed. Please contact the "
        "webmaster of the registrar server if this error persists.");
    return 502;
  }

  return 200;
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

int registrar_signcert(const RequestHeader &request_header,
                       const std::string &request_body,
                       CRYPTO_CERT peer_certificate,
                       ResponseHeader &response_header, std::string &response,
                       void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);
  struct registrar_config *rconf = context->rconf;
  struct masa_config *mconf = context->mconf;

  log_trace("registrar_signcert:");

  std::string path = PATH_BRSKI_SIGNCERT;
  std::string content_type = "text/plain";
  std::string body = request_body;

  log_info("Request sign cert from MASA %s", path.c_str());

  struct HttpResponse http_res;
  int status = https_post_request(rconf->tls_key_path, rconf->tls_cert_path,
                                  mconf->bind_address, mconf->port, path, false,
                                  body, content_type, http_res);

  if (status < 0) {
    log_error("https_post_request fail");
    return 400;
  }

  if (status >= 400) {
    log_error("https_post_request failed with HTTP code %d and "
              "response: '%s'",
              status, http_res.response.c_str());
    crypto_free_certcontext(http_res.peer_certificate);
    return 400;
  }

  crypto_free_certcontext(http_res.peer_certificate);
  response = http_res.response;

  response_header["Content-Type"] = content_type;
  return 200;
}
