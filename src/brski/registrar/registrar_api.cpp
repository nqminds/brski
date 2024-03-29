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

void save_to_log(CRYPTO_CERT icert, CRYPTO_CERT lcert, char *log_path) {
  struct crypto_cert_meta imeta = {};
  imeta.issuer = init_keyvalue_list();
  imeta.subject = init_keyvalue_list();

  log_trace("Saving the log");

  if (imeta.issuer == NULL || imeta.subject == NULL) {
    log_error("error allocation metadata");
    return;
  }

  if (crypto_getcert_meta(icert, &imeta) < 0) {
    log_error("crypto_getcert_meta fail");
    free_keyvalue_list(imeta.issuer);
    free_keyvalue_list(imeta.subject);
    return;
  }

  char *iserial = crypto_getcert_serial(&imeta);

  struct crypto_cert_meta lmeta = {};
  lmeta.issuer = init_keyvalue_list();
  lmeta.subject = init_keyvalue_list();

  if (lmeta.issuer == NULL || lmeta.subject == NULL) {
    log_error("error allocation metadata");
    free_keyvalue_list(imeta.issuer);
    free_keyvalue_list(imeta.subject);
    return;
  }

  if (crypto_getcert_meta(lcert, &lmeta) < 0) {
    log_error("crypto_getcert_meta fail");
    free_keyvalue_list(imeta.issuer);
    free_keyvalue_list(imeta.subject);
    free_keyvalue_list(lmeta.issuer);
    free_keyvalue_list(lmeta.subject);
    return;
  }

  char *lserial = crypto_getcert_serial(&lmeta);

  FILE *f = fopen(log_path, "a");
  if (f != NULL) {
    fprintf(f, "%lu 0x%" PRIx64 " \"%s\" 0x%" PRIx64 " \"%s\"\n", time(NULL),
            imeta.serial_number, (iserial != NULL) ? iserial : "NULL",
            lmeta.serial_number, (lserial != NULL) ? lserial : "NULL");
    fclose(f);
  } else {
    log_errno("fopen fail");
  }

  free_keyvalue_list(imeta.issuer);
  free_keyvalue_list(imeta.subject);
  free_keyvalue_list(lmeta.issuer);
  free_keyvalue_list(lmeta.subject);
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

  log_trace("registrar_requestvoucher: %p", peer_certificate);
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

  serial_number = crypto_getcert_serial(&idev_meta);

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

int registrar_est_simpleenroll(const RequestHeader &request_header,
                               const std::string &request_body,
                               CRYPTO_CERT peer_certificate,
                               ResponseHeader &response_header,
                               std::string &response, void *user_ctx) {
  struct RegistrarContext *context =
      static_cast<struct RegistrarContext *>(user_ctx);
  struct registrar_config *rconf = context->rconf;
  struct masa_config *mconf = context->mconf;

  struct BinaryArray cert_to_sign = {};
  struct BinaryArray *tls_ca_key = NULL;
  struct BinaryArray *tls_ca_cert = NULL;
  ssize_t length;
  CRYPTO_CERT scert;

  log_trace("registrar_est_simpleenroll:");

  char *cert_str = (char *)request_body.c_str();

  response_header["Content-Type"] = "text/plain";

  if ((length = serialize_base64str2array((const uint8_t *)cert_str,
                                          strlen(cert_str),
                                          &cert_to_sign.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto registrar_signcert_err;
  }
  cert_to_sign.length = length;

  /* Here check the idevid */

  if ((tls_ca_cert = file_to_x509buf(rconf->tls_ca_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto registrar_signcert_err;
  }

  if ((tls_ca_key = file_to_keybuf(rconf->tls_ca_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto registrar_signcert_err;
  }

  length = crypto_sign_cert(tls_ca_key->array, tls_ca_key->length,
                            tls_ca_cert->array, tls_ca_cert->length,
                            cert_to_sign.length, &cert_to_sign.array);
  if (length < 0) {
    log_error("file_to_x509buf fail");
    goto registrar_signcert_err;
  }
  cert_to_sign.length = length;
  cert_str = NULL;

  if (serialize_array2base64str(cert_to_sign.array, cert_to_sign.length,
                                (uint8_t **)&cert_str) < 0) {
    log_error("serialize_array2base64str fail");
    goto registrar_signcert_err;
  }

  response.assign((char *)cert_str);

  scert = crypto_cert2context(cert_to_sign.array, cert_to_sign.length);

  if (scert != NULL) {
    save_to_log(peer_certificate, scert, context->log_path);
    crypto_free_certcontext(scert);
  }

  sys_free(cert_str);
  free_binary_array_content(&cert_to_sign);
  free_binary_array(tls_ca_cert);
  free_binary_array(tls_ca_key);
  return 200;

registrar_signcert_err:
  free_binary_array_content(&cert_to_sign);
  free_binary_array(tls_ca_cert);
  free_binary_array(tls_ca_key);
  return 400;
}
