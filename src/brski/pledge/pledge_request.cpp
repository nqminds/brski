/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the pledge request functions.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pledge_config.h"

#include "../http/https_client.hpp"
#include "../masa/masa_api.hpp"
#include "../masa/masa_config.h"
#include "../registrar/registrar_api.hpp"
#include "../registrar/registrar_config.h"

#include "../config.h"

extern "C" {
#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/keyvalue.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
#include "../pledge/pledge_utils.h"
}

int post_voucher_pledge_request(struct pledge_config *pconf,
                                struct registrar_config *rconf,
                                struct masa_config *mconf,
                                struct BinaryArray *pinned_domain_cert) {
  int status;
  struct HttpResponse http_res = {};
  struct BinaryArray *registrar_tls_cert = NULL;

  if (rconf->bind_address == nullptr) {
    log_error("bind_address param is NULL");
    return -1;
  }

  if (pconf->idevid_key_path == nullptr) {
    log_error("idevid_key_path param is NULL");
    return -1;
  }

  if (pconf->idevid_cert_path == nullptr) {
    log_error("idevid_cert_path param is NULL");
    return -1;
  }

  std::string path = PATH_BRSKI_REQUESTVOUCHER;
  std::string content_type = "application/voucher-cms+json";

  /* First run with an empty body to retrieve the certificate */
  status = https_post_request(pconf->idevid_key_path, pconf->idevid_cert_path,
                              rconf->bind_address, rconf->port, path, false, "",
                              content_type, http_res);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  if ((registrar_tls_cert = crypto_cert2buf(http_res.peer_certificate)) ==
      NULL) {
    log_error("crypto_cert2buf fail");
    crypto_free_certcontext(http_res.peer_certificate);
    return -1;
  }

  crypto_free_certcontext(http_res.peer_certificate);

  char *cms = voucher_pledge_request_to_base64(pconf, registrar_tls_cert);
  free_binary_array(registrar_tls_cert);

  if (cms == NULL) {
    log_error("voucher_pledge_request_to_base64 fail");
    return -1;
  }

  std::string body = cms;

  sys_free(cms);

  log_info("Request pledge voucher from %s", path.c_str());

  status = https_post_request(pconf->idevid_key_path, pconf->idevid_cert_path,
                              rconf->bind_address, rconf->port, path, false,
                              body, content_type, http_res);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  if (status >= 400) {
    log_error("post_voucher_pledge_request failed with HTTP code %d and "
              "response: '%s'",
              status, http_res.response.c_str());
    crypto_free_certcontext(http_res.peer_certificate);
    return -1;
  }

  if ((registrar_tls_cert = crypto_cert2buf(http_res.peer_certificate)) ==
      NULL) {
    log_error("crypto_cert2buf fail");
    crypto_free_certcontext(http_res.peer_certificate);
    return -1;
  }

  crypto_free_certcontext(http_res.peer_certificate);

  const char *masa_pledge_voucher_str = http_res.response.c_str();
  struct BinaryArray masa_pledge_voucher_cms = {};
  struct BinaryArray *nonce = NULL;
  struct BinaryArrayList *masa_verify_certs = NULL;
  struct BinaryArrayList *masa_store_certs = NULL;

  int result;

  if ((masa_pledge_voucher_cms.length =
           serialize_base64str2array((const uint8_t *)masa_pledge_voucher_str,
                                     strlen(masa_pledge_voucher_str),
                                     &masa_pledge_voucher_cms.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto post_voucher_pledge_request_fail;
  }

  if (pconf->nonce != NULL) {
    if ((nonce = init_binary_array()) == NULL) {
      log_errno("init_binary_array");
      goto post_voucher_pledge_request_fail;
    }
    ssize_t length;
    if ((length = serialize_base64str2array((const uint8_t *)pconf->nonce,
                                            strlen(pconf->nonce),
                                            &nonce->array)) < 0) {
      log_errno("serialize_base64str2array fail");
      free_binary_array(nonce);
      goto post_voucher_pledge_request_fail;
    }
    nonce->length = length;
  }

  if (load_cert_files(pconf->cms_verify_certs_paths, &masa_verify_certs) < 0) {
    log_error("load_cert_files");
    goto post_voucher_pledge_request_fail;
  }

  if (load_cert_files(pconf->cms_verify_store_paths, &masa_store_certs) < 0) {
    log_error("load_cert_files");
    goto post_voucher_pledge_request_fail;
  }

  result = verify_masa_pledge_voucher(
      &masa_pledge_voucher_cms, pconf->serial_number, nonce, registrar_tls_cert,
      NULL, masa_verify_certs, masa_store_certs, NULL, pinned_domain_cert);

  if (result < 0) {
    log_error("verify_masa_pledge_voucher fail");
    goto post_voucher_pledge_request_fail;
  }

  free_binary_array_content(&masa_pledge_voucher_cms);
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_array_list(masa_verify_certs);
  free_array_list(masa_store_certs);
  return 0;

post_voucher_pledge_request_fail:
  free_binary_array_content(&masa_pledge_voucher_cms);
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_array_list(masa_verify_certs);
  free_array_list(masa_store_certs);
  return -1;
}

std::string create_cert_string(const char *cert) {
  std::string out = "-----BEGIN CERTIFICATE-----\n";
  out += std::string(cert) + "\n";
  out += "-----END CERTIFICATE-----";

  return out;
}

int generate_sign_cert(struct BinaryArray *scert_cert,
                       struct BinaryArray *scert_key) {
  uint8_t rand[8];
  char rands[17];
  struct BinaryArray buf = {.array = rand, .length = 8};

  struct crypto_cert_meta sign_cert_meta = {
      .serial_number = 12345,
      .not_before = 0,
      // Long-lived pledge certificate
      .not_after_absolute = (char *)"99991231235959Z",
      .issuer = NULL,
      .subject = NULL,
      .basic_constraints = (char *)"CA:false"};

  if (crypto_getrand(&buf) < 0) {
    log_error("crypto_getrand fail");
    return -1;
  }

  printf_hex(rands, 16, rand, 8, 1);

  if ((sign_cert_meta.issuer = init_keyvalue_list()) == NULL) {
    log_error("init_keyvalue_list fail");
    return -1;
  }

  if ((sign_cert_meta.subject = init_keyvalue_list()) == NULL) {
    log_error("init_keyvalue_list fail");
    free_keyvalue_list(sign_cert_meta.issuer);
    return -1;
  }

  if (push_keyvalue_list(sign_cert_meta.subject, (char *)"C", (char *)"IE") <
      0) {
    log_error("push_keyvalue_list fail");
    goto generate_sign_cert_err;
  }

  if (push_keyvalue_list(sign_cert_meta.subject, (char *)"CN",
                         (char *)"ldevid-cert") < 0) {
    log_error("push_keyvalue_list fail");
    goto generate_sign_cert_err;
  }

  if (push_keyvalue_list(sign_cert_meta.subject, (char *)"serialNumber",
                         rands) < 0) {
    log_error("push_keyvalue_list fail");
    goto generate_sign_cert_err;
  }

  if ((scert_key->length = (size_t)crypto_generate_eckey(&scert_key->array)) <
      0) {
    log_error("crypto_generate_eckey fail");
    goto generate_sign_cert_err;
  }

  if ((scert_cert->length = (size_t)crypto_generate_eccert(
           &sign_cert_meta, scert_key->array, scert_key->length,
           &scert_cert->array)) < 0) {
    free_binary_array_content(scert_key);
    goto generate_sign_cert_err;
  }

  free_keyvalue_list(sign_cert_meta.issuer);
  free_keyvalue_list(sign_cert_meta.subject);

  return 0;

generate_sign_cert_err:
  free_keyvalue_list(sign_cert_meta.issuer);
  free_keyvalue_list(sign_cert_meta.subject);

  return -1;
}

int post_sign_cert(struct pledge_config *pconf, struct registrar_config *rconf,
                   struct masa_config *mconf, struct BinaryArray *out_cert,
                   struct BinaryArray *out_key) {
  std::string pinned_cert, response, ca, body;
  struct BinaryArray pinned_domain_cert = {};
  int status;
  char *pki_str = NULL;
  std::string path = PATH_EST_SIMPLEENROLL;
  std::string content_type = "application/voucher-cms+json";
  std::string registrar_ca_cert;
  ssize_t length;

  if (generate_sign_cert(out_cert, out_key) < 0) {
    log_error("generate_sign_cert");
    return -1;
  }

  if (post_voucher_pledge_request(pconf, rconf, mconf, &pinned_domain_cert) <
      0) {
    log_error("post_voucher_pledge_request fail");
    goto post_sign_cert_err;
  }

  if (serialize_array2base64str(pinned_domain_cert.array,
                                pinned_domain_cert.length,
                                (uint8_t **)&pki_str) < 0) {
    log_error("serialize_array2base64str fail");
    goto post_sign_cert_err;
  }

  registrar_ca_cert = create_cert_string(pki_str);
  sys_free(pki_str);

  if (serialize_array2base64str(out_cert->array, out_cert->length,
                                (uint8_t **)&pki_str) < 0) {
    log_error("serialize_array2base64str fail");
    goto post_sign_cert_err;
  }
  body = pki_str;
  sys_free(pki_str);

  status = https_post_request_ca(
      pconf->idevid_key_path, pconf->idevid_cert_path, registrar_ca_cert,
      rconf->bind_address, rconf->port, path, body, content_type, response);

  if (status < 0) {
    log_error("https_post_request fail");
    goto post_sign_cert_err;
  }

  if (status >= 400) {
    log_error("post_voucher_pledge_request_ca failed with HTTP code %d and "
              "response: '%s'",
              status, response.c_str());
    goto post_sign_cert_err;
  }

  free_binary_array_content(out_cert);
  pki_str = (char *)response.c_str();

  if ((length = serialize_base64str2array(
           (const uint8_t *)pki_str, strlen(pki_str), &out_cert->array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto post_sign_cert_err;
  }
  out_cert->length = length;

  free_binary_array_content(&pinned_domain_cert);
  return 0;

post_sign_cert_err:
  free_binary_array_content(out_cert);
  free_binary_array_content(out_key);
  free_binary_array_content(&pinned_domain_cert);
  return -1;
}
