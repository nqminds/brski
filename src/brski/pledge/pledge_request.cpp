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
                                std::string &response) {
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
  status = https_post_request(
      pconf->idevid_key_path, pconf->idevid_cert_path, rconf->bind_address,
      rconf->port, path, false, "", content_type, http_res);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  if ((registrar_tls_cert = crypto_cert2buf(http_res.peer_certificate)) == NULL) {
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

  status = https_post_request(
      pconf->idevid_key_path, pconf->idevid_cert_path, rconf->bind_address,
      rconf->port, path, false, body, content_type, http_res);

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

  if ((registrar_tls_cert = crypto_cert2buf(http_res.peer_certificate)) == NULL) {
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
  struct BinaryArray pinned_domain_cert = {};
  char *pinned_domain_cert_base64 = NULL;

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
      NULL, masa_verify_certs, masa_store_certs, NULL,
      &pinned_domain_cert);

  if (result < 0) {
    log_error("verify_masa_pledge_voucher fail");
    goto post_voucher_pledge_request_fail;
  }

  if (serialize_array2base64str(pinned_domain_cert.array,
                                pinned_domain_cert.length,
                                (uint8_t **)&pinned_domain_cert_base64) < 0) {
    log_error("serialize_array2base64str fail");
    goto post_voucher_pledge_request_fail;
  }

  response.assign(pinned_domain_cert_base64);

  free_binary_array_content(&masa_pledge_voucher_cms);
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_array_list(masa_verify_certs);
  free_array_list(masa_store_certs);
  free_binary_array_content(&pinned_domain_cert);
  free(pinned_domain_cert_base64);
  return 0;

post_voucher_pledge_request_fail:
  free_binary_array_content(&masa_pledge_voucher_cms);
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_array_list(masa_verify_certs);
  free_array_list(masa_store_certs);
  free_binary_array_content(&pinned_domain_cert);
  free(pinned_domain_cert_base64);
  return -1;
}
