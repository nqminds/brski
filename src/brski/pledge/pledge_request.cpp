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

#include "../http/https_client.h"
#include "../registrar/registrar_config.h"
#include "../registrar/registrar_api.h"
#include "../masa/masa_api.h"

extern "C" {
#include "../pledge/pledge_utils.h"
#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/keyvalue.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
}

int post_voucher_pledge_request(struct pledge_config *pconf,
                                struct registrar_config *rconf,
                                std::string &response) {
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

  char *cms = voucher_pledge_request_to_base64(pconf, rconf->tls_cert_path);

  if (cms == NULL) {
    log_error("voucher_pledge_request_to_base64 fail");
    return -1;
  }

  std::string body = cms;

  sys_free(cms);

  log_info("Request pledge voucher from %s", path.c_str());

  int status = https_post_request(
      pconf->idevid_key_path, pconf->idevid_cert_path, rconf->bind_address,
      rconf->port, path, false, body, content_type, response);

  if (status < 0) {
    log_error("https_post_request fail");
    return -1;
  }

  log_debug("post_voucher_pledge_request status %d", status);

  const char *masa_pledge_voucher_str = response.c_str();
  struct BinaryArray masa_pledge_voucher_cms = {};

  if ((masa_pledge_voucher_cms.length =
           serialize_base64str2array((const uint8_t *)masa_pledge_voucher_str,
                                      strlen(masa_pledge_voucher_str),
                                     &masa_pledge_voucher_cms.array)) < 0) {
    log_errno("serialize_base64str2array fail");
    goto post_voucher_pledge_request_fail;
  }

  free_binary_array_content(&masa_pledge_voucher_cms);
  return 0;

post_voucher_pledge_request_fail:
  free_binary_array_content(&masa_pledge_voucher_cms);
  return -1;
}
