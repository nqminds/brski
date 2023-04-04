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

#include "../registrar/registrar_config.h"
#include "../registrar/registrar_server.h"
#include "../http/https_client.h"

extern "C" {
#include "../../utils/log.h"
}

int post_voucher_pledge_request(struct pledge_config *pconf, struct registrar_config *rconf) {
  if (rconf->bind_address == nullptr) {
    log_error("bind_address param is NULL");
    return -1;
  }

  std::string address = get_https_address(rconf->bind_address, rconf->port);
  std::string path = PATH_BRSKI_REQUESTVOUCHER;
  std::string content_type = "application/voucher-cms+json";
  std::string body = "test";
  std::string response;
  log_info("Request pledge voucher from %s", path.c_str());

  int status = https_post_request(address, path, false, body, content_type, response);
  return 0;
}