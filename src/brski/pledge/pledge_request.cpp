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

extern "C" {
#include "../../utils/log.h"
}

int post_voucher_pledge_request(struct pledge_config *pconf, struct registrar_config *rconf) {
  (void)pconf;
  (void)rconf;

  return 0;
}