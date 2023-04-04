/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the pledge request functions.
 */

#ifndef PLEDGE_REQUEST_H
#define PLEDGE_REQUEST_H

#include "../registrar/registrar_config.h"
#include "pledge_config.h"

/**
 * @brief Sends a pledge voucher POST request to the registrar
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] rconf The registrar configuration structure
 * @return int 0 on success, -1 on failure
 */
int post_voucher_pledge_request(struct pledge_config *pconf,
                                struct registrar_config *rconf);
#endif
