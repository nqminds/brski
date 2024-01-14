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

#include <string>

#include "../masa/masa_config.h"
#include "../registrar/registrar_config.h"
#include "pledge_config.h"

/**
 * @brief Sends a pledge voucher POST request to the registrar
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] rconf The registrar configuration structure
 * @param[in] mconf The masa configuration structure
 * @param[out] pinned_domain_cert The pinned domain certificate in DER format
 * @return int 0 on success, -1 on failure
 */
int post_voucher_pledge_request(struct pledge_config *pconf,
                                struct registrar_config *rconf,
                                struct masa_config *mconf,
                                struct BinaryArray *pinned_domain_cert);

/**
 * @brief Signs a certificate after sending a pledge voucher POST request to the registrar
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] rconf The registrar configuration structure
 * @param[in] mconf The masa configuration structure
 * @param[out] out_cert The signed certificate in DER format
 * @param[out] out_key The output key in DER format
 * @return int 0 on success, -1 on failure
 */
int post_sign_cert(struct pledge_config *pconf,
                   struct registrar_config *rconf,
                   struct masa_config *mconf,
                   struct BinaryArray *out_cert,
                   struct BinaryArray *out_key);

#endif
